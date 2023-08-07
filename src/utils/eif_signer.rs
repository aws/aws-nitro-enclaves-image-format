use aws_nitro_enclaves_cose::{
    crypto::kms::KmsKey, crypto::Openssl, header_map::HeaderMap, CoseSign1,
};
use aws_sdk_kms::{client::Client, Region};
use openssl::pkey::PKey;
use sha2::{Digest, Sha384};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use tokio::runtime::Runtime;

use crate::utils::eif_reader::EifReader;
use crate::utils::get_pcrs;
use std::collections::BTreeMap;
use std::mem::size_of;

use serde_cbor::to_vec;

use crate::defs::{EifHeader, EifSectionHeader, EifSectionType, PcrInfo, PcrSignature};

#[derive(Clone, Debug)]
pub enum SigningMethod {
    PrivateKey(Vec<u8>),
    Kms(KmsKey),
}

#[derive(Debug, PartialEq, Clone)]
pub enum SigningKey {
    LocalKey { path: String },
    KmsKey { arn: String, region: String },
}

/// Used for signing enclave image file
pub struct EifSigner {
    /// EIF file path.
    pub eif_path: String,
    /// Certificate file path
    pub signing_certificate: Vec<u8>,
    /// Private key
    pub signing_key: SigningMethod,
    /// Is signed
    pub is_signed: bool,
}

impl EifSigner {
    pub fn new(
        eif_path: String,
        cert_path: String,
        signing_key_args: SigningKey,
    ) -> Result<Self, String> {
        let mut private_key = Vec::new();
        let mut signing_key = None;

        let mut certificate_file = File::open(cert_path)
            .map_err(|err| format!("Could not open the certificate file: {:?}", err))?;
        let mut signing_certificate = Vec::new();
        certificate_file
            .read_to_end(&mut signing_certificate)
            .map_err(|err| format!("Could not read the certificate file: {:?}", err))?;

        match signing_key_args {
            SigningKey::LocalKey { path } => {
                let key_path = &path;

                let mut key_file = File::open(key_path)
                    .map_err(|err| format!("Could not open the key file: {:?}", err))?;
                key_file
                    .read_to_end(&mut private_key)
                    .map_err(|err| format!("Could not read the key file: {:?}", err))?;
                signing_key = Some(SigningMethod::PrivateKey(private_key));
            }
            SigningKey::KmsKey { arn, region } => {
                let act = async {
                    let shared_config = aws_config::from_env()
                        .region(Region::new(region))
                        .load()
                        .await;
                    let kms_key = tokio::task::spawn_blocking(move || {
                        let client = Client::new(&shared_config);
                        KmsKey::new_with_public_key(client, arn, None)
                            .expect("Error building kms_key")
                    })
                    .await
                    .unwrap();
                    signing_key = Some(SigningMethod::Kms(kms_key));
                };
                let runtime = Runtime::new().unwrap();
                runtime.block_on(act);
            }
        };

        let eif_reader = EifReader::from_eif(eif_path.clone())
            .map_err(|err| format!("Could not read the EIF: {:?}", err))?;

        Ok(EifSigner {
            eif_path,
            signing_certificate,
            signing_key: signing_key.unwrap(),
            is_signed: eif_reader.signature_section.is_some(),
        })
    }

    /// Get the pcr information that will be used as payload, from the
    /// existing enclave image file.
    pub fn get_payload(&mut self) -> Result<Vec<u8>, String> {
        let mut eif_reader = EifReader::from_eif(self.eif_path.clone())
            .map_err(|err| format!("Could not read the EIF: {:?}", err))?;
        let measurements = get_pcrs(
            &mut eif_reader.image_hasher,
            &mut eif_reader.bootstrap_hasher,
            &mut eif_reader.app_hasher,
            &mut eif_reader.cert_hasher,
            Sha384::new(),
            eif_reader.signature_section.is_some(),
        )
        .expect("Failed to get measurements");

        let pcr0 = match measurements.get("PCR0") {
            Some(pcr) => pcr,
            None => "",
        };

        let pcr_info = PcrInfo::new(
            0,
            hex::decode(pcr0).map_err(|e| format!("Error while decoding PCR0: {:?}", e))?,
        );

        let payload = to_vec(&pcr_info).expect("Could not serialize PCR info");

        Ok(payload)
    }

    /// Writes the provided pcr signature to an existing EIF
    pub fn write_signature(&mut self, pcr_signature: PcrSignature) -> Result<(), String> {
        let mut header_buf = vec![0u8; EifHeader::size()];
        let mut curr_seek = 0;
        let mut section_id = 0;
        let mut eif_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.eif_path)
            .unwrap();

        let eif_signature = vec![pcr_signature];
        let serialized_signature =
            to_vec(&eif_signature).expect("Could not serialize the signature");
        let signature_size = serialized_signature.len() as u64;

        let eif_section = EifSectionHeader {
            section_type: EifSectionType::EifSectionSignature,
            flags: 0,
            section_size: signature_size,
        };

        // If the file is already signed, replace the existing signature
        if self.is_signed {
            let mut eif_content = Vec::<Vec<u8>>::new();
            let mut section_buf = vec![0u8; EifSectionHeader::size()];
            let mut signature_seek = 0;

            eif_file
                .read_exact(&mut header_buf)
                .map_err(|e| format!("Error while reading EIF header: {:?}", e))?;
            let mut header = EifHeader::from_be_bytes(&header_buf).unwrap();

            curr_seek += EifHeader::size();
            eif_file
                .seek(SeekFrom::Start(curr_seek as u64))
                .map_err(|e| format!("Failed to seek file from start: {:?}", e))?;
            while eif_file
                .read_exact(&mut section_buf)
                .map_err(|e| format!("Error while reading EIF header: {:?}", e))
                .is_ok()
            {
                let section = EifSectionHeader::from_be_bytes(&section_buf)
                    .map_err(|e| format!("Error extracting EIF section header: {:?}", e))?;

                if section.section_type == EifSectionType::EifSectionSignature {
                    header.section_offsets[section_id] = curr_seek as u64;
                    header.section_sizes[section_id] = signature_size;

                    signature_seek = curr_seek;

                    curr_seek += EifSectionHeader::size();
                    curr_seek += section.section_size as usize;

                    eif_content.push(eif_section.clone().to_be_bytes());
                    eif_content.push(serialized_signature.clone());

                    let mut buf = Vec::new();
                    eif_file
                        .seek(SeekFrom::Start(curr_seek as u64))
                        .map_err(|e| format!("Failed to seek after EIF section: {:?}", e))?;
                    eif_file
                        .read_to_end(&mut buf)
                        .map_err(|e| format!("Error while reading kernel from EIF: {:?}", e))?;
                    if !buf.is_empty() {
                        eif_content.push(buf.clone());
                    }

                    break;
                }
                curr_seek += EifSectionHeader::size();
                curr_seek += section.section_size as usize;
                eif_file
                    .seek(SeekFrom::Start(curr_seek as u64))
                    .map_err(|e| format!("Failed to seek after: {:?}", e))?;
                section_id += 1;
            }

            eif_file
                .seek(SeekFrom::Start(0))
                .map_err(|e| format!("Failed to seek file: {:?}", e))?;

            eif_file
                .write_all(&header.clone().to_be_bytes())
                .map_err(|e| format!("Error while writing EIF: {:?}", e))?;

            eif_file
                .seek(SeekFrom::Start(signature_seek as u64))
                .map_err(|e| format!("Failed to seek file: {:?}", e))?;
            for content in eif_content {
                eif_file
                    .write_all(&content)
                    .map_err(|e| format!("Error while writing EIF: {:?}", e))?;
            }
        } else {
            eif_file
                .read_exact(&mut header_buf)
                .map_err(|e| format!("Error while reading EIF header: {:?}", e))?;
            let mut header = EifHeader::from_be_bytes(&header_buf).unwrap();
            // Update header information
            header.section_offsets[header.num_sections as usize] =
                eif_file.metadata().unwrap().len();
            header.section_sizes[header.num_sections as usize] = signature_size;
            header.num_sections += 1;

            eif_file
                .seek(SeekFrom::Start(0))
                .map_err(|e| format!("Failed to seek file: {:?}", e))?;

            eif_file
                .write_all(&header.clone().to_be_bytes())
                .map_err(|e| format!("Error while writing EIF: {:?}", e))?;

            // Create the signature section for an EIF that is not signed
            eif_file
                .seek(SeekFrom::End(0))
                .map_err(|e| format!("Failed to seek file from end: {:?}", e))?;

            eif_file
                .write_all(&eif_section.to_be_bytes())
                .expect("Failed to write signature header");

            eif_file
                .write_all(&serialized_signature)
                .expect("Failed write signature");
        }

        Ok(())
    }

    /// Generates the signature based on the selected method and writes it to the EIF
    pub fn sign_image(
        &mut self,
    ) -> Result<BTreeMap<std::string::String, std::string::String>, String> {
        let payload = self
            .get_payload()
            .expect("Failed to get payload for image signing.");

        let pcr_signature = match &self.signing_key {
            SigningMethod::PrivateKey(signing_key) => {
                let private_key =
                    PKey::private_key_from_pem(signing_key.as_ref()).map_err(|e| {
                        format!("Could not deserialize the PEM-formatted private key: {}", e)
                    })?;

                let signature =
                    CoseSign1::new::<Openssl>(&payload, &HeaderMap::new(), private_key.as_ref())
                        .unwrap()
                        .as_bytes(false)
                        .unwrap();
                PcrSignature {
                    signing_certificate: self.signing_certificate.clone(),
                    signature,
                }
            }
            SigningMethod::Kms(signing_key) => {
                let payload_clone = payload;
                let signing_key_clone = signing_key.clone();
                let act = async move {
                    tokio::task::spawn_blocking(move || {
                        let signing_key = signing_key_clone;
                        CoseSign1::new::<Openssl>(&payload_clone, &HeaderMap::new(), &signing_key)
                            .unwrap()
                            .as_bytes(false)
                            .unwrap()
                    })
                    .await
                };

                let runtime =
                    Runtime::new().map_err(|e| format!("Failed to create Tokio runtime: {}", e))?;
                let signature = runtime.block_on(act).unwrap();

                PcrSignature {
                    signing_certificate: self.signing_certificate.clone(),
                    signature,
                }
            }
        };
        self.write_signature(pcr_signature)
            .map_err(|e| format!("Failed to write signature to EIF: {}", e))?;
        let mut eif_reader = EifReader::from_eif(self.eif_path.clone())
            .map_err(|err| format!("Could not read the EIF: {:?}", err))?;
        self.update_crc(eif_reader.eif_crc);

        let measurements = get_pcrs(
            &mut eif_reader.image_hasher,
            &mut eif_reader.bootstrap_hasher,
            &mut eif_reader.app_hasher,
            &mut eif_reader.cert_hasher,
            Sha384::new(),
            eif_reader.signature_section.is_some(),
        )
        .expect("Failed to get measurements");

        Ok(measurements)
    }

    pub fn update_crc(&mut self, eif_crc: u32) {
        let mut eif_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.eif_path)
            .unwrap();

        let len_without_crc = EifHeader::size() - size_of::<u32>();
        eif_file
            .seek(SeekFrom::Start(len_without_crc as u64))
            .unwrap();

        eif_file
            .write_all(&eif_crc.to_be_bytes())
            .expect("Failed to write signature header");
    }
}
