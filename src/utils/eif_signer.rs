use aws_nitro_enclaves_cose::{
    crypto::kms::KmsKey, crypto::Openssl, crypto::SignatureAlgorithm, header_map::HeaderMap,
    CoseSign1,
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

use serde_cbor::to_vec;

use crate::defs::{EifHeader, EifSectionHeader, EifSectionType, PcrInfo, PcrSignature};

#[derive(Debug, PartialEq)]
pub enum SigningMethod {
    PKey,
    Kms,
    NoSign,
}

/// Used for signing enclave image file
pub struct EifSigner {
    /// EIF file path.
    pub eif_path: String,
    /// Method used to sign the enclave image. (PrivateKey or KMS)
    pub signing_method: SigningMethod,
    /// Certificate file path
    pub signing_certificate: Vec<u8>,
    /// Private key
    pub private_key: Option<Vec<u8>>,
    /// KMS key
    pub kms_key: Option<KmsKey>,
    /// Is signed
    pub is_signed: bool,
}

impl EifSigner {
    pub fn new(
        eif_path: String,
        signing_method: String,
        cert_path: String,
        key_path: Option<String>,
        region: Option<String>,
        key_id: Option<String>,
    ) -> Result<Self, String> {
        let mut method = SigningMethod::NoSign;
        let mut private_key = Vec::new();
        let mut kms_key = None;

        let mut certificate_file = File::open(cert_path)
            .map_err(|err| format!("Could not open the certificate file: {:?}", err))?;
        let mut signing_certificate = Vec::new();
        certificate_file
            .read_to_end(&mut signing_certificate)
            .map_err(|err| format!("Could not read the certificate file: {:?}", err))?;

        match signing_method.as_str() {
            "PrivateKey" => {
                method = SigningMethod::PKey;
                let key_path = key_path.as_ref().map(String::as_str).unwrap();

                let mut key_file = File::open(key_path)
                    .map_err(|err| format!("Could not open the key file: {:?}", err))?;
                key_file
                    .read_to_end(&mut private_key)
                    .map_err(|err| format!("Could not read the key file: {:?}", err))?;
            }
            "KMS" => {
                method = SigningMethod::Kms;
                let act = async {
                    let shared_config = aws_config::from_env()
                        .region(region.map(Region::new).unwrap())
                        .load()
                        .await;
                    let client = Client::new(&shared_config);
                    kms_key = Some(
                        KmsKey::new(client, key_id.unwrap(), SignatureAlgorithm::ES384)
                            .expect("Error building kms_key"),
                    );
                };
                let runtime = Runtime::new().unwrap();
                runtime.block_on(act);
            }
            _ => (),
        };

        let eif_reader = EifReader::from_eif(eif_path.clone())
            .map_err(|err| format!("Could not read the EIF: {:?}", err))?;

        Ok(EifSigner {
            eif_path: eif_path,
            signing_method: method,
            signing_certificate: signing_certificate,
            private_key: Some(private_key),
            kms_key: kms_key,
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

        let mut curr_seek = 0;

        // If the file is already signed, replace the existing signature
        if self.is_signed {
            let mut eif_content = Vec::<Vec<u8>>::new();
            let mut header_buf = vec![0u8; EifHeader::size()];
            let mut section_buf = vec![0u8; EifSectionHeader::size()];

            eif_file
                .read_exact(&mut header_buf)
                .map_err(|e| format!("Error while reading EIF header: {:?}", e))?;
            eif_content.push(header_buf.clone());

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
                    eif_content.push(serialized_signature.clone().to_vec());
                }

                eif_content.push(section_buf.clone());
                curr_seek += EifSectionHeader::size();
                curr_seek += section.section_size as usize;
                eif_file
                    .seek(SeekFrom::Start(curr_seek as u64))
                    .map_err(|e| format!("Failed to seek after EIF section: {:?}", e))?;
            }
            eif_file
                .seek(SeekFrom::Start(0))
                .map_err(|e| format!("Error while truncating EIF: {:?}", e))?;
            for section in eif_content {
                eif_file
                    .write_all(&section)
                    .map_err(|e| format!("Error while writing EIF: {:?}", e))?;
            }
        } else {
            // Create the signature section for an EIF that is not signed
            let eif_buffer = eif_section.to_be_bytes();

            eif_file
                .seek(SeekFrom::End(0))
                .map_err(|e| format!("Failed to seek file from end: {:?}", e))?;
            eif_file
                .write_all(&eif_buffer[..])
                .expect("Failed to write signature header");
            eif_file
                .write_all(&serialized_signature[..])
                .expect("Failed write signature");
        }

        Ok(())
    }

    /// Generates the signature based on the selected method and writes it to the EIF
    pub fn sign_image(&mut self) -> Result<(), String> {
        if self.signing_method == SigningMethod::NoSign {
            return Ok(());
        }

        let mut signature = Vec::new();
        let payload = self
            .get_payload()
            .expect("Failed to get payload for image signing.");

        match &self.signing_method {
            SigningMethod::PKey => {
                let private_key =
                    PKey::private_key_from_pem(&mut self.private_key.as_ref().unwrap())
                        .expect("Could not deserialize the PEM-formatted private key");

                signature =
                    CoseSign1::new::<Openssl>(&payload, &HeaderMap::new(), private_key.as_ref())
                        .unwrap()
                        .as_bytes(false)
                        .unwrap();
            }
            SigningMethod::Kms => {
                signature = CoseSign1::new::<Openssl>(
                    &payload,
                    &HeaderMap::new(),
                    self.kms_key.as_ref().unwrap(),
                )
                .unwrap()
                .as_bytes(false)
                .unwrap();
            }
            _ => (),
        }

        let pcr_signature = PcrSignature {
            signing_certificate: self.signing_certificate.clone(),
            signature,
        };

        self.write_signature(pcr_signature)
            .expect("Failed to write signature to EIF.");

        Ok(())
    }
}
