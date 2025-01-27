use crate::defs::{EifHeader, EifSectionHeader, EifSectionType, PcrInfo, PcrSignature};
use crate::utils::eif_reader::EifReader;
use crate::utils::get_pcrs;
use aws_config::BehaviorVersion;
use aws_nitro_enclaves_cose::{
    crypto::kms::KmsKey, crypto::Openssl, header_map::HeaderMap, CoseSign1,
};
use aws_sdk_kms::client::Client;
use aws_types::region::Region;
use openssl::pkey::PKey;
use regex::Regex;
use serde_cbor::to_vec;
use sha2::{Digest, Sha384};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::sync::Arc;
use tokio::runtime::Runtime;

// Signing key for eif images
pub enum SignKey {
    // Local private key
    LocalPrivateKey(Vec<u8>),

    // KMS signer implementation from Cose library
    KmsKey(Arc<KmsKey>),
}

// Signing key details
#[derive(Clone, Debug)]
enum SignKeyInfo {
    // Local private key file path
    LocalPrivateKeyInfo { path: std::path::PathBuf },

    // KMS key details
    KmsKeyInfo { id: String, region: Option<String> },
}

impl SignKeyInfo {
    pub fn new(key_location: &str) -> Result<Self, String> {
        match parse_kms_arn(key_location) {
            Some((region, key_id)) => Ok(SignKeyInfo::KmsKeyInfo {
                id: key_id,
                region: Some(region),
            }),
            None => Ok(SignKeyInfo::LocalPrivateKeyInfo {
                path: key_location.into(),
            }),
        }
    }
}

fn parse_kms_arn(s: &str) -> Option<(String, String)> {
    // Matches KMS key ARNs in the format:
    // arn:partition:kms:region:account-id:key[/|:]key-id where:
    // - partition is: aws, aws-cn, or aws-us-gov
    // - region is captured: letters, numbers, hyphens
    // - account-id: exactly 12 digits
    // - key-id is captured: letters, numbers, hyphens
    let re = Regex::new(
        r"^arn:(?:aws|aws-cn|aws-us-gov):kms:([a-z0-9-]+):\d{12}:key[:/]([a-zA-Z0-9-]+)$",
    )
    .expect("Regular expression for parsing ARNs must be valid");

    re.captures(s).map(|caps| {
        // Safe to use index access since we know the pattern has exactly 2 capture groups
        (caps[1].to_string(), caps[2].to_string())
    })
}

// Full signining key data
pub struct SignKeyData {
    // x509 certificate
    pub cert: Vec<u8>,

    // Signing key itself
    pub key: SignKey,
}

impl SignKeyData {
    pub fn new(key_location: &str, certificate: &std::path::Path) -> Result<Self, String> {
        let key_info = SignKeyInfo::new(key_location)?;

        let mut cert_file = File::open(certificate)
            .map_err(|err| format!("Could not open the certificate file: {:?}", err))?;
        let mut cert = Vec::new();
        cert_file
            .read_to_end(&mut cert)
            .map_err(|err| format!("Could not read the certificate file: {:?}", err))?;

        let key = match &key_info {
            SignKeyInfo::LocalPrivateKeyInfo { path } => {
                let mut key_file = File::open(path)
                    .map_err(|err| format!("Could not open the key file: {:?}", err))?;
                let mut key_data = Vec::new();
                key_file
                    .read_to_end(&mut key_data)
                    .map_err(|err| format!("Could not read the key file: {:?}", err))?;

                SignKey::LocalPrivateKey(key_data)
            }
            SignKeyInfo::KmsKeyInfo { id, region } => {
                // Method `KmsKey::new_with_public_key` must be called from a thread being run
                // by Tokio runtime, or from a thread with an active `EnterGuard`.
                let act = async {
                    let mut config_loader = aws_config::defaults(BehaviorVersion::latest());
                    if let Some(region_id) = region {
                        config_loader = config_loader.region(Region::new(region_id.clone()));
                    }

                    let sdk_config = config_loader.load().await;
                    if sdk_config.region().is_none() {
                        return Err("AWS region for KMS is not specified".to_string());
                    }

                    let id_copy = id.clone();
                    tokio::task::spawn_blocking(move || {
                        let client = Client::new(&sdk_config);
                        KmsKey::new_with_public_key(client, id_copy, None)
                            .map_err(|e| e.to_string())
                    })
                    .await
                    .unwrap()
                };
                let runtime = Runtime::new().map_err(|e| e.to_string())?;
                let key = runtime.block_on(act)?;
                SignKey::KmsKey(Arc::new(key))
            }
        };

        Ok(SignKeyData { cert, key })
    }
}

pub struct EifSigner {
    key_data: SignKeyData,
}

impl EifSigner {
    pub fn new(sign_key: Option<SignKeyData>) -> Option<Self> {
        sign_key.map(|key| EifSigner { key_data: key })
    }

    pub fn sign(&self, payload: &[u8]) -> Result<PcrSignature, String> {
        let cose_sign = match &self.key_data.key {
            SignKey::LocalPrivateKey(key) => {
                let pkey = PKey::private_key_from_pem(key).map_err(|e| {
                    format!("Failed to deserialize PEM-formatted private key: {}", e)
                })?;

                CoseSign1::new::<Openssl>(payload, &HeaderMap::new(), &pkey)
                    .map_err(|e| format!("Failed to create CoseSign1 with local key: {}", e))?
            }
            SignKey::KmsKey(key) => {
                let arc_key = key.clone();
                let runtime =
                    Runtime::new().map_err(|e| format!("Failed to create Tokio runtime: {}", e))?;

                runtime.block_on(async move {
                    let payload_copy = Vec::from(payload);
                    tokio::task::spawn_blocking(move || {
                        CoseSign1::new::<Openssl>(&payload_copy, &HeaderMap::new(), &*arc_key)
                            .map_err(|e| format!("Failed to create CoseSign1 with KMS key: {}", e))
                    })
                    .await
                    .map_err(|e| format!("Task join error: {}", e))?
                })?
            }
        };

        let signature = cose_sign
            .as_bytes(false)
            .map_err(|e| format!("Failed to get signature bytes: {}", e))?;

        Ok(PcrSignature {
            signing_certificate: self.key_data.cert.clone(),
            signature,
        })
    }

    /// Generate the signature of a certain PCR.
    fn generate_pcr_signature(
        &self,
        register_index: i32,
        register_value: Vec<u8>,
    ) -> Result<PcrSignature, String> {
        let pcr_info = PcrInfo::new(register_index, register_value);
        let payload = to_vec(&pcr_info).expect("Could not serialize PCR info");

        self.sign(payload.as_slice())
    }

    /// Generate the signature of the EIF.
    /// eif_signature = [pcr0_signature]
    pub fn generate_eif_signature(
        &self,
        measurements: &BTreeMap<String, String>,
    ) -> Result<Vec<u8>, String> {
        let pcr0_index = 0;
        let pcr0_value = hex::decode(
            measurements
                .get("PCR0")
                .ok_or_else(|| "PCR0 measurement not found".to_string())?,
        )
        .map_err(|e| format!("Failed to decode PCR0 hex value: {}", e))?;

        let pcr0_signature = self.generate_pcr_signature(pcr0_index, pcr0_value)?;

        let eif_signature = vec![pcr0_signature];
        to_vec(&eif_signature).map_err(|e| format!("Failed to serialize signature: {}", e))
    }

    pub fn get_cert_der(&self) -> Result<Vec<u8>, String> {
        let cert = openssl::x509::X509::from_pem(&self.key_data.cert)
            .map_err(|e| format!("Failed to parse PEM certificate: {}", e))?;

        cert.to_der()
            .map_err(|e| format!("Failed to convert certificate to DER format: {}", e))
    }

    /// Writes the provided pcr signature to an existing EIF
    pub fn write_signature(
        &self,
        eif_path: &str,
        serialized_signature: Vec<u8>,
        is_signed: bool,
    ) -> Result<(), String> {
        let mut eif_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(eif_path)
            .map_err(|e| format!("Failed to open file: {:?}", e))?;
        let new_signature_size = serialized_signature.len() as u64;
        let mut header = self.read_and_parse_header(&mut eif_file)?;

        let signature_section = EifSectionHeader {
            section_type: EifSectionType::EifSectionSignature,
            flags: 0,
            section_size: new_signature_size,
        };

        // Determine where to write the signature
        let (signature_offset, section_id, old_signature_size) = if is_signed {
            self.find_existing_signature(&mut eif_file, &header)?
        } else {
            let file_len = eif_file
                .metadata()
                .map_err(|e| format!("Failed to get file metadata: {:?}", e))?
                .len();
            (file_len, header.num_sections as usize, 0)
        };

        let section_header_size = EifSectionHeader::size() as u64;
        let old_section_end = signature_offset + section_header_size + old_signature_size;
        let new_section_end = signature_offset + section_header_size + new_signature_size;
        let mut remaining_data = Vec::new();

        if is_signed {
            // Read all data after the old signature section
            eif_file
                .seek(SeekFrom::Start(old_section_end))
                .and_then(|_| eif_file.read_to_end(&mut remaining_data))
                .map_err(|e| format!("Failed to read remaining data: {:?}", e))?;

            // Calculate the shift amount (positive if expanding, negative if shrinking)
            let shift_amount = (new_section_end as i64) - (old_section_end as i64);

            // Update offsets in the header for all sections after the signature
            for i in (section_id + 1)..header.num_sections as usize {
                header.section_offsets[i] =
                    (header.section_offsets[i] as i64 + shift_amount) as u64;
            }
        } else {
            // For new signatures, just append to the end
            header.section_offsets[section_id] = signature_offset;
            header.section_sizes[section_id] = new_signature_size;
            header.num_sections += 1;
        }

        // Write updated header
        eif_file
            .seek(SeekFrom::Start(0))
            .and_then(|_| eif_file.write_all(&header.to_be_bytes()))
            .map_err(|e| format!("Failed to write header: {:?}", e))?;

        // Write signature section
        eif_file
            .seek(SeekFrom::Start(signature_offset))
            .and_then(|_| eif_file.write_all(&signature_section.to_be_bytes()))
            .and_then(|_| eif_file.write_all(&serialized_signature))
            .map_err(|e| format!("Failed to write signature: {:?}", e))?;

        // Write the remaining data at the new position
        eif_file
            .write_all(&remaining_data)
            .map_err(|e| format!("Failed to write remaining data: {:?}", e))?;

        // Set the new file length
        let new_file_size = new_section_end + remaining_data.len() as u64;
        eif_file.set_len(new_file_size).map_err(|e| {
            format!(
                "Failed to set new file length after writing signature: {:?}",
                e
            )
        })
    }

    fn read_and_parse_header(&self, file: &mut File) -> Result<EifHeader, String> {
        let mut header_buf = vec![0u8; EifHeader::size()];
        file.read_exact(&mut header_buf)
            .map_err(|e| format!("Error while reading EIF header: {:?}", e))?;

        EifHeader::from_be_bytes(&header_buf).map_err(|e| format!("Error parsing header: {:?}", e))
    }

    fn find_existing_signature(
        &self,
        eif_file: &mut File,
        header: &EifHeader,
    ) -> Result<(u64, usize, u64), String> {
        for i in 0..header.num_sections as usize {
            let offset = header.section_offsets[i];
            let mut section_header_buf = vec![0u8; EifSectionHeader::size()];

            eif_file
                .seek(SeekFrom::Start(offset))
                .map_err(|e| format!("Failed to seek: {:?}", e))?;

            eif_file
                .read_exact(&mut section_header_buf)
                .map_err(|e| format!("Failed to read section header: {:?}", e))?;

            let section_header = EifSectionHeader::from_be_bytes(&section_header_buf)
                .map_err(|e| format!("Failed to parse section header: {:?}", e))?;

            if section_header.section_type == EifSectionType::EifSectionSignature {
                return Ok((offset, i, section_header.section_size));
            }
        }
        Err("Signature section not found".to_string())
    }

    /// Generates the signature based on the selected method and writes it to the EIF
    pub fn sign_image(&self, eif_path: &str) -> Result<(), String> {
        // Read PCRs and check if EIF already has a signature
        let mut eif_reader = EifReader::from_eif(eif_path.into())?;
        let has_signature = eif_reader.signature_section.is_some();
        let measurements = get_pcrs(
            &mut eif_reader.image_hasher,
            &mut eif_reader.bootstrap_hasher,
            &mut eif_reader.app_hasher,
            &mut eif_reader.cert_hasher,
            Sha384::new(),
            has_signature,
        )?;

        let signature = self.generate_eif_signature(&measurements)?;
        self.write_signature(eif_path, signature, has_signature)
            .map_err(|e| format!("Failed to write signature to EIF: {}", e))?;

        // Update CRC of the EIF
        self.update_crc(eif_path)
    }

    pub fn update_crc(&self, eif_path: &str) -> Result<(), String> {
        // Create a new instance of Reader to calculate the actual CRC
        let eif_reader = EifReader::from_eif(eif_path.into())?;

        let mut eif_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(eif_path)
            .map_err(|err| format!("Could not open the EIF: {:?}", err))?;

        let len_without_crc = EifHeader::size() - size_of::<u32>();
        eif_file
            .seek(SeekFrom::Start(len_without_crc as u64))
            .map_err(|err| format!("Could not seek in the EIF: {:?}", err))?;

        eif_file
            .write_all(&eif_reader.eif_crc.to_be_bytes())
            .map_err(|err| format!("Failed to write checksum: {:?}", err))
    }
}
