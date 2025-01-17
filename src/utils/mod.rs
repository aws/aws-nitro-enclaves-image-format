// Copyright 2019-2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]
pub mod eif_reader;
pub mod eif_signer;
pub mod identity;

use crate::defs::eif_hasher::EifHasher;
use crate::defs::{
    EifHeader, EifIdentityInfo, EifSectionHeader, EifSectionType, PcrSignature, EIF_MAGIC,
    MAX_NUM_SECTIONS,
};
use aws_nitro_enclaves_cose::{crypto::Openssl, CoseSign1};
use crc::{Crc, CRC_32_ISO_HDLC};
use openssl::asn1::Asn1Time;
use serde::{Deserialize, Serialize};
use serde_cbor::from_slice;
use sha2::Digest;
use std::cmp::Ordering;
use std::collections::BTreeMap;

pub use eif_signer::{EifSigner, SignKeyData, SignKeyDataInfo, SignKeyInfo};

/// Contains code for EifBuilder a simple library used for building an EifFile
/// from a:
///    - kernel_file
///    - cmdline string
///    - ramdisks files.
///
/// TODO:
///    - Unittests.
///    - Add support to write default_mem & default_cpus, flags.
///    - Various validity checks: E.g: kernel is a bzImage.
use std::ffi::CString;
use std::fmt::Debug;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::path::Path;

const DEFAULT_SECTIONS_COUNT: u16 = 3;

/// Utility function to calculate PCRs, used at build and describe.
pub fn get_pcrs<T: Digest + Debug + Write + Clone>(
    image_hasher: &mut EifHasher<T>,
    bootstrap_hasher: &mut EifHasher<T>,
    app_hasher: &mut EifHasher<T>,
    cert_hasher: &mut EifHasher<T>,
    hasher: T,
    is_signed: bool,
) -> Result<BTreeMap<String, String>, String> {
    let mut measurements = BTreeMap::new();
    let image_hasher = hex::encode(
        image_hasher
            .tpm_extend_finalize_reset()
            .map_err(|e| format!("Could not get result for image_hasher: {:?}", e))?,
    );
    let bootstrap_hasher = hex::encode(
        bootstrap_hasher
            .tpm_extend_finalize_reset()
            .map_err(|e| format!("Could not get result for bootstrap_hasher: {:?}", e))?,
    );
    let app_hash = hex::encode(
        app_hasher
            .tpm_extend_finalize_reset()
            .map_err(|e| format!("Could not get result for app_hasher: {:?}", e))?,
    );

    // Hash certificate only if signing key is set, otherwise related PCR will be zero
    let cert_hash = if is_signed {
        Some(hex::encode(
            cert_hasher
                .tpm_extend_finalize_reset()
                .map_err(|e| format!("Could not get result for cert_hash: {:?}", e))?,
        ))
    } else {
        None
    };

    measurements.insert("HashAlgorithm".to_string(), format!("{:?}", hasher));
    measurements.insert("PCR0".to_string(), image_hasher);
    measurements.insert("PCR1".to_string(), bootstrap_hasher);
    measurements.insert("PCR2".to_string(), app_hash);
    if let Some(cert_hash) = cert_hash {
        measurements.insert("PCR8".to_string(), cert_hash);
    }

    Ok(measurements)
}

pub struct EifBuilder<T: Digest + Debug + Write + Clone> {
    kernel: File,
    cmdline: Vec<u8>,
    ramdisks: Vec<File>,
    signer: Option<EifSigner>,
    signature: Option<Vec<u8>>,
    signature_size: u64,
    metadata: Vec<u8>,
    eif_hdr_flags: u16,
    default_mem: u64,
    default_cpus: u64,
    /// Hash of the whole EifImage.
    pub image_hasher: EifHasher<T>,
    /// Hash of the EifSections provided by Amazon
    /// Kernel + cmdline + First Ramdisk
    pub bootstrap_hasher: EifHasher<T>,
    /// Hash of the remaining ramdisks.
    pub customer_app_hasher: EifHasher<T>,
    /// Hash the signing certificate
    pub certificate_hasher: EifHasher<T>,
    hasher_template: T,
    eif_crc: u32,
}

impl<T: Digest + Debug + Write + Clone> EifBuilder<T> {
    pub fn new(
        kernel_path: &Path,
        cmdline: String,
        sign_info: Option<SignKeyData>,
        hasher: T,
        flags: u16,
        eif_info: EifIdentityInfo,
    ) -> Self {
        let kernel_file = File::open(kernel_path).expect("Invalid kernel path");
        let cmdline = CString::new(cmdline).expect("Invalid cmdline");
        let metadata = serde_json::to_vec(&eif_info).expect("Could not serialize metadata: {}");
        let signer = EifSigner::new(sign_info);
        EifBuilder {
            kernel: kernel_file,
            cmdline: cmdline.into_bytes(),
            ramdisks: Vec::new(),
            signer,
            signature: None,
            signature_size: 0,
            metadata,
            eif_hdr_flags: flags,
            default_mem: 1024 * 1024 * 1024,
            default_cpus: 2,
            image_hasher: EifHasher::new_without_cache(hasher.clone())
                .expect("Could not create image_hasher"),
            bootstrap_hasher: EifHasher::new_without_cache(hasher.clone())
                .expect("Could not create bootstrap_hasher"),
            customer_app_hasher: EifHasher::new_without_cache(hasher.clone())
                .expect("Could not create customer app hasher"),
            certificate_hasher: EifHasher::new_without_cache(hasher.clone())
                .expect("Could not create certificate hasher"),
            hasher_template: hasher,
            eif_crc: 0,
        }
    }

    pub fn is_signed(&mut self) -> bool {
        self.signer.is_some()
    }

    pub fn add_ramdisk(&mut self, ramdisk_path: &Path) {
        let ramdisk_file = File::open(ramdisk_path).expect("Invalid ramdisk path");
        self.ramdisks.push(ramdisk_file);
    }

    /// The first two sections are the kernel and the cmdline and the last is metadata.
    fn num_sections(&self) -> u16 {
        DEFAULT_SECTIONS_COUNT + self.ramdisks.len() as u16 + self.signer.iter().count() as u16
    }

    fn sections_offsets(&self) -> [u64; MAX_NUM_SECTIONS] {
        let mut result = [0; MAX_NUM_SECTIONS];
        result[0] = self.kernel_offset();
        result[1] = self.cmdline_offset();
        result[2] = self.metadata_offset();

        for i in 0..self.ramdisks.len() {
            result[i + DEFAULT_SECTIONS_COUNT as usize] = self.ramdisk_offset(i);
        }

        if self.signer.is_some() {
            result[DEFAULT_SECTIONS_COUNT as usize + self.ramdisks.len()] = self.signature_offset();
        }

        result
    }

    fn sections_sizes(&self) -> [u64; MAX_NUM_SECTIONS] {
        let mut result = [0; MAX_NUM_SECTIONS];

        result[0] = self.kernel_size();
        result[1] = self.cmdline_size();
        result[2] = self.metadata_size();

        for i in 0..self.ramdisks.len() {
            result[i + DEFAULT_SECTIONS_COUNT as usize] = self.ramdisk_size(&self.ramdisks[i]);
        }

        if self.signer.is_some() {
            result[DEFAULT_SECTIONS_COUNT as usize + self.ramdisks.len()] = self.signature_size();
        }

        result
    }

    fn eif_header_offset(&self) -> u64 {
        0
    }

    fn kernel_offset(&self) -> u64 {
        self.eif_header_offset() + EifHeader::size() as u64
    }

    fn kernel_size(&self) -> u64 {
        self.kernel.metadata().unwrap().len()
    }

    fn cmdline_offset(&self) -> u64 {
        self.kernel_offset() + EifSectionHeader::size() as u64 + self.kernel_size()
    }

    fn cmdline_size(&self) -> u64 {
        self.cmdline.len() as u64
    }

    fn ramdisk_offset(&self, index: usize) -> u64 {
        self.metadata_offset()
            + self.metadata_size()
            + EifSectionHeader::size() as u64
            + self.ramdisks[0..index]
                .iter()
                .fold(0, |mut total_len, file| {
                    total_len += file.metadata().expect("Invalid ramdisk metadata").len()
                        + EifSectionHeader::size() as u64;
                    total_len
                })
    }

    fn ramdisk_size(&self, ramdisk: &File) -> u64 {
        ramdisk.metadata().unwrap().len()
    }

    fn signature_offset(&self) -> u64 {
        let index = self.ramdisks.len() - 1;
        self.ramdisk_offset(index)
            + EifSectionHeader::size() as u64
            + self.ramdisk_size(&self.ramdisks[index])
    }

    fn signature_size(&self) -> u64 {
        self.signature_size
    }

    fn metadata_offset(&self) -> u64 {
        self.cmdline_offset() + EifSectionHeader::size() as u64 + self.cmdline_size()
    }

    fn metadata_size(&self) -> u64 {
        self.metadata.len() as u64
    }

    pub fn header(&mut self) -> EifHeader {
        EifHeader {
            magic: EIF_MAGIC,
            version: crate::defs::CURRENT_VERSION,
            flags: self.eif_hdr_flags,
            default_mem: self.default_mem,
            default_cpus: self.default_cpus,
            reserved: 0,
            num_sections: self.num_sections(),
            section_offsets: self.sections_offsets(),
            section_sizes: self.sections_sizes(),
            unused: 0,
            eif_crc32: self.eif_crc,
        }
    }

    /// Compute the crc for the whole enclave image, excluding the
    /// eif_crc32 field from the EIF header.
    pub fn compute_crc(&mut self) {
        let crc_gen = Crc::<u32>::new(&CRC_32_ISO_HDLC);
        let mut crc = crc_gen.digest();
        let eif_header = self.header();
        let eif_buffer = eif_header.to_be_bytes();
        // The last field of the EifHeader is the CRC itself, so we need
        // to exclude it from contributing to the CRC.
        let len_without_crc = eif_buffer.len() - size_of::<u32>();
        crc.update(&eif_buffer[..len_without_crc]);

        let eif_section = EifSectionHeader {
            section_type: EifSectionType::EifSectionKernel,
            flags: 0,
            section_size: self.kernel_size(),
        };

        let eif_buffer = eif_section.to_be_bytes();
        crc.update(&eif_buffer[..]);
        let mut kernel_file = &self.kernel;

        kernel_file
            .seek(SeekFrom::Start(0))
            .expect("Could not seek kernel to beginning");
        let mut buffer = Vec::new();
        kernel_file
            .read_to_end(&mut buffer)
            .expect("Failed to read kernel content");

        crc.update(&buffer[..]);

        let eif_section = EifSectionHeader {
            section_type: EifSectionType::EifSectionCmdline,
            flags: 0,
            section_size: self.cmdline_size(),
        };

        let eif_buffer = eif_section.to_be_bytes();
        crc.update(&eif_buffer[..]);
        crc.update(&self.cmdline[..]);

        let eif_section = EifSectionHeader {
            section_type: EifSectionType::EifSectionMetadata,
            flags: 0,
            section_size: self.metadata_size(),
        };

        let eif_buffer = eif_section.to_be_bytes();
        crc.update(&eif_buffer[..]);
        crc.update(&self.metadata[..]);

        for mut ramdisk in &self.ramdisks {
            let eif_section = EifSectionHeader {
                section_type: EifSectionType::EifSectionRamdisk,
                flags: 0,
                section_size: self.ramdisk_size(ramdisk),
            };

            let eif_buffer = eif_section.to_be_bytes();
            crc.update(&eif_buffer[..]);

            ramdisk
                .seek(SeekFrom::Start(0))
                .expect("Could not seek kernel to begining");
            let mut buffer = Vec::new();
            ramdisk
                .read_to_end(&mut buffer)
                .expect("Failed to read kernel content");
            crc.update(&buffer[..]);
        }

        if let Some(signature) = &self.signature {
            let eif_section = EifSectionHeader {
                section_type: EifSectionType::EifSectionSignature,
                flags: 0,
                section_size: self.signature_size(),
            };

            let eif_buffer = eif_section.to_be_bytes();
            crc.update(&eif_buffer[..]);
            crc.update(&signature[..]);
        }

        self.eif_crc = crc.finalize();
    }

    pub fn write_header(&mut self, file: &mut File) {
        let eif_header = self.header();
        file.seek(SeekFrom::Start(self.eif_header_offset())).expect(
            "Could not seek while writing eif \
             header",
        );
        let eif_buffer = eif_header.to_be_bytes();
        file.write_all(&eif_buffer[..])
            .expect("Failed to write eif header");
    }

    pub fn write_kernel(&mut self, eif_file: &mut File) {
        let eif_section = EifSectionHeader {
            section_type: EifSectionType::EifSectionKernel,
            flags: 0,
            section_size: self.kernel_size(),
        };

        eif_file
            .seek(SeekFrom::Start(self.kernel_offset()))
            .expect("Could not seek while writing kernel section");
        let eif_buffer = eif_section.to_be_bytes();
        eif_file
            .write_all(&eif_buffer[..])
            .expect("Failed to write kernel header");
        let mut kernel_file = &self.kernel;

        kernel_file
            .seek(SeekFrom::Start(0))
            .expect("Could not seek kernel to begining");
        let mut buffer = Vec::new();
        kernel_file
            .read_to_end(&mut buffer)
            .expect("Failed to read kernel content");

        eif_file
            .write_all(&buffer[..])
            .expect("Failed to write kernel data");
    }

    pub fn write_cmdline(&mut self, eif_file: &mut File) {
        let eif_section = EifSectionHeader {
            section_type: EifSectionType::EifSectionCmdline,
            flags: 0,
            section_size: self.cmdline_size(),
        };

        eif_file
            .seek(SeekFrom::Start(self.cmdline_offset()))
            .expect(
                "Could not seek while writing
        cmdline section",
            );
        let eif_buffer = eif_section.to_be_bytes();
        eif_file
            .write_all(&eif_buffer[..])
            .expect("Failed to write cmdline header");

        eif_file
            .write_all(&self.cmdline[..])
            .expect("Failed write cmdline header");
    }

    pub fn write_metadata(&mut self, eif_file: &mut File) {
        let eif_section = EifSectionHeader {
            section_type: EifSectionType::EifSectionMetadata,
            flags: 0,
            section_size: self.metadata_size(),
        };

        eif_file
            .seek(SeekFrom::Start(self.metadata_offset()))
            .expect("Could not seek while writing metadata section");

        let eif_buffer = eif_section.to_be_bytes();
        eif_file
            .write_all(&eif_buffer[..])
            .expect("Failed to write metadata header");

        eif_file
            .write_all(&self.metadata)
            .expect("Failed to write metadata content");
    }

    pub fn write_ramdisks(&mut self, eif_file: &mut File) {
        for (index, mut ramdisk) in self.ramdisks.iter().enumerate() {
            let eif_section = EifSectionHeader {
                section_type: EifSectionType::EifSectionRamdisk,
                flags: 0,
                section_size: self.ramdisk_size(ramdisk),
            };

            eif_file
                .seek(SeekFrom::Start(self.ramdisk_offset(index)))
                .expect(
                    "Could not seek while writing
        kernel section",
                );
            let eif_buffer = eif_section.to_be_bytes();
            eif_file
                .write_all(&eif_buffer[..])
                .expect("Failed to write section header");

            ramdisk
                .seek(SeekFrom::Start(0))
                .expect("Could not seek ramdisk to beginning");
            let mut buffer = Vec::new();
            ramdisk
                .read_to_end(&mut buffer)
                .expect("Failed to read ramdisk content");
            eif_file
                .write_all(&buffer[..])
                .expect("Failed to write ramdisk data");
        }
    }

    pub fn write_signature(&mut self, eif_file: &mut File) {
        if let Some(signature) = &self.signature {
            let eif_section = EifSectionHeader {
                section_type: EifSectionType::EifSectionSignature,
                flags: 0,
                section_size: self.signature_size(),
            };

            eif_file
                .seek(SeekFrom::Start(self.signature_offset()))
                .expect("Could not seek while writing signature section");
            let eif_buffer = eif_section.to_be_bytes();
            eif_file
                .write_all(&eif_buffer[..])
                .expect("Failed to write signature header");

            eif_file
                .write_all(&signature[..])
                .expect("Failed write signature header");
        }
    }

    pub fn write_to(&mut self, output_file: &mut File) -> BTreeMap<String, String> {
        self.measure();
        let measurements = get_pcrs(
            &mut self.image_hasher,
            &mut self.bootstrap_hasher,
            &mut self.customer_app_hasher,
            &mut self.certificate_hasher,
            self.hasher_template.clone(),
            self.signer.is_some(),
        )
        .expect("Failed to get measurements");
        if let Some(signer) = self.signer.as_ref() {
            let signature = signer
                .generate_eif_signature(&measurements)
                .expect("Failed to generate signature");
            self.signature_size = signature.len() as u64;
            self.signature = Some(signature);
        }
        self.compute_crc();
        self.write_header(output_file);
        self.write_kernel(output_file);
        self.write_cmdline(output_file);
        self.write_metadata(output_file);
        self.write_ramdisks(output_file);
        self.write_signature(output_file);
        measurements
    }

    pub fn measure(&mut self) {
        let mut kernel_file = &self.kernel;
        kernel_file
            .seek(SeekFrom::Start(0))
            .expect("Could not seek kernel to beginning");
        let mut buffer = Vec::new();
        kernel_file
            .read_to_end(&mut buffer)
            .expect("Failed to read kernel content");
        self.image_hasher.write_all(&buffer[..]).unwrap();
        self.bootstrap_hasher.write_all(&buffer[..]).unwrap();

        self.image_hasher.write_all(&self.cmdline[..]).unwrap();
        self.bootstrap_hasher.write_all(&self.cmdline[..]).unwrap();

        for (index, mut ramdisk) in self.ramdisks.iter().enumerate() {
            ramdisk
                .seek(SeekFrom::Start(0))
                .expect("Could not seek kernel to beginning");
            let mut buffer = Vec::new();
            ramdisk
                .read_to_end(&mut buffer)
                .expect("Failed to read kernel content");
            self.image_hasher.write_all(&buffer[..]).unwrap();
            // The first ramdisk is provided by amazon and it contains the
            // code to bootstrap the docker container.
            if index == 0 {
                self.bootstrap_hasher.write_all(&buffer[..]).unwrap();
            } else {
                self.customer_app_hasher.write_all(&buffer[..]).unwrap();
            }
        }

        if let Some(signer) = self.signer.as_ref() {
            let cert_der = signer
                .get_cert_der()
                .expect("Certificate must be available and convertible to DER");
            // This is equivalent to extend(cert.digest(sha384)), since hasher is going to
            // hash the DER certificate (cert.digest()) and then tpm_extend_finalize_reset
            // will do the extend.
            self.certificate_hasher.write_all(&cert_der).unwrap();
        }
    }
}

/// PCR Signature verifier that checks the validity of
/// the certificate used to sign the enclave
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PcrSignatureChecker {
    signing_certificate: Vec<u8>,
    signature: Vec<u8>,
}

impl PcrSignatureChecker {
    pub fn new(pcr_signature: &PcrSignature) -> Self {
        PcrSignatureChecker {
            signing_certificate: pcr_signature.signing_certificate.clone(),
            signature: pcr_signature.signature.clone(),
        }
    }

    /// Reads EIF section headers and looks for a signature.
    /// Seek to the signature section, if present, and save the certificate and signature
    pub fn from_eif(eif_path: &str) -> Result<Self, String> {
        let mut signing_certificate = Vec::new();
        let mut signature = Vec::new();

        let mut curr_seek = 0;
        let mut eif_file =
            File::open(eif_path).map_err(|e| format!("Failed to open the EIF file: {:?}", e))?;

        // Skip header
        let mut header_buf = vec![0u8; EifHeader::size()];
        eif_file
            .read_exact(&mut header_buf)
            .map_err(|e| format!("Error while reading EIF header: {:?}", e))?;

        curr_seek += EifHeader::size();
        eif_file
            .seek(SeekFrom::Start(curr_seek as u64))
            .map_err(|e| format!("Failed to seek file from start: {:?}", e))?;

        let mut section_buf = vec![0u8; EifSectionHeader::size()];

        // Read all section headers and skip if different from signature section
        while eif_file.read_exact(&mut section_buf).is_ok() {
            let section = EifSectionHeader::from_be_bytes(&section_buf)
                .map_err(|e| format!("Error extracting EIF section header: {:?}", e))?;
            curr_seek += EifSectionHeader::size();

            if section.section_type == EifSectionType::EifSectionSignature {
                let mut buf = vec![0u8; section.section_size as usize];
                eif_file
                    .seek(SeekFrom::Start(curr_seek as u64))
                    .map_err(|e| format!("Failed to seek after EIF section header: {:?}", e))?;
                eif_file.read_exact(&mut buf).map_err(|e| {
                    format!("Error while reading signature section from EIF: {:?}", e)
                })?;

                // Deserialize PCR signature structure and save certificate and signature
                let des_sign: Vec<PcrSignature> = from_slice(&buf[..])
                    .map_err(|e| format!("Error deserializing certificate: {:?}", e))?;

                signing_certificate.clone_from(&des_sign[0].signing_certificate);
                signature.clone_from(&des_sign[0].signature);
            }

            curr_seek += section.section_size as usize;
            eif_file
                .seek(SeekFrom::Start(curr_seek as u64))
                .map_err(|e| format!("Failed to seek after EIF section: {:?}", e))?;
        }

        Ok(Self {
            signing_certificate,
            signature,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.signing_certificate.len() == 0 && self.signature.len() == 0
    }

    /// Verifies the validity of the signing certificate
    pub fn verify(&mut self) -> Result<(), String> {
        let signature = CoseSign1::from_bytes(&self.signature[..])
            .map_err(|err| format!("Could not deserialize the signature: {:?}", err))?;
        let cert = openssl::x509::X509::from_pem(&self.signing_certificate[..])
            .map_err(|_| "Could not deserialize the signing certificate".to_string())?;
        let public_key = cert
            .public_key()
            .map_err(|_| "Could not get the public key from the signing certificate".to_string())?;

        // Verify the signature
        let result = signature
            .verify_signature::<Openssl>(public_key.as_ref())
            .map_err(|err| format!("Could not verify EIF signature: {:?}", err))?;
        if !result {
            return Err("The EIF signature is not valid".to_string());
        }

        // Verify that the signing certificate is not expired
        let current_time = Asn1Time::days_from_now(0).map_err(|err| err.to_string())?;
        if current_time
            .compare(cert.not_after())
            .map_err(|err| err.to_string())?
            == Ordering::Greater
            || current_time
                .compare(cert.not_before())
                .map_err(|err| err.to_string())?
                == Ordering::Less
        {
            return Err("The signing certificate is expired".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::eif_signer::{SignKey, SignKeyData, SignKeyDataInfo, SignKeyInfo};
    use std::{env, io::Write};
    use tempfile::{NamedTempFile, TempPath};

    const TEST_CERT_CONTENT: &[u8] = "test cert content".as_bytes();
    const TEST_PKEY_CONTENT: &[u8] = "test key content".as_bytes();

    fn generate_certificate_file() -> Result<TempPath, std::io::Error> {
        let cert_file = NamedTempFile::new()?;
        cert_file.as_file().write(TEST_CERT_CONTENT)?;
        Ok(cert_file.into_temp_path())
    }

    fn generate_pkey_file() -> Result<TempPath, std::io::Error> {
        let key_file = NamedTempFile::new()?;
        key_file.as_file().write(TEST_PKEY_CONTENT)?;
        Ok(key_file.into_temp_path())
    }

    #[test]
    fn test_local_sign_key_data_from_invalid_local_key_info() -> Result<(), std::io::Error> {
        let cert_file_path = generate_certificate_file()?;

        let key_data = SignKeyData::new(&SignKeyDataInfo {
            cert_path: (&cert_file_path).into(),
            key_info: SignKeyInfo::LocalPrivateKeyInfo {
                path: "/invalid/path".into(),
            },
        });

        assert!(key_data.is_err());
        Ok(())
    }

    #[test]
    fn test_local_sign_key_data_from_invalid_cert_key_info() -> Result<(), std::io::Error> {
        let key_file_path = generate_pkey_file()?;

        let key_data = SignKeyData::new(&SignKeyDataInfo {
            cert_path: "/invalid/path".into(),
            key_info: SignKeyInfo::LocalPrivateKeyInfo {
                path: (&key_file_path).into(),
            },
        });

        assert!(key_data.is_err());
        Ok(())
    }

    #[test]
    fn test_local_sign_key_data_from_valid_key_info() -> Result<(), std::io::Error> {
        let cert_file_path = generate_certificate_file()?;
        let key_file_path = generate_pkey_file()?;

        let key_data = SignKeyData::new(&SignKeyDataInfo {
            cert_path: (&cert_file_path).into(),
            key_info: SignKeyInfo::LocalPrivateKeyInfo {
                path: (&key_file_path).into(),
            },
        })
        .unwrap();

        assert_eq!(key_data.cert, TEST_CERT_CONTENT);
        assert!(matches!(key_data.key, SignKey::LocalPrivateKey(key) if key == TEST_PKEY_CONTENT));

        Ok(())
    }

    mod kms {
        use std::sync::Mutex;

        use super::*;

        // Mutex to lock and prevent running tests that modify AWS_REGION env variable
        // within multiple threads
        static ENV_MUTEX: std::sync::Mutex<i32> = Mutex::new(0);

        #[test]
        fn test_kms_sign_key_data_from_invalid_cert_key_info() -> Result<(), std::io::Error> {
            let key_id = env::var("AWS_KMS_TEST_KEY_ID").expect("Please set AWS_KMS_TEST_KEY_ID");
            let key_region = env::var("AWS_KMS_TEST_KEY_REGION").ok();

            let key_data = SignKeyData::new(&SignKeyDataInfo {
                cert_path: "/invalid/path".into(),
                key_info: SignKeyInfo::KmsKeyInfo {
                    id: key_id,
                    region: key_region,
                },
            });

            assert!(key_data.is_err());
            Ok(())
        }

        #[test]
        fn test_kms_sign_key_data_from_valid_key_info_explicit_region() -> Result<(), std::io::Error>
        {
            let cert_file_path = generate_certificate_file()?;
            let key_id = env::var("AWS_KMS_TEST_KEY_ID").expect("Please set AWS_KMS_TEST_KEY_ID");
            let key_region =
                env::var("AWS_KMS_TEST_KEY_REGION").expect("Please set AWS_KMS_TEST_KEY_REGION");
            let _m = ENV_MUTEX.lock().unwrap();
            env::remove_var("AWS_REGION");

            let key_data = SignKeyData::new(&SignKeyDataInfo {
                cert_path: (&cert_file_path).into(),
                key_info: SignKeyInfo::KmsKeyInfo {
                    id: key_id,
                    region: Some(key_region),
                },
            })
            .unwrap();

            assert_eq!(key_data.cert, TEST_CERT_CONTENT);
            assert!(matches!(key_data.key, SignKey::KmsKey(_)));

            Ok(())
        }

        #[test]
        fn test_kms_sign_key_data_from_valid_key_info_region_from_env() -> Result<(), std::io::Error>
        {
            let cert_file_path = generate_certificate_file()?;
            let key_id = env::var("AWS_KMS_TEST_KEY_ID").expect("Please set AWS_KMS_TEST_KEY_ID");
            let key_region =
                env::var("AWS_KMS_TEST_KEY_REGION").expect("Please set AWS_KMS_TEST_KEY_REGION");

            let _m = ENV_MUTEX.lock().unwrap();
            env::set_var("AWS_REGION", key_region);

            let key_data = SignKeyData::new(&SignKeyDataInfo {
                cert_path: (&cert_file_path).into(),
                key_info: SignKeyInfo::KmsKeyInfo {
                    id: key_id,
                    region: None,
                },
            })
            .unwrap();

            assert_eq!(key_data.cert, TEST_CERT_CONTENT);
            assert!(matches!(key_data.key, SignKey::KmsKey(_)));

            Ok(())
        }

        #[test]
        fn test_kms_sign_key_data_from_valid_key_info_no_region() -> Result<(), std::io::Error> {
            let cert_file_path = generate_certificate_file()?;
            let key_id = env::var("AWS_KMS_TEST_KEY_ID").expect("Please set AWS_KMS_TEST_KEY_ID");

            let _m = ENV_MUTEX.lock().unwrap();
            env::remove_var("AWS_REGION");

            let key_data = SignKeyData::new(&SignKeyDataInfo {
                cert_path: (&cert_file_path).into(),
                key_info: SignKeyInfo::KmsKeyInfo {
                    id: key_id,
                    region: None,
                },
            });

            assert!(key_data.is_err());
            Ok(())
        }
    }
}
