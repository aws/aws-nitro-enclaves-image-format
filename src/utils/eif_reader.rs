// Copyright 2019-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::defs::eif_hasher::EifHasher;
use crate::defs::{
    EifHeader, EifIdentityInfo, EifSection, EifSectionHeader, EifSectionType, EifSignature,
    PcrInfo, PcrSignature, EIF_MAGIC, MAX_NUM_SECTIONS,
};
use crate::utils::cbor::{from_slice, to_vec};
use crate::utils::get_pcrs;
use aws_nitro_enclaves_cose::{crypto::Openssl, CoseSign1};
use crc::{Crc, CRC_32_ISO_HDLC};
use openssl::pkey::PKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::size_of;

/// The information about the signing certificate to be provided for a `describe-eif` request.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignCertificateInfo {
    #[serde(rename = "IssuerName")]
    /// Certificate's subject name.
    pub issuer_name: BTreeMap<String, String>,
    #[serde(rename = "Algorithm")]
    /// Certificate's signature algorithm
    pub algorithm: String,
    #[serde(rename = "NotBefore")]
    /// Not before validity period
    pub not_before: String,
    #[serde(rename = "NotAfter")]
    /// Not after validity period
    pub not_after: String,
    #[serde(rename = "Signature")]
    /// Certificate's signature in hex format: 'XX:XX:XX..'
    pub signature: String,
}

impl SignCertificateInfo {
    /// Create new signing certificate information structure
    pub fn new(
        issuer_name: BTreeMap<String, String>,
        algorithm: String,
        not_before: String,
        not_after: String,
        signature: String,
    ) -> Self {
        SignCertificateInfo {
            issuer_name,
            algorithm,
            not_before,
            not_after,
            signature,
        }
    }
}

/// Deserializes the data of an `EifSectionSignature` section
pub fn parse_signature_section(data: &[u8]) -> Result<EifSignature, String> {
    from_slice(data).map_err(|e| format!("Error deserializing signature section: {:?}", e))
}

/// Iterates over the sections of an EIF file, locating them through the
/// section offsets in the `EifHeader`, like the Nitro hypervisor does.
///
/// Only section headers are read while iterating. Section data can be
/// streamed with `copy_data` or loaded with `read_data`, so large ramdisks
/// don't have to fit in memory.
///
/// The data length of a section is taken from its section header, which
/// can differ from the matching `EifHeader::section_sizes` entry (e.g. on
/// re-signed images, see issue #54). Callers can compare the two.
pub struct Sections<R> {
    reader: R,
    header: EifHeader,
    index: usize,
}

impl<R: Read + Seek> Sections<R> {
    pub fn new(mut reader: R) -> Result<Self, String> {
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| format!("Failed to seek to EIF header: {:?}", e))?;
        let mut header_buf = vec![0u8; EifHeader::size()];
        reader
            .read_exact(&mut header_buf)
            .map_err(|e| format!("Error while reading EIF header: {:?}", e))?;
        let header = EifHeader::from_be_bytes(&header_buf)
            .map_err(|e| format!("Error while parsing EIF header: {:?}", e))?;

        if header.magic != EIF_MAGIC {
            return Err("Invalid EIF magic".to_string());
        }
        if header.num_sections as usize > MAX_NUM_SECTIONS {
            return Err(format!(
                "Invalid number of EIF sections: {}",
                header.num_sections
            ));
        }

        Ok(Sections {
            reader,
            header,
            index: 0,
        })
    }

    /// Returns the deserialized EIF header
    pub fn eif_header(&self) -> &EifHeader {
        &self.header
    }

    /// Copies the data of `section` to `writer`, returning the number of bytes copied
    pub fn copy_data<W: Write>(
        &mut self,
        section: &EifSection,
        writer: &mut W,
    ) -> Result<u64, String> {
        self.reader
            .seek(SeekFrom::Start(section.data_offset))
            .map_err(|e| format!("Failed to seek to EIF section data: {:?}", e))?;
        let size = section.header.section_size;
        let copied = io::copy(&mut (&mut self.reader).take(size), writer)
            .map_err(|e| format!("Error while copying EIF section data: {:?}", e))?;
        if copied != size {
            return Err(format!(
                "EIF section {} is truncated: expected {} bytes, found {}",
                section.index, size, copied
            ));
        }
        Ok(copied)
    }

    /// Reads the data of `section` into memory
    pub fn read_data(&mut self, section: &EifSection) -> Result<Vec<u8>, String> {
        let mut data = Vec::new();
        self.copy_data(section, &mut data)?;
        Ok(data)
    }

    fn read_section(&mut self, index: usize) -> Result<EifSection, String> {
        let offset = self.header.section_offsets[index];
        self.reader
            .seek(SeekFrom::Start(offset))
            .map_err(|e| format!("Failed to seek to EIF section {}: {:?}", index, e))?;
        let mut section_buf = vec![0u8; EifSectionHeader::size()];
        self.reader
            .read_exact(&mut section_buf)
            .map_err(|e| format!("Error while reading EIF section header {}: {:?}", index, e))?;
        let header = EifSectionHeader::from_be_bytes(&section_buf)
            .map_err(|e| format!("Error extracting EIF section header {}: {:?}", index, e))?;
        if header.section_type == EifSectionType::EifSectionInvalid {
            return Err(format!("Found invalid EIF section at index {}", index));
        }

        Ok(EifSection {
            index,
            header,
            data_offset: offset + EifSectionHeader::size() as u64,
        })
    }
}

impl<R: Read + Seek> Iterator for Sections<R> {
    type Item = Result<EifSection, String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.header.num_sections as usize {
            return None;
        }
        let index = self.index;
        self.index += 1;
        Some(self.read_section(index))
    }
}

/// Used for providing EIF info when requested by
/// 'describe-eif' or 'describe-enclaves' commands
pub struct EifReader {
    /// Deserialized EIF header
    pub header: EifHeader,
    /// Serialized signature section
    pub signature_section: Option<Vec<u8>>,
    /// Hash of the whole EifImage.
    pub image_hasher: EifHasher<Sha384>,
    /// Hash of the EifSections provided by Amazon
    /// Kernel + cmdline + First Ramdisk
    pub bootstrap_hasher: EifHasher<Sha384>,
    /// Hash of the remaining ramdisks.
    pub app_hasher: EifHasher<Sha384>,
    /// Hash the signing certificate
    pub cert_hasher: EifHasher<Sha384>,
    pub eif_crc: u32,
    pub sign_check: Option<bool>,
    /// Generated and custom EIF metadata
    pub metadata: Option<EifIdentityInfo>,
}

impl EifReader {
    /// Reads EIF and extracts sections to be written in the hashers based
    /// on section type. Also writes sections in the eif_crc, excluding the
    /// CRC from the header
    pub fn from_eif(eif_path: String) -> Result<Self, String> {
        let crc_gen = Crc::<u32>::new(&CRC_32_ISO_HDLC);
        let mut eif_crc = crc_gen.digest();
        let mut curr_seek = 0;
        let mut eif_file =
            File::open(eif_path).map_err(|e| format!("Failed to open the EIF file: {:?}", e))?;

        // Extract EIF header
        let mut header_buf = vec![0u8; EifHeader::size()];
        eif_file
            .read_exact(&mut header_buf)
            .map_err(|e| format!("Error while reading EIF header: {:?}", e))?;

        // Exclude last field of header which is CRC
        let len_without_crc = header_buf.len() - size_of::<u32>();
        eif_crc.update(&header_buf[..len_without_crc]);

        let header = EifHeader::from_be_bytes(&header_buf)
            .map_err(|e| format!("Error while parsing EIF header: {:?}", e))?;
        curr_seek += EifHeader::size();
        eif_file
            .seek(SeekFrom::Start(curr_seek as u64))
            .map_err(|e| format!("Failed to seek file from start: {:?}", e))?;

        let mut section_buf = vec![0u8; EifSectionHeader::size()];
        let mut image_hasher = EifHasher::new_without_cache(Sha384::new())
            .map_err(|e| format!("Could not create image_hasher: {:?}", e))?;
        let mut bootstrap_hasher = EifHasher::new_without_cache(Sha384::new())
            .map_err(|e| format!("Could not create bootstrap_hasher: {:?}", e))?;
        let mut app_hasher = EifHasher::new_without_cache(Sha384::new())
            .map_err(|e| format!("Could not create app_hasher: {:?}", e))?;
        let mut cert_hasher = EifHasher::new_without_cache(Sha384::new())
            .map_err(|e| format!("Could not create cert_hasher: {:?}", e))?;
        let mut ramdisk_idx = 0;
        let mut signature_section = None;
        let mut metadata = None;

        // Read all section headers and treat by type
        while eif_file
            .read_exact(&mut section_buf)
            .map_err(|e| format!("Error while reading EIF header: {:?}", e))
            .is_ok()
        {
            let section = EifSectionHeader::from_be_bytes(&section_buf)
                .map_err(|e| format!("Error extracting EIF section header: {:?}", e))?;
            eif_crc.update(&section_buf);

            let mut buf = vec![0u8; section.section_size as usize];
            curr_seek += EifSectionHeader::size();
            eif_file
                .seek(SeekFrom::Start(curr_seek as u64))
                .map_err(|e| format!("Failed to seek after EIF header: {:?}", e))?;
            eif_file
                .read_exact(&mut buf)
                .map_err(|e| format!("Error while reading kernel from EIF: {:?}", e))?;
            eif_crc.update(&buf);

            curr_seek += section.section_size as usize;
            eif_file
                .seek(SeekFrom::Start(curr_seek as u64))
                .map_err(|e| format!("Failed to seek after EIF section: {:?}", e))?;

            match section.section_type {
                EifSectionType::EifSectionKernel | EifSectionType::EifSectionCmdline => {
                    image_hasher.write_all(&buf).map_err(|e| {
                        format!("Failed to write EIF section to image_hasher: {:?}", e)
                    })?;
                    bootstrap_hasher.write_all(&buf).map_err(|e| {
                        format!("Failed to write EIF section to bootstrap_hasher: {:?}", e)
                    })?;
                }
                EifSectionType::EifSectionRamdisk => {
                    image_hasher.write_all(&buf).map_err(|e| {
                        format!("Failed to write ramdisk section to image_hasher: {:?}", e)
                    })?;
                    if ramdisk_idx == 0 {
                        bootstrap_hasher.write_all(&buf).map_err(|e| {
                            format!(
                                "Failed to write ramdisk section to bootstrap_hasher: {:?}",
                                e
                            )
                        })?;
                    } else {
                        app_hasher.write_all(&buf).map_err(|e| {
                            format!("Failed to write ramdisk section to app_hasher: {:?}", e)
                        })?;
                    }
                    ramdisk_idx += 1;
                }
                EifSectionType::EifSectionSignature => {
                    signature_section = Some(buf.clone());
                    // Deserialize PCR0 signature structure and write it to the hasher
                    let des_sign: Vec<PcrSignature> = from_slice(&buf[..])
                        .map_err(|e| format!("Error deserializing certificate: {:?}", e))?;

                    let cert = openssl::x509::X509::from_pem(&des_sign[0].signing_certificate)
                        .map_err(|e| format!("Error while digesting certificate: {:?}", e))?;
                    let cert_der = cert.to_der().map_err(|e| {
                        format!("Failed to deserialize signing certificate: {:?}", e)
                    })?;
                    cert_hasher.write_all(&cert_der).map_err(|e| {
                        format!("Failed to write signature section to cert_hasher: {:?}", e)
                    })?;
                }
                EifSectionType::EifSectionMetadata => {
                    metadata = serde_json::from_slice(&buf[..])
                        .map_err(|e| format!("Error deserializing metadata: {:?}", e))?;
                }
                EifSectionType::EifSectionInvalid => {
                    return Err("Found invalid EIF section".to_string());
                }
            }
        }

        Ok(EifReader {
            header,
            signature_section,
            image_hasher,
            bootstrap_hasher,
            app_hasher,
            cert_hasher,
            eif_crc: eif_crc.finalize(),
            sign_check: None,
            metadata,
        })
    }

    pub fn get_metadata(&self) -> Option<EifIdentityInfo> {
        self.metadata.clone()
    }

    pub fn get_measurements(&mut self) -> Result<BTreeMap<String, String>, String> {
        get_pcrs(
            &mut self.image_hasher,
            &mut self.bootstrap_hasher,
            &mut self.app_hasher,
            &mut self.cert_hasher,
            Sha384::new(),
            self.signature_section.is_some(),
        )
    }

    /// Returns deserialized header section
    pub fn get_header(&self) -> EifHeader {
        self.header
    }

    /// Compare header CRC to the one we computed
    pub fn check_crc(&self) -> bool {
        self.header.eif_crc32 == self.eif_crc
    }

    /// Extract signature section from EIF and parse the signing certificate
    pub fn get_certificate_info(
        &mut self,
        measurements: BTreeMap<String, String>,
    ) -> Result<SignCertificateInfo, String> {
        let signature_buf = match &self.signature_section {
            Some(section) => section,
            None => {
                return Err("Signature section missing from EIF.".to_string());
            }
        };
        // Deserialize PCR0 signature structure and write it to the hasher
        let des_sign: Vec<PcrSignature> = from_slice(&signature_buf[..])
            .map_err(|e| format!("Error deserializing certificate: {:?}", e))?;

        let cert = openssl::x509::X509::from_pem(&des_sign[0].signing_certificate)
            .map_err(|e| format!("Error while digesting certificate: {:?}", e))?;

        // Parse issuer into a BTreeMap
        let mut issuer_name = BTreeMap::new();
        for e in cert.issuer_name().entries() {
            issuer_name.insert(
                e.object().to_string(),
                format!("{:?}", e.data()).replace(&['\"'][..], ""),
            );
        }

        let algorithm = format!("{:#?}", cert.signature_algorithm().object());

        // Get measured PCR0 signature payload
        let pcr0 = match measurements.get("PCR0") {
            Some(pcr) => pcr,
            None => {
                return Err("Failed to get PCR0.".to_string());
            }
        };
        let pcr_info = PcrInfo::new(
            0,
            hex::decode(pcr0).map_err(|e| format!("Error while decoding PCR0: {:?}", e))?,
        );

        let measured_payload =
            to_vec(&pcr_info).map_err(|e| format!("Could not serialize PCR info: {:?}", e))?;

        // Extract public key from certificate and convert to PKey
        let public_key = &cert
            .public_key()
            .map_err(|e| format!("Failed to get public key: {:?}", e))?;
        let coses_key = PKey::public_key_from_pem(
            &public_key
                .public_key_to_pem()
                .map_err(|e| format!("Failed to serialize public key: {:?}", e))?[..],
        )
        .map_err(|e| format!("Failed to decode key nit elliptic key structure: {:?}", e))?;

        // Deserialize COSE signature and extract the payload using the public key
        let pcr_sign = CoseSign1::from_bytes(&des_sign[0].signature[..])
            .map_err(|e| format!("Failed to deserialize signature: {:?}", e))?;
        let coses_payload = pcr_sign
            .get_payload::<Openssl>(Some(coses_key.as_ref()))
            .map_err(|e| format!("Failed to get signature payload: {:?}", e))?;

        self.sign_check = Some(measured_payload == coses_payload);

        Ok(SignCertificateInfo {
            issuer_name,
            algorithm,
            not_before: format!("{:#?}", cert.not_before()),
            not_after: format!("{:#?}", cert.not_after()),
            // Change format from [\  XX, \  X, ..] to XX:XX:XX...
            signature: format!("{:02X?}", cert.signature().as_slice().to_vec())
                .replace(&vec!['[', ']'][..], "")
                .replace(", ", ":"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defs::{EifBuildInfo, EifIdentityInfo};
    use crate::utils::EifBuilder;
    use std::io::Cursor;
    use std::path::Path;
    use tempfile::TempDir;

    fn build_test_eif(dir: &Path) -> Vec<u8> {
        let kernel = dir.join("kernel");
        let ramdisk0 = dir.join("ramdisk0");
        let ramdisk1 = dir.join("ramdisk1");
        std::fs::write(&kernel, b"kernel data").unwrap();
        std::fs::write(&ramdisk0, b"first ramdisk").unwrap();
        std::fs::write(&ramdisk1, vec![0x5a; 100_000]).unwrap();

        let eif_info = EifIdentityInfo {
            img_name: "test".to_string(),
            img_version: "1.0".to_string(),
            build_info: EifBuildInfo {
                build_time: "2026-01-01T00:00:00+00:00".to_string(),
                build_tool: "test".to_string(),
                build_tool_version: "0.0.0".to_string(),
                img_os: "OS".to_string(),
                img_kernel: "kernel".to_string(),
            },
            docker_info: serde_json::Value::Null,
            custom_info: serde_json::Value::Null,
        };
        let mut builder = EifBuilder::new(
            &kernel,
            "console=ttyS0".to_string(),
            None,
            Sha384::new(),
            0,
            eif_info,
        );
        builder.add_ramdisk(&ramdisk0);
        builder.add_ramdisk(&ramdisk1);

        let eif_path = dir.join("test.eif");
        let mut eif_file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&eif_path)
            .unwrap();
        builder.write_to(&mut eif_file);
        std::fs::read(&eif_path).unwrap()
    }

    #[test]
    fn test_sections_iterates_in_header_order() {
        let dir = TempDir::new().unwrap();
        let eif = build_test_eif(dir.path());

        let mut sections = Sections::new(Cursor::new(eif)).unwrap();
        let num_sections = sections.eif_header().num_sections as usize;
        let mut found = Vec::new();
        while let Some(section) = sections.next() {
            let section = section.unwrap();
            let data = sections.read_data(&section).unwrap();
            found.push((section.header.section_type, data));
        }

        assert_eq!(found.len(), num_sections);
        let types: Vec<_> = found.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            types,
            vec![
                EifSectionType::EifSectionKernel,
                EifSectionType::EifSectionCmdline,
                EifSectionType::EifSectionMetadata,
                EifSectionType::EifSectionRamdisk,
                EifSectionType::EifSectionRamdisk,
            ]
        );
        assert_eq!(found[0].1, b"kernel data");
        assert_eq!(found[1].1, b"console=ttyS0");
        assert_eq!(found[3].1, b"first ramdisk");
        assert_eq!(found[4].1, vec![0x5a; 100_000]);
    }

    #[test]
    fn test_sections_rejects_bad_magic() {
        let dir = TempDir::new().unwrap();
        let mut eif = build_test_eif(dir.path());
        eif[0] = b'x';

        assert!(Sections::new(Cursor::new(eif)).is_err());
    }

    #[test]
    fn test_sections_rejects_too_many_sections() {
        let dir = TempDir::new().unwrap();
        let mut eif = build_test_eif(dir.path());
        let mut header = EifHeader::from_be_bytes(&eif[..EifHeader::size()]).unwrap();
        header.num_sections = MAX_NUM_SECTIONS as u16 + 1;
        eif[..EifHeader::size()].copy_from_slice(&header.to_be_bytes());

        assert!(Sections::new(Cursor::new(eif)).is_err());
    }

    #[test]
    fn test_sections_reports_truncated_data() {
        let dir = TempDir::new().unwrap();
        let mut eif = build_test_eif(dir.path());
        eif.truncate(eif.len() - 1);

        let mut sections = Sections::new(Cursor::new(eif)).unwrap();
        let last = sections.by_ref().last().unwrap().unwrap();
        assert!(sections.read_data(&last).is_err());
    }
}
