// Copyright 2019-2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(warnings)]
pub(crate) mod cbor;
pub mod eif_reader;
pub mod eif_signer;
pub mod identity;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;

use crate::defs::eif_hasher::EifHasher;
use crate::defs::{
    pcr0_flag_fold_bytes, EifHeader, EifIdentityInfo, EifSectionHeader, EifSectionType,
    PcrSignature, EIF_HDR_FLAG_PCIE, EIF_MAGIC, MAX_NUM_SECTIONS,
};
use crate::utils::cbor::from_slice;
use aws_nitro_enclaves_cose::{crypto::Openssl, CoseSign1};
use crc::{Crc, CRC_32_ISO_HDLC};
use openssl::asn1::Asn1Time;
use serde::{Deserialize, Serialize};
use sha2::digest::FixedOutputReset;
use sha2::Digest;
use std::cmp::Ordering;
use std::collections::BTreeMap;

pub use eif_signer::{EifSigner, SignKeyData};

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
use std::io::{Error as IoError, Read, Result as IoResult, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::path::Path;

const DEFAULT_SECTIONS_COUNT: u16 = 3;

/// Utility function to calculate PCRs, used at build and describe.
pub fn get_pcrs<T: Digest + FixedOutputReset + Debug + Write + Clone>(
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

/// Extent an EIF header declares: the larger of the file header size and
/// the furthest declared section end (each section end = section_offset +
/// section header size + section_size; offsets are file-absolute).
///
/// This is the range PCR6 covers, so the write path and the read path must
/// derive it the same way, and both must refuse an extent of 4 GiB or more.
fn declared_eif_extent(header: &EifHeader) -> Result<u64, String> {
    if header.num_sections as usize > MAX_NUM_SECTIONS {
        return Err(format!(
            "EIF num_sections={} exceeds MAX_NUM_SECTIONS={}",
            header.num_sections, MAX_NUM_SECTIONS
        ));
    }
    let mut extent = EifHeader::size() as u64;
    for i in 0..header.num_sections as usize {
        let section_end = header.section_offsets[i]
            .checked_add(EifSectionHeader::size() as u64)
            .and_then(|v| v.checked_add(header.section_sizes[i]))
            .ok_or_else(|| {
                format!(
                    "EIF section {} offset=0x{:x} size=0x{:x} overflows",
                    i, header.section_offsets[i], header.section_sizes[i]
                )
            })?;
        if section_end > extent {
            extent = section_end;
        }
    }
    // A PCIE EIF must be smaller than 4 GiB, so one of 4 GiB or more is
    // neither written nor measured.
    if extent > u32::MAX as u64 {
        return Err(format!("EIF extent 0x{extent:x} is 4 GiB or more"));
    }
    Ok(extent)
}

/// Running PCR6 whole-file measurement of an EIF.
///
/// PCR6 is the hash of the EIF from offset 0 up to the extent its header
/// declares: the larger of the file header size and the furthest declared
/// section end (each section end = section_offset + section header size +
/// section_size; offsets are file-absolute).  Bytes past the extent are not
/// measured.  Unlike PCR0/1/2, PCR6 also covers the section headers and the
/// metadata section.
///
/// Fed with the file bytes in order from offset 0, it hashes those below
/// the extent.  The result includes the TPM extend fold (the hash of a
/// zeroed PCR concatenated with the file digest), matching the other
/// measurements from [`get_pcrs`] and the PCR6 in the attestation document.
struct Pcr6Hasher<T: Digest + FixedOutputReset + Debug + Write + Clone> {
    hasher: EifHasher<T>,
    measured: u64,
    extent: u64,
}

impl<T: Digest + FixedOutputReset + Debug + Write + Clone> Pcr6Hasher<T> {
    fn new(header: &EifHeader, hasher: T) -> Result<Self, String> {
        Ok(Pcr6Hasher {
            hasher: EifHasher::new_without_cache(hasher)
                .map_err(|e| format!("PCR6: could not create hasher: {:?}", e))?,
            measured: 0,
            extent: declared_eif_extent(header).map_err(|e| format!("PCR6: {e}"))?,
        })
    }

    /// Bytes of the extent not measured yet.
    fn remaining(&self) -> u64 {
        self.extent - self.measured
    }

    /// Measure the next bytes of the file, up to the end of the extent.
    fn update(&mut self, bytes: &[u8]) -> Result<(), String> {
        let n = std::cmp::min(bytes.len() as u64, self.remaining()) as usize;
        self.hasher
            .write_all(&bytes[..n])
            .map_err(|e| format!("PCR6: could not hash EIF bytes: {:?}", e))?;
        self.measured += n as u64;
        Ok(())
    }

    fn finalize(mut self) -> Result<String, String> {
        if self.measured != self.extent {
            return Err(format!(
                "PCR6: measured 0x{:x} bytes, but the EIF header declares an extent of 0x{:x}",
                self.measured, self.extent
            ));
        }
        Ok(hex::encode(
            self.hasher
                .tpm_extend_finalize_reset()
                .map_err(|e| format!("PCR6: could not finalize measurement: {:?}", e))?,
        ))
    }
}

/// Write adapter that streams every written byte into a PCR6 hasher.
///
/// The EIF writer emits the file strictly front to back (every section
/// offset is the previous section's end), so the write stream IS the file
/// content [0, extent).  Hashing the stream as it passes removes any need
/// to read the finished file back: `write_to` works on a write-only
/// handle and never reads the file back.  Seeks are validated to
/// be contiguous; a gap or rewind would silently desynchronize the hash
/// from the file, so it fails the write instead.
///
/// The stream length is held to the extent the EIF header declares.  Every
/// section size is read from the input file's metadata again for each
/// offset, header field and payload, so an input that changes while the EIF
/// is written would otherwise yield a file whose sections run past or stop
/// short of the extent its header declares.
struct Pcr6TeeWriter<'a, W: Write + Seek, T: Digest + FixedOutputReset + Debug + Write + Clone> {
    inner: &'a mut W,
    pcr6: Pcr6Hasher<T>,
}

impl<W: Write + Seek, T: Digest + FixedOutputReset + Debug + Write + Clone> Write
    for Pcr6TeeWriter<'_, W, T>
{
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        // Refuse the bytes rather than emit a file the declared extent does
        // not cover.
        if buf.len() as u64 > self.pcr6.remaining() {
            return Err(IoError::other(format!(
                "PCR6 tee: write of {} bytes at offset {} exceeds the declared EIF extent {}",
                buf.len(),
                self.pcr6.measured,
                self.pcr6.extent
            )));
        }
        let n = self.inner.write(buf)?;
        self.pcr6.update(&buf[..n]).map_err(IoError::other)?;
        Ok(n)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.flush()
    }
}

impl<W: Write + Seek, T: Digest + FixedOutputReset + Debug + Write + Clone> Seek
    for Pcr6TeeWriter<'_, W, T>
{
    fn seek(&mut self, pos: SeekFrom) -> IoResult<u64> {
        // Only contiguous forward positioning keeps the hash equal to the
        // file content; the EIF writer never needs anything else.
        match pos {
            SeekFrom::Start(target) if target == self.pcr6.measured => self.inner.seek(pos),
            _ => Err(IoError::other(format!(
                "PCR6 tee: non-contiguous seek to {:?} at offset {}",
                pos, self.pcr6.measured
            ))),
        }
    }
}

pub struct EifBuilder<T: Digest + FixedOutputReset + Debug + Write + Clone> {
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

impl<T: Digest + FixedOutputReset + Debug + Write + Clone> EifBuilder<T> {
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

    pub fn write_header<W: Write + Seek>(&mut self, file: &mut W) {
        let eif_header = self.header();
        file.seek(SeekFrom::Start(self.eif_header_offset())).expect(
            "Could not seek while writing eif \
             header",
        );
        let eif_buffer = eif_header.to_be_bytes();
        file.write_all(&eif_buffer[..])
            .expect("Failed to write eif header");
    }

    pub fn write_kernel<W: Write + Seek>(&mut self, eif_file: &mut W) {
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

    pub fn write_cmdline<W: Write + Seek>(&mut self, eif_file: &mut W) {
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

    pub fn write_metadata<W: Write + Seek>(&mut self, eif_file: &mut W) {
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

    pub fn write_ramdisks<W: Write + Seek>(&mut self, eif_file: &mut W) {
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

    pub fn write_signature<W: Write + Seek>(&mut self, eif_file: &mut W) {
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

    /// Write the EIF to `output_file` and return its measurements.  For
    /// PCIE-flagged images they include PCR6, computed over the written
    /// byte stream itself, so the handle only needs write permission.
    pub fn write_to<W: Write + Seek>(&mut self, output_file: &mut W) -> BTreeMap<String, String> {
        self.measure();
        let mut measurements = get_pcrs(
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
        // PCR6 covers the complete file as written -- including the header
        // CRC and any signature section -- so it is measured from the byte
        // stream while it is written, never pre-computed from the input
        // parts.  It is deliberately not an input to the signature above:
        // the signature covers PCR0, and PCR6 in turn covers the signature
        // section.
        //
        // Only PCIE-flagged images have a PCR6.  Other images are written
        // without the 4 GiB check.
        //
        // header() reads the input sizes again on every call, so compute it
        // once: the file gets the header the PCR6 extent comes from.
        let header = self.header();
        if self.eif_hdr_flags & EIF_HDR_FLAG_PCIE == 0 {
            self.write_sections(output_file, &header);
            return measurements;
        }
        // Bind the measurement to the extent the header declares, before the
        // first byte goes out: PCR6 must cover [0, extent), the range
        // the reader measures.  Checking the extent here also reports an EIF
        // of 4 GiB or more instead of writing the whole file and failing
        // afterwards.
        let pcr6 = Pcr6Hasher::new(&header, self.hasher_template.clone())
            .expect("Failed to create PCR6 hasher");
        let mut tee = Pcr6TeeWriter {
            inner: output_file,
            pcr6,
        };
        self.write_sections(&mut tee, &header);
        let pcr6 = tee.pcr6.finalize().expect("Failed to get PCR6 measurement");
        measurements.insert("PCR6".to_string(), pcr6);
        measurements
    }

    fn write_sections<W: Write + Seek>(&mut self, eif_file: &mut W, header: &EifHeader) {
        eif_file
            .seek(SeekFrom::Start(self.eif_header_offset()))
            .expect("Could not seek while writing eif header");
        eif_file
            .write_all(&header.to_be_bytes())
            .expect("Failed to write eif header");
        self.write_kernel(eif_file);
        self.write_cmdline(eif_file);
        self.write_metadata(eif_file);
        self.write_ramdisks(eif_file);
        self.write_signature(eif_file);
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

        // The fold goes into PCR0 (image_hasher) only, after every section,
        // so it must come last. The certificate above feeds PCR8, not PCR0.
        if let Some(fold) = pcr0_flag_fold_bytes(self.eif_hdr_flags) {
            self.image_hasher.write_all(&fold).unwrap();
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
    use crate::utils::eif_signer::{SignKey, SignKeyData};
    use std::{io::Write, path::Path};
    use tempfile::{NamedTempFile, TempPath};

    const TEST_CERT_CONTENT: &[u8] = "test cert content".as_bytes();
    const TEST_PKEY_CONTENT: &[u8] = "test key content".as_bytes();

    fn generate_certificate_file() -> Result<TempPath, std::io::Error> {
        let cert_file = NamedTempFile::new()?;
        cert_file.as_file().write_all(TEST_CERT_CONTENT)?;
        Ok(cert_file.into_temp_path())
    }

    fn generate_pkey_file() -> Result<TempPath, std::io::Error> {
        let key_file = NamedTempFile::new()?;
        key_file.as_file().write_all(TEST_PKEY_CONTENT)?;
        Ok(key_file.into_temp_path())
    }

    #[test]
    fn test_local_sign_key_data_from_invalid_local_key_info() -> Result<(), std::io::Error> {
        let cert_file_path = generate_certificate_file()?;

        let key_data = SignKeyData::new("/incorrect/pk/path", &cert_file_path);

        assert!(key_data.is_err());
        Ok(())
    }

    #[test]
    fn test_local_sign_key_data_from_invalid_cert_key_info() -> Result<(), std::io::Error> {
        let key_file_path = generate_pkey_file()?;
        let key_path_str = <TempPath as AsRef<Path>>::as_ref(&key_file_path)
            .to_str()
            .expect("Key file must be correct");

        let key_data = SignKeyData::new(key_path_str, Path::new("/incorrect/cert/path"));

        assert!(key_data.is_err());
        Ok(())
    }

    #[test]
    fn test_local_sign_key_data_from_valid_key_info() -> Result<(), std::io::Error> {
        let key_file_path = generate_pkey_file()?;
        let key_path_str = <TempPath as AsRef<Path>>::as_ref(&key_file_path)
            .to_str()
            .expect("Key file must be correct");
        let cert_file_path = generate_certificate_file()?;

        let key_data = SignKeyData::new(key_path_str, &cert_file_path).unwrap();

        assert_eq!(key_data.cert, TEST_CERT_CONTENT);
        assert!(matches!(key_data.key, SignKey::LocalPrivateKey(key) if key == TEST_PKEY_CONTENT));

        Ok(())
    }

    #[cfg(not(feature = "kms"))]
    #[test]
    fn test_kms_sign_key_data_without_kms_feature() -> Result<(), std::io::Error> {
        let cert_file_path = generate_certificate_file()?;
        let key_arn = "arn:aws:kms:us-east-1:123456789012:key/test-key-id";

        let err = SignKeyData::new(key_arn, &cert_file_path)
            .err()
            .expect("KMS key must be rejected without the kms feature");

        assert!(err.contains("`kms` feature"));
        Ok(())
    }

    #[cfg(not(feature = "pkcs11"))]
    #[test]
    fn test_pkcs11_sign_key_data_without_pkcs11_feature() -> Result<(), std::io::Error> {
        let cert_file_path = generate_certificate_file()?;
        let key_uri = "pkcs11:id=%01?module-path=/usr/lib/libykcs11.so";

        let err = SignKeyData::new(key_uri, &cert_file_path)
            .err()
            .expect("PKCS#11 key must be rejected without the pkcs11 feature");

        assert!(err.contains("`pkcs11` feature"));
        Ok(())
    }

    #[cfg(feature = "kms")]
    mod kms {
        use super::*;
        use std::env;

        #[test]
        fn test_kms_sign_key_data_from_invalid_cert_key_info() -> Result<(), std::io::Error> {
            let key_arn =
                env::var("AWS_KMS_TEST_KEY_ARN").expect("Please set AWS_KMS_TEST_KEY_ARN");

            let key_data = SignKeyData::new(&key_arn, Path::new("/incorrect/cert/path"));

            assert!(key_data.is_err());
            Ok(())
        }

        #[test]
        fn test_kms_sign_key_data_from_valid_key_arn() -> Result<(), std::io::Error> {
            let cert_file_path = generate_certificate_file()?;
            let key_arn =
                env::var("AWS_KMS_TEST_KEY_ARN").expect("Please set AWS_KMS_TEST_KEY_ARN");

            let key_data = SignKeyData::new(&key_arn, &cert_file_path).unwrap();

            assert_eq!(key_data.cert, TEST_CERT_CONTENT);
            assert!(matches!(key_data.key, SignKey::KmsKey(_)));

            Ok(())
        }
    }

    mod pcr6 {
        use crate::defs::{EifHeader, EifSectionHeader, EifSectionType, EIF_MAGIC};
        use crate::utils::eif_reader::EifReader;
        use sha2::{Digest, Sha384};
        use std::io::{Seek, SeekFrom, Write};
        use tempfile::NamedTempFile;

        /// Independent reference: the TPM extend fold of a plain hash over
        /// `bytes`.
        fn reference_pcr6<D: Digest>(bytes: &[u8]) -> String {
            let mut fold = D::new();
            Digest::update(&mut fold, vec![0u8; <D as Digest>::output_size()]);
            Digest::update(&mut fold, D::digest(bytes));
            hex::encode(fold.finalize())
        }

        /// PCR6 as EifReader describes the file at `path`.
        fn described_pcr6(path: &std::path::Path) -> Result<Option<String>, String> {
            EifReader::from_eif(path.to_str().unwrap().to_string())?
                .get_measurements()
                .map(|measurements| measurements.get("PCR6").cloned())
        }

        /// The error EifReader::from_eif returns for the file at `path`.
        fn from_eif_error(path: &std::path::Path) -> String {
            match EifReader::from_eif(path.to_str().unwrap().to_string()) {
                Ok(_) => panic!("from_eif accepted {:?}", path),
                Err(e) => e,
            }
        }

        /// Header of a minimal EIF: one kernel section of `payload_len`
        /// bytes right after the file header.
        fn minimal_header(payload_len: u64, flags: u16) -> EifHeader {
            let mut section_offsets = [0u64; crate::defs::MAX_NUM_SECTIONS];
            let mut section_sizes = [0u64; crate::defs::MAX_NUM_SECTIONS];
            section_offsets[0] = EifHeader::size() as u64;
            section_sizes[0] = payload_len;
            EifHeader {
                magic: EIF_MAGIC,
                version: crate::defs::CURRENT_VERSION,
                flags,
                default_mem: 0,
                default_cpus: 0,
                reserved: 0,
                num_sections: 1,
                section_offsets,
                section_sizes,
                unused: 0,
                eif_crc32: 0,
            }
        }

        /// Build a minimal syntactically valid EIF: header + one kernel
        /// section, returning (file, full length of the declared extent).
        fn write_minimal_eif(payload: &[u8], flags: u16) -> (NamedTempFile, usize) {
            let section = EifSectionHeader {
                section_type: EifSectionType::EifSectionKernel,
                flags: 0,
                section_size: payload.len() as u64,
            };
            let header = minimal_header(payload.len() as u64, flags);
            let mut file = NamedTempFile::new().unwrap();
            file.as_file_mut().write_all(&header.to_be_bytes()).unwrap();
            file.as_file_mut()
                .write_all(&section.to_be_bytes())
                .unwrap();
            file.as_file_mut().write_all(payload).unwrap();
            let len = EifHeader::size() + EifSectionHeader::size() + payload.len();
            (file, len)
        }

        /// Bytes past the furthest declared section end are outside the
        /// measurement.  PCR6 stops at the extent even where the reader
        /// reads on, here through a section the header does not list,
        /// followed by a tail shorter than a section header.
        #[test]
        fn ignores_bytes_past_the_extent() {
            let payload = vec![0x5au8; 4096];
            let (file, _) = write_minimal_eif(&payload, crate::defs::EIF_HDR_FLAG_PCIE);
            let pcr6_clean = described_pcr6(file.path()).unwrap().unwrap();

            let extra = vec![0x77u8; 100];
            let section = EifSectionHeader {
                section_type: EifSectionType::EifSectionKernel,
                flags: 0,
                section_size: extra.len() as u64,
            };
            let mut f = file.reopen().unwrap();
            f.seek(SeekFrom::End(0)).unwrap();
            f.write_all(&section.to_be_bytes()).unwrap();
            f.write_all(&extra).unwrap();
            f.write_all(&[0xffu8; 5]).unwrap();

            assert_eq!(described_pcr6(file.path()).unwrap().unwrap(), pcr6_clean);
        }

        /// The reader measures only the bytes it reads.  When the header
        /// declares an extent past them, from_eif rejects the file rather
        /// than report a PCR6 over a range other than the declared extent.
        #[test]
        fn rejects_an_extent_the_reader_did_not_read() {
            let payload = vec![0x44u8; 4096];
            let (file, _) = write_minimal_eif(&payload, crate::defs::EIF_HDR_FLAG_PCIE);
            let header = minimal_header(payload.len() as u64 + 4, crate::defs::EIF_HDR_FLAG_PCIE);
            let mut f = file.reopen().unwrap();
            f.write_all(&header.to_be_bytes()).unwrap();
            f.seek(SeekFrom::End(0)).unwrap();
            f.write_all(&[0u8; 4]).unwrap();

            let err = from_eif_error(file.path());
            assert!(err.contains("declares an extent"), "{}", err);
        }

        /// A PCIE image whose declared extent is 4 GiB or more is rejected
        /// before its sections are read.
        #[test]
        fn rejects_an_extent_of_4_gib_or_more() {
            let payload = vec![0x55u8; 4096];
            let (file, _) = write_minimal_eif(&payload, crate::defs::EIF_HDR_FLAG_PCIE);
            let header = minimal_header(u32::MAX as u64, crate::defs::EIF_HDR_FLAG_PCIE);
            file.reopen()
                .unwrap()
                .write_all(&header.to_be_bytes())
                .unwrap();

            let err = from_eif_error(file.path());
            assert!(err.contains("4 GiB or more"), "{}", err);
        }

        /// Kernel and two ramdisk inputs for a multi-section test image.
        /// The caller owns them, so a test can mutate one while write_to
        /// runs.
        fn test_inputs() -> (NamedTempFile, NamedTempFile, NamedTempFile) {
            let mut kernel = NamedTempFile::new().unwrap();
            kernel.as_file_mut().write_all(&[0x4bu8; 16384]).unwrap();
            let mut rd1 = NamedTempFile::new().unwrap();
            rd1.as_file_mut().write_all(&[0x21u8; 8192]).unwrap();
            let mut rd2 = NamedTempFile::new().unwrap();
            rd2.as_file_mut().write_all(&[0x22u8; 5000]).unwrap();
            (kernel, rd1, rd2)
        }

        /// Builder over the given inputs: kernel, cmdline, metadata and two
        /// ramdisks make a five-section image.
        fn builder_for<
            H: Digest + sha2::digest::FixedOutputReset + std::fmt::Debug + Write + Clone,
        >(
            kernel: &NamedTempFile,
            ramdisks: &[&NamedTempFile],
            flags: u16,
            sign_info: Option<crate::utils::SignKeyData>,
            hasher: H,
        ) -> crate::utils::EifBuilder<H> {
            use crate::defs::{EifBuildInfo, EifIdentityInfo};
            use crate::utils::EifBuilder;

            let eif_info = EifIdentityInfo {
                img_name: "pcr6-test".to_string(),
                img_version: "1.0".to_string(),
                build_info: EifBuildInfo {
                    build_time: "2026-09-04T00:00:00Z".to_string(),
                    build_tool: "pcr6-test".to_string(),
                    build_tool_version: "1.0".to_string(),
                    img_os: "Linux".to_string(),
                    img_kernel: "6.18".to_string(),
                },
                docker_info: serde_json::json!({}),
                custom_info: serde_json::json!({}),
            };
            let mut builder = EifBuilder::new(
                kernel.path(),
                "console=ttyS0 pcr6-test".to_string(),
                sign_info,
                hasher,
                flags,
                eif_info,
            );
            for ramdisk in ramdisks {
                builder.add_ramdisk(ramdisk.path());
            }
            builder
        }

        /// Build a real multi-section EIF with EifBuilder and return the
        /// output file with the measurements write_to returned.
        fn build_eif(flags: u16) -> (NamedTempFile, std::collections::BTreeMap<String, String>) {
            let (kernel, rd1, rd2) = test_inputs();
            let mut builder = builder_for(&kernel, &[&rd1, &rd2], flags, None, Sha384::new());

            let out = NamedTempFile::new().unwrap();
            let mut out_file = out.reopen().unwrap();
            let measurements = builder.write_to(&mut out_file);
            (out, measurements)
        }

        /// A local SECP384R1 key with a self-signed certificate.
        fn sign_key() -> crate::utils::SignKeyData {
            use crate::utils::eif_signer::{SignKey, SignKeyData};
            use openssl::asn1::Asn1Time;
            use openssl::ec::{EcGroup, EcKey};
            use openssl::hash::MessageDigest;
            use openssl::nid::Nid;
            use openssl::pkey::PKey;
            use openssl::x509::{X509NameBuilder, X509};

            let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
            let pkey = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
            let mut name = X509NameBuilder::new().unwrap();
            name.append_entry_by_text("CN", "pcr6-test").unwrap();
            let name = name.build();
            let mut cert = X509::builder().unwrap();
            cert.set_version(2).unwrap();
            cert.set_subject_name(&name).unwrap();
            cert.set_issuer_name(&name).unwrap();
            cert.set_pubkey(&pkey).unwrap();
            cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
                .unwrap();
            cert.sign(&pkey, MessageDigest::sha384()).unwrap();
            SignKeyData {
                cert: cert.build().to_pem().unwrap(),
                key: SignKey::LocalPrivateKey(pkey.private_key_to_pem_pkcs8().unwrap()),
            }
        }

        /// A signed multi-section PCIE image: the signature section passes
        /// through the tee after the signature over PCR0 is made, so the
        /// built PCR6 still equals an independent hash of the file.  Describe
        /// agrees with the build on every PCR, even after the file is gone.
        #[test]
        fn signed_flagged_image_describe_matches_builder() {
            let (kernel, rd1, rd2) = test_inputs();
            let flags = crate::defs::EIF_HDR_FLAG_PCIE | crate::defs::EIF_HDR_FLAG_PCIE_VIRTIO;
            let mut builder = builder_for(
                &kernel,
                &[&rd1, &rd2],
                flags,
                Some(sign_key()),
                Sha384::new(),
            );
            let out = NamedTempFile::new().unwrap();
            let measurements = builder.write_to(&mut out.reopen().unwrap());
            assert!(measurements.contains_key("PCR8"));

            let bytes = std::fs::read(out.path()).unwrap();
            assert_eq!(reference_pcr6::<Sha384>(&bytes), measurements["PCR6"]);
            let header = EifHeader::from_be_bytes(&bytes[..EifHeader::size()]).unwrap();
            assert_eq!(header.num_sections, 6);

            let path = out.path().to_str().unwrap().to_string();
            let mut reader = EifReader::from_eif(path).unwrap();
            out.close().unwrap();
            let described = reader.get_measurements().unwrap();
            for pcr in ["PCR0", "PCR1", "PCR2", "PCR6", "PCR8"] {
                assert_eq!(described.get(pcr).unwrap().len(), 96);
                assert_eq!(described.get(pcr), measurements.get(pcr), "{pcr}");
            }
        }

        /// The builder measures PCR6 with its own hasher, like PCR0/1/2.
        #[test]
        fn flagged_image_pcr6_uses_the_builder_hasher() {
            use sha2::Sha256;

            let (kernel, rd1, rd2) = test_inputs();
            let mut builder = builder_for(
                &kernel,
                &[&rd1, &rd2],
                crate::defs::EIF_HDR_FLAG_PCIE,
                None,
                Sha256::new(),
            );
            let out = NamedTempFile::new().unwrap();
            let measurements = builder.write_to(&mut out.reopen().unwrap());

            let bytes = std::fs::read(out.path()).unwrap();
            assert_eq!(measurements["PCR6"], reference_pcr6::<Sha256>(&bytes));
            assert_eq!(measurements["PCR0"].len(), 64);
        }

        /// An image without the PCIE flag gets no PCR6 from either path.
        #[test]
        fn unflagged_image_skips_pcr6() {
            let (out, measurements) = build_eif(0);
            assert!(!measurements.contains_key("PCR6"));
            let pcr0 = measurements.get("PCR0").unwrap().clone();
            assert_eq!(pcr0.len(), 96);

            let path = out.path().to_str().unwrap().to_string();
            let mut reader = EifReader::from_eif(path).unwrap();
            out.close().unwrap();
            let described = reader.get_measurements().unwrap();
            assert!(!described.contains_key("PCR6"));
            assert_eq!(described.get("PCR0").unwrap(), &pcr0);
        }

        /// sign_image signs a flagged image that was built unsigned: the
        /// file gets a valid CRC and a signature over its PCR0, and describe
        /// reports a PCR6 over the whole signed file.
        #[test]
        fn sign_image_signs_a_flagged_image() {
            use crate::utils::{EifSigner, PcrSignatureChecker};

            let (out, built) = build_eif(crate::defs::EIF_HDR_FLAG_PCIE);
            let path = out.path().to_str().unwrap();
            EifSigner::new(Some(sign_key()))
                .unwrap()
                .sign_image(path)
                .unwrap();

            let mut reader = EifReader::from_eif(path.to_string()).unwrap();
            assert_eq!(reader.eif_crc, reader.header.eif_crc32);
            let described = reader.get_measurements().unwrap();
            assert_eq!(described["PCR0"], built["PCR0"]);
            assert_eq!(described["PCR8"].len(), 96);
            reader.get_certificate_info(described.clone()).unwrap();
            assert_eq!(reader.sign_check, Some(true));

            let bytes = std::fs::read(path).unwrap();
            assert_eq!(described["PCR6"], reference_pcr6::<Sha384>(&bytes));
            assert_ne!(described["PCR6"], built["PCR6"]);
            PcrSignatureChecker::from_eif(path)
                .unwrap()
                .verify()
                .unwrap();
        }

        /// Writer that changes one of the builder's input files on the first
        /// write, which is the file header: every later size, offset and
        /// payload comes from a fresh read of that input.
        struct MutateOnFirstWrite<'a> {
            inner: &'a mut std::fs::File,
            target: std::path::PathBuf,
            /// `Some(len)` truncates the input, `None` appends to it.
            new_len: Option<u64>,
            fired: bool,
        }

        impl MutateOnFirstWrite<'_> {
            fn mutate(&self) -> std::io::Result<()> {
                match self.new_len {
                    Some(len) => std::fs::OpenOptions::new()
                        .write(true)
                        .open(&self.target)?
                        .set_len(len),
                    None => std::fs::OpenOptions::new()
                        .append(true)
                        .open(&self.target)?
                        .write_all(&[0x99u8; 100]),
                }
            }
        }

        impl Write for MutateOnFirstWrite<'_> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if !self.fired {
                    self.fired = true;
                    self.mutate()?;
                }
                self.inner.write(buf)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.inner.flush()
            }
        }

        impl Seek for MutateOnFirstWrite<'_> {
            fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
                self.inner.seek(pos)
            }
        }

        fn build_with_mutating_input(new_len: Option<u64>) {
            let (kernel, rd1, rd2) = test_inputs();
            let mut builder = builder_for(
                &kernel,
                &[&rd1, &rd2],
                crate::defs::EIF_HDR_FLAG_PCIE,
                None,
                Sha384::new(),
            );
            let out = NamedTempFile::new().unwrap();
            let mut out_file = out.reopen().unwrap();
            let mut writer = MutateOnFirstWrite {
                inner: &mut out_file,
                target: rd2.path().to_path_buf(),
                new_len,
                fired: false,
            };
            builder.write_to(&mut writer);
        }

        /// An input that grows after the header is written makes the written
        /// stream longer than the extent the header declares, so its
        /// sections would run past that extent.  The build must fail instead.
        #[test]
        #[should_panic(expected = "exceeds the declared EIF extent")]
        fn input_growing_mid_write_fails_the_build() {
            build_with_mutating_input(None);
        }

        /// The same for an input that shrinks: the stream then stops short of
        /// the declared extent, which PCR6 still covers.
        #[test]
        #[should_panic(expected = "declares an extent")]
        fn input_shrinking_mid_write_fails_the_build() {
            build_with_mutating_input(Some(4900));
        }
    }
}
