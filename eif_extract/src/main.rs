// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]
/// Simple utility tool for extracting the sections of an Eif file
///  cargo run -p eif_extract -- --help  should be self explanatory.
/// Example of usage:
/// cargo run -p eif_extract -- --eif image.eif --output-dir image/
///
/// The extracted kernel, cmdline, ramdisks and metadata can be passed back
/// to eif_build to assemble an image with the same measurements. The
/// matching eif_build command line is printed after extraction.
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use aws_nitro_enclaves_image_format::defs::{EifIdentityInfo, EifSectionType, EIF_HDR_ARCH_ARM64};
use aws_nitro_enclaves_image_format::utils::eif_reader::{parse_signature_section, Sections};
use clap::{Arg, Command};

/// Paths and information gathered while extracting an EIF
pub struct ExtractedEif {
    pub arch: &'static str,
    pub kernel: Option<PathBuf>,
    pub cmdline: Option<String>,
    pub ramdisks: Vec<PathBuf>,
    pub metadata: Option<EifIdentityInfo>,
    pub custom_metadata: Option<PathBuf>,
    pub signing_certificate: Option<PathBuf>,
    pub warnings: Vec<String>,
}

fn create_new(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("Could not create {}: {}", path.display(), e))
}

fn write_new(path: &Path, data: &[u8]) -> Result<(), String> {
    create_new(path)?
        .write_all(data)
        .map_err(|e| format!("Could not write {}: {}", path.display(), e))
}

/// Extracts all sections of the EIF at `eif_path` into `output_dir`.
/// Existing files are never overwritten.
pub fn extract_eif(eif_path: &Path, output_dir: &Path) -> Result<ExtractedEif, String> {
    let eif_file = File::open(eif_path)
        .map_err(|e| format!("Could not open {}: {}", eif_path.display(), e))?;
    let mut sections = Sections::new(eif_file)?;
    let eif_header = *sections.eif_header();

    fs::create_dir_all(output_dir)
        .map_err(|e| format!("Could not create {}: {}", output_dir.display(), e))?;

    let mut extracted = ExtractedEif {
        arch: if eif_header.flags & EIF_HDR_ARCH_ARM64 != 0 {
            "aarch64"
        } else {
            "x86_64"
        },
        kernel: None,
        cmdline: None,
        ramdisks: Vec::new(),
        metadata: None,
        custom_metadata: None,
        signing_certificate: None,
        warnings: Vec::new(),
    };

    while let Some(section) = sections.next() {
        let section = section?;
        let header_size = eif_header.section_sizes[section.index];
        if header_size != section.header.section_size {
            extracted.warnings.push(format!(
                "Section {} is {} bytes but the EIF header lists {} bytes",
                section.index, section.header.section_size, header_size
            ));
        }

        match section.header.section_type {
            EifSectionType::EifSectionKernel => {
                let path = output_dir.join("kernel");
                sections.copy_data(&section, &mut create_new(&path)?)?;
                extracted.kernel = Some(path);
            }
            EifSectionType::EifSectionCmdline => {
                let data = sections.read_data(&section)?;
                write_new(&output_dir.join("cmdline"), &data)?;
                extracted.cmdline =
                    Some(String::from_utf8(data).map_err(|_| "Cmdline is not valid UTF-8")?);
            }
            EifSectionType::EifSectionRamdisk => {
                let path = output_dir.join(format!("ramdisk{}", extracted.ramdisks.len()));
                sections.copy_data(&section, &mut create_new(&path)?)?;
                extracted.ramdisks.push(path);
            }
            EifSectionType::EifSectionMetadata => {
                let data = sections.read_data(&section)?;
                write_new(&output_dir.join("metadata.json"), &data)?;
                let metadata: EifIdentityInfo = serde_json::from_slice(&data)
                    .map_err(|e| format!("Error deserializing metadata: {}", e))?;
                if !metadata.custom_info.is_null() {
                    let path = output_dir.join("custom_metadata.json");
                    let custom = serde_json::to_vec_pretty(&metadata.custom_info)
                        .map_err(|e| format!("Error serializing custom metadata: {}", e))?;
                    write_new(&path, &custom)?;
                    extracted.custom_metadata = Some(path);
                }
                extracted.metadata = Some(metadata);
            }
            EifSectionType::EifSectionSignature => {
                let data = sections.read_data(&section)?;
                write_new(&output_dir.join("signature.cbor"), &data)?;
                let signature = parse_signature_section(&data)?;
                let pcr0_signature = signature
                    .first()
                    .ok_or_else(|| "Signature section is empty".to_string())?;
                let path = output_dir.join("signing_certificate.pem");
                write_new(&path, &pcr0_signature.signing_certificate)?;
                extracted.signing_certificate = Some(path);
            }
            EifSectionType::EifSectionInvalid => {
                unreachable!("Sections rejects invalid sections")
            }
        }
    }

    Ok(extracted)
}

fn shell_quote(arg: &str) -> String {
    let is_safe = |c: char| c.is_ascii_alphanumeric() || "-_./=:+,@".contains(c);
    if !arg.is_empty() && arg.chars().all(is_safe) {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

/// Returns the eif_build arguments that reassemble the extracted EIF,
/// except for `--output` and, for signed images, `--private-key`
pub fn eif_build_args(extracted: &ExtractedEif) -> Result<Vec<String>, String> {
    let kernel = extracted
        .kernel
        .as_ref()
        .ok_or("EIF has no kernel section")?;
    let cmdline = extracted
        .cmdline
        .as_ref()
        .ok_or("EIF has no cmdline section")?;
    if extracted.ramdisks.is_empty() {
        return Err("EIF has no ramdisk sections".to_string());
    }

    let mut args = vec![
        "--kernel".to_string(),
        kernel.display().to_string(),
        "--cmdline".to_string(),
        cmdline.clone(),
    ];
    for ramdisk in &extracted.ramdisks {
        args.push("--ramdisk".to_string());
        args.push(ramdisk.display().to_string());
    }
    args.push("--arch".to_string());
    args.push(extracted.arch.to_string());

    if let Some(metadata) = &extracted.metadata {
        let build_info = &metadata.build_info;
        for (flag, value) in [
            ("--name", &metadata.img_name),
            ("--version", &metadata.img_version),
            ("--build-time", &build_info.build_time),
            ("--build-tool", &build_info.build_tool),
            ("--build-tool-version", &build_info.build_tool_version),
            ("--img-os", &build_info.img_os),
            ("--img-kernel", &build_info.img_kernel),
        ] {
            args.push(flag.to_string());
            args.push(value.clone());
        }
    }
    if let Some(custom_metadata) = &extracted.custom_metadata {
        args.push("--metadata".to_string());
        args.push(custom_metadata.display().to_string());
    }
    if let Some(certificate) = &extracted.signing_certificate {
        args.push("--signing-certificate".to_string());
        args.push(certificate.display().to_string());
    }

    Ok(args)
}

fn main() {
    let matches = Command::new("Enclave image format extractor")
        .about("Extracts the sections of an eif file")
        .arg(
            Arg::new("eif")
                .long("eif")
                .value_name("FILE")
                .required(true)
                .help("Sets path to the eif file to extract"),
        )
        .arg(
            Arg::new("output_dir")
                .long("output-dir")
                .value_name("DIR")
                .required(true)
                .help("Directory to extract the sections to. Existing files are not overwritten"),
        )
        .get_matches();

    let eif_path = matches
        .get_one::<String>("eif")
        .expect("Eif path is a mandatory option");
    let output_dir = matches
        .get_one::<String>("output_dir")
        .expect("Output directory is a mandatory option");

    let extracted = extract_eif(Path::new(eif_path), Path::new(output_dir)).unwrap_or_else(|e| {
        eprintln!("Failed to extract {}: {}", eif_path, e);
        std::process::exit(1);
    });

    for warning in &extracted.warnings {
        eprintln!("Warning: {}", warning);
    }
    println!("Extracted {} to {}", eif_path, output_dir);

    match eif_build_args(&extracted) {
        Ok(args) => {
            let mut args: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
            if extracted.signing_certificate.is_some() {
                args.push("--private-key <PRIVATE_KEY>".to_string());
            }
            args.push("--output <OUTPUT>".to_string());
            println!("\nTo reassemble it, run:\neif_build {}", args.join(" "));
            let metadata = extracted.metadata.as_ref();
            if metadata.is_some_and(|m| !m.docker_info.is_null()) {
                println!("\nNote: eif_build does not set the docker info found in metadata.json.");
            }
        }
        Err(e) => println!("\nCannot be reassembled with eif_build: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_nitro_enclaves_image_format::defs::{EifBuildInfo, EifHeader};
    use aws_nitro_enclaves_image_format::utils::eif_reader::EifReader;
    use aws_nitro_enclaves_image_format::utils::{EifBuilder, SignKeyData};
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509NameBuilder, X509};
    use sha2::{Digest, Sha384};
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    struct Inputs {
        kernel: PathBuf,
        cmdline: String,
        ramdisks: Vec<PathBuf>,
        eif_info: EifIdentityInfo,
    }

    fn test_inputs(dir: &Path) -> Inputs {
        let kernel = dir.join("bzImage");
        fs::write(&kernel, b"kernel data").unwrap();
        let ramdisks = vec![dir.join("init.cpio.gz"), dir.join("user.cpio.gz")];
        fs::write(&ramdisks[0], b"init ramdisk").unwrap();
        fs::write(&ramdisks[1], vec![0xa5; 300_000]).unwrap();

        Inputs {
            kernel,
            cmdline: "reboot=k panic=30 console=ttyS0 init='/init'".to_string(),
            ramdisks,
            eif_info: EifIdentityInfo {
                img_name: "my-enclave".to_string(),
                img_version: "1.2.3".to_string(),
                build_info: EifBuildInfo {
                    build_time: "2026-01-01T00:00:00+00:00".to_string(),
                    build_tool: "eif_build".to_string(),
                    build_tool_version: "0.3.2".to_string(),
                    img_os: "Linux".to_string(),
                    img_kernel: "6.1".to_string(),
                },
                docker_info: serde_json::Value::Null,
                custom_info: serde_json::json!({"app": "test", "replicas": 3}),
            },
        }
    }

    fn build(inputs: Inputs, sign_info: Option<SignKeyData>, output: &Path) {
        let mut builder = EifBuilder::new(
            &inputs.kernel,
            inputs.cmdline,
            sign_info,
            Sha384::new(),
            0,
            inputs.eif_info,
        );
        for ramdisk in &inputs.ramdisks {
            builder.add_ramdisk(ramdisk);
        }
        let mut output_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(output)
            .unwrap();
        builder.write_to(&mut output_file);
    }

    /// The inputs eif_build would use when run with `eif_build_args`
    fn inputs_from_extracted(extracted: &ExtractedEif) -> Inputs {
        let metadata = extracted.metadata.clone().unwrap();
        let custom_info = match &extracted.custom_metadata {
            Some(path) => serde_json::from_slice(&fs::read(path).unwrap()).unwrap(),
            None => serde_json::Value::Null,
        };
        Inputs {
            kernel: extracted.kernel.clone().unwrap(),
            cmdline: extracted.cmdline.clone().unwrap(),
            ramdisks: extracted.ramdisks.clone(),
            eif_info: EifIdentityInfo {
                docker_info: serde_json::Value::Null,
                custom_info,
                ..metadata
            },
        }
    }

    fn generate_sign_info(dir: &Path) -> SignKeyData {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "eif_extract test").unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha384()).unwrap();

        let key_path = dir.join("key.pem");
        let cert_path = dir.join("cert.pem");
        fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        fs::write(&cert_path, cert.build().to_pem().unwrap()).unwrap();
        SignKeyData::new(key_path.to_str().unwrap(), &cert_path).unwrap()
    }

    fn measurements(eif: &Path) -> BTreeMap<String, String> {
        EifReader::from_eif(eif.to_str().unwrap().to_string())
            .unwrap()
            .get_measurements()
            .unwrap()
    }

    #[test]
    fn test_unsigned_round_trip_is_identical() {
        let dir = TempDir::new().unwrap();
        let original = dir.path().join("original.eif");
        let inputs = test_inputs(dir.path());
        let original_ramdisk = fs::read(&inputs.ramdisks[1]).unwrap();
        build(inputs, None, &original);

        let extracted = extract_eif(&original, &dir.path().join("out")).unwrap();
        assert!(extracted.warnings.is_empty());
        assert_eq!(extracted.arch, "x86_64");
        assert_eq!(extracted.ramdisks.len(), 2);
        assert_eq!(fs::read(&extracted.ramdisks[1]).unwrap(), original_ramdisk);
        assert!(extracted.signing_certificate.is_none());

        let rebuilt = dir.path().join("rebuilt.eif");
        build(inputs_from_extracted(&extracted), None, &rebuilt);
        assert_eq!(fs::read(&original).unwrap(), fs::read(&rebuilt).unwrap());
    }

    #[test]
    fn test_signed_round_trip_keeps_measurements() {
        let dir = TempDir::new().unwrap();
        let original = dir.path().join("original.eif");
        build(
            test_inputs(dir.path()),
            Some(generate_sign_info(dir.path())),
            &original,
        );

        let extracted = extract_eif(&original, &dir.path().join("out")).unwrap();
        let certificate = extracted.signing_certificate.clone().unwrap();
        assert_eq!(
            fs::read(certificate).unwrap(),
            fs::read(dir.path().join("cert.pem")).unwrap()
        );
        assert!(dir.path().join("out/signature.cbor").is_file());

        let rebuilt = dir.path().join("rebuilt.eif");
        build(
            inputs_from_extracted(&extracted),
            Some(
                SignKeyData::new(
                    dir.path().join("key.pem").to_str().unwrap(),
                    &dir.path().join("cert.pem"),
                )
                .unwrap(),
            ),
            &rebuilt,
        );
        let original_pcrs = measurements(&original);
        assert!(original_pcrs.contains_key("PCR8"));
        assert_eq!(original_pcrs, measurements(&rebuilt));
    }

    #[test]
    fn test_eif_build_args() {
        let dir = TempDir::new().unwrap();
        let original = dir.path().join("original.eif");
        build(test_inputs(dir.path()), None, &original);
        let out = dir.path().join("out");

        let extracted = extract_eif(&original, &out).unwrap();
        let args = eif_build_args(&extracted).unwrap();
        let value_of = |flag: &str| {
            let pos = args.iter().position(|a| a == flag).unwrap();
            args[pos + 1].clone()
        };

        assert_eq!(
            value_of("--kernel"),
            out.join("kernel").display().to_string()
        );
        assert_eq!(
            value_of("--cmdline"),
            "reboot=k panic=30 console=ttyS0 init='/init'"
        );
        assert_eq!(args.iter().filter(|a| *a == "--ramdisk").count(), 2);
        assert_eq!(value_of("--arch"), "x86_64");
        assert_eq!(value_of("--name"), "my-enclave");
        assert_eq!(value_of("--version"), "1.2.3");
        assert_eq!(value_of("--build-time"), "2026-01-01T00:00:00+00:00");
        assert_eq!(value_of("--img-kernel"), "6.1");
        assert_eq!(
            value_of("--metadata"),
            out.join("custom_metadata.json").display().to_string()
        );
        assert!(!args.contains(&"--signing-certificate".to_string()));
    }

    #[test]
    fn test_extract_does_not_overwrite() {
        let dir = TempDir::new().unwrap();
        let original = dir.path().join("original.eif");
        build(test_inputs(dir.path()), None, &original);
        let out = dir.path().join("out");

        extract_eif(&original, &out).unwrap();
        assert!(extract_eif(&original, &out).is_err());
    }

    #[test]
    fn test_extract_warns_on_header_size_mismatch() {
        let dir = TempDir::new().unwrap();
        let original = dir.path().join("original.eif");
        build(test_inputs(dir.path()), None, &original);

        // Make the EIF header disagree with the last section header, as
        // happens to the signature section of re-signed images (issue #54)
        let mut eif = fs::read(&original).unwrap();
        let mut header = EifHeader::from_be_bytes(&eif[..EifHeader::size()]).unwrap();
        let last = header.num_sections as usize - 1;
        header.section_sizes[last] += 1;
        eif[..EifHeader::size()].copy_from_slice(&header.to_be_bytes());
        let modified = dir.path().join("modified.eif");
        fs::write(&modified, eif).unwrap();

        let extracted = extract_eif(&modified, &dir.path().join("out")).unwrap();
        assert_eq!(extracted.warnings.len(), 1);
        assert_eq!(
            fs::read(&extracted.ramdisks[1]).unwrap(),
            vec![0xa5; 300_000]
        );
    }

    #[test]
    fn test_shell_quote() {
        assert_eq!(shell_quote("console=ttyS0"), "console=ttyS0");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("init='/init'"), r"'init='\''/init'\'''");
        assert_eq!(shell_quote(""), "''");
    }
}
