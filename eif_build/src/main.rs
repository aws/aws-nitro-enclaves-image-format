// Copyright 2019-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]
/// Simple utility tool for building an Eif file
///  cargo run --example eif_build -- --help  should be self explanatory.
/// Example of usage:
/// cargo run --example eif_build --target-dir=~/vmm-build -- --kernel bzImage \
///    --cmdline "reboot=k initrd=0x2000000,3228672 root=/dev/ram0 panic=1 pci=off nomodules \
///               console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd"
///   --ramdisk  initramfs_x86.txt_part1.cpio.gz
///   --ramdisk  initramfs_x86.txt_part2.cpio.gz
///   --output   eif.bin
///
use std::path::Path;

use aws_nitro_enclaves_image_format::defs::{EifBuildInfo, EifIdentityInfo, EIF_HDR_ARCH_ARM64};
use aws_nitro_enclaves_image_format::utils::identity::parse_custom_metadata;
use aws_nitro_enclaves_image_format::{
    generate_build_info,
    utils::{get_pcrs, EifBuilder, SignKeyData, SignKeyDataInfo, SignKeyInfo},
};
use chrono::offset::Utc;
use clap::{App, Arg, ArgGroup, ValueSource};
use serde_json::json;
use sha2::{Digest, Sha384};
use std::fmt::Debug;
use std::fs::OpenOptions;
use std::io::Write;
use ValueSource::CommandLine;

pub struct EifBuildParameters<'a> {
    pub kernel_path: &'a str,
    pub cmdline: &'a str,
    pub ramdisks: Vec<&'a str>,
    pub output_path: &'a str,
    pub sign_info: Option<SignKeyData>,
    pub eif_info: EifIdentityInfo,
    pub arch: &'a str,
}

fn main() {
    let now = Utc::now().to_rfc3339();
    let build_tool = env!("CARGO_PKG_NAME").to_string();
    let build_tool_version = env!("CARGO_PKG_VERSION").to_string();
    let img_os = "OS".to_string();
    let img_kernel = "kernel".to_string();
    let matches = App::new("Enclave image format builder")
        .about("Builds an eif file")
        .arg(
            Arg::with_name("kernel")
                .long("kernel")
                .value_name("FILE")
                .required(true)
                .help("Sets path to a bzImage/Image file for x86_64/aarch64 architecture")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("kernel_config")
                .long("kernel_config")
                .value_name("FILE")
                .help("Sets path to a bzImage.config/Image.config file for x86_64/aarch64 architecture")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cmdline")
                .long("cmdline")
                .help("Sets the cmdline")
                .value_name("String")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("output")
                .long("output")
                .help("Specify output file path")
                .value_name("FILE")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ramdisk")
                .long("ramdisk")
                .value_name("FILE")
                .required(true)
                .help("Sets path to a ramdisk file representing a cpio.gz archive")
                .takes_value(true)
                .multiple(true)
                .number_of_values(1),
        )
        .arg(
            Arg::with_name("signing-certificate")
                .long("signing-certificate")
                .help("Specify the path to the signing certificate")
                .takes_value(true)
                .requires("signing-key"),
        )
        .arg(
            Arg::with_name("private-key")
                .long("private-key")
                .help("Specify the path to the private-key")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("kms-key-id")
                .long("kms-key-id")
                .help("Specify unique id of the KMS key")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("kms-key-region")
                .long("kms-key-region")
                .help("Specify region in which the KMS key resides")
                .takes_value(true)
                .requires("kms-key-id")
        )
        .group(
            ArgGroup::new("signing-key")
                .args(&["kms-key-id", "private-key"])
                .multiple(false)
                .requires("signing-certificate")
        )
        .arg(
            Arg::with_name("image_name")
                .long("name")
                .help("Name for enclave image")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("image_version")
                .long("version")
                .help("Version of the enclave image")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("metadata")
                .long("metadata")
                .help("Path to JSON containing the custom metadata provided by the user.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("arch")
                .long("arch")
                .help("Sets image architecture")
                .default_value("x86_64")
                .value_parser(["x86_64", "aarch64"])
                .takes_value(true),
        )
        .arg(
            Arg::with_name("build_time")
                .long("build-time")
                .help("Overrides image build time.")
                .default_value(&now)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("build_tool")
                .long("build-tool")
                .help("Image build tool name.")
                .default_value(&build_tool)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("build_tool_version")
                .long("build-tool-version")
                .help("Overrides image build tool version.")
                .default_value(&build_tool_version)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("img_os")
                .long("img-os")
                .help("Overrides image Operating System name.")
                .default_value(&img_os)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("img_kernel")
                .long("img-kernel")
                .help("Overrides image Operating System kernel version.")
                .default_value(&img_kernel)
                .takes_value(true),
        )
        .get_matches();

    let arch = matches.value_of("arch").expect("default value");

    let kernel_path = matches
        .value_of("kernel")
        .expect("Kernel path is a mandatory option");

    let cmdline = matches
        .value_of("cmdline")
        .expect("Cmdline is a mandatory option");

    let ramdisks: Vec<&str> = matches
        .values_of("ramdisk")
        .expect("At least one ramdisk should be specified")
        .collect();

    let output_path = matches
        .value_of("output")
        .expect("Output file should be provided");

    let signing_certificate = matches.value_of("signing-certificate");

    let private_key = matches.value_of("private-key");

    let kms_key_id = matches.value_of("kms-key-id");
    let kms_key_region = matches.value_of("kms-key-region");

    let sign_key_info = match (kms_key_id, private_key) {
        (None, None) => None,
        (Some(kms_id), None) => Some(SignKeyInfo::KmsKeyInfo {
            id: kms_id.into(),
            region: kms_key_region.map(str::to_string),
        }),
        (None, Some(key_path)) => Some(SignKeyInfo::LocalPrivateKeyInfo {
            path: key_path.into(),
        }),
        _ => panic!("kms-key-id and private-key parameters are mutually exclusive"),
    };

    let sign_key_data = sign_key_info.map(|key_info| {
        SignKeyData::new(&SignKeyDataInfo {
            cert_path: signing_certificate.unwrap().into(),
            key_info,
        })
        .expect("Could not read signing info")
    });

    let img_name = matches.value_of("image_name").map(|val| val.to_string());
    let img_version = matches.value_of("image_name").map(|val| val.to_string());
    let metadata_path = matches.value_of("metadata").map(|val| val.to_string());
    let metadata = match metadata_path {
        Some(ref path) => {
            parse_custom_metadata(path).expect("Can not parse specified metadata file")
        }
        None => json!(null),
    };

    let mut build_info = EifBuildInfo {
        build_time: matches
            .get_one::<String>("build_time")
            .expect("default value")
            .to_string(),
        build_tool: matches
            .get_one::<String>("build_tool")
            .expect("default value")
            .to_string(),
        build_tool_version: matches
            .get_one::<String>("build_tool_version")
            .expect("default value")
            .to_string(),
        img_os: matches
            .get_one::<String>("img_os")
            .expect("default value")
            .to_string(),
        img_kernel: matches
            .get_one::<String>("img_kernel")
            .expect("default value")
            .to_string(),
    };

    if let Some(kernel_config) = matches.get_one::<String>("kernel_config") {
        build_info = generate_build_info!(kernel_config).expect("Can not generate build info");
    }

    if matches.value_source("build_time") == Some(CommandLine) {
        build_info.build_time = matches
            .get_one::<String>("build_time")
            .expect("default value")
            .to_string();
    }

    if matches.value_source("build_tool") == Some(CommandLine) {
        build_info.build_tool = matches
            .get_one::<String>("build_tool")
            .expect("default_value")
            .to_string();
    }

    if matches.value_source("build_tool_version") == Some(CommandLine) {
        build_info.build_tool_version = matches
            .get_one::<String>("build_tool_version")
            .expect("default value")
            .to_string();
    }

    if matches.value_source("img_os") == Some(CommandLine) {
        build_info.img_os = matches
            .get_one::<String>("img_os")
            .expect("default value")
            .to_string();
    }

    if matches.value_source("img_kernel") == Some(CommandLine) {
        build_info.img_kernel = matches
            .get_one::<String>("img_kernel")
            .expect("default value")
            .to_string();
    }

    let eif_info = EifIdentityInfo {
        img_name: img_name.unwrap_or_else(|| {
            // Set default value to kernel file name
            Path::new(kernel_path)
                .file_name()
                .expect("Valid kernel file path should be provided")
                .to_str()
                .unwrap()
                .to_string()
        }),
        img_version: img_version.unwrap_or_else(|| "1.0".to_string()),
        build_info,
        docker_info: json!(null),
        custom_info: metadata,
    };

    let params = EifBuildParameters {
        kernel_path,
        cmdline,
        ramdisks,
        output_path,
        sign_info: sign_key_data,
        eif_info,
        arch
    };

    build_eif(
        params,
        Sha384::new(),
    );
}

pub fn build_eif<T: Digest + Debug + Write + Clone>(
    params: EifBuildParameters,
    hasher: T
) {
    let mut output_file = OpenOptions::new()
        .read(true)
        .create(true)
        .write(true)
        .truncate(true)
        .open(params.output_path)
        .expect("Could not create output file");

    let flags = match params.arch {
        "aarch64" => EIF_HDR_ARCH_ARM64,
        "x86_64" => 0,
        _ => panic!("Invalid architecture: {}", params.arch),
    };

    let mut build = EifBuilder::new(
        Path::new(params.kernel_path),
        params.cmdline.to_string(),
        params.sign_info,
        hasher.clone(),
        flags, // flags
        params.eif_info,
    );
    for ramdisk in params.ramdisks {
        build.add_ramdisk(Path::new(ramdisk));
    }

    build.write_to(&mut output_file);
    let signed = build.is_signed();
    println!("Output file: {}", params.output_path);
    build.measure();
    let measurements = get_pcrs(
        &mut build.image_hasher,
        &mut build.bootstrap_hasher,
        &mut build.customer_app_hasher,
        &mut build.certificate_hasher,
        hasher.clone(),
        signed,
    )
    .expect("Failed to get boot measurements.");

    println!("{}", serde_json::to_string_pretty(&measurements).unwrap());
}
