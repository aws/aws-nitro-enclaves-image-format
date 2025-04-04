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
    utils::{get_pcrs, EifBuilder, SignKeyData},
};
use chrono::offset::Utc;
use clap::{Arg, ArgAction, Command};
use serde_json::json;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt::Debug;
use std::fs::OpenOptions;
use std::io::Write;

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
    let img_os = "OS";
    let img_kernel = "kernel";
    let matches = Command::new("Enclave image format builder")
        .about("Builds an eif file")
        .arg(
            Arg::new("kernel")
                .long("kernel")
                .value_name("FILE")
                .required(true)
                .help("Sets path to a bzImage/Image file for x86_64/aarch64 architecture")
        )
        .arg(
            Arg::new("kernel_config")
                .long("kernel_config")
                .value_name("FILE")
                .help("Sets path to a bzImage.config/Image.config file for x86_64/aarch64 architecture")
        )
        .arg(
            Arg::new("cmdline")
                .long("cmdline")
                .help("Sets the cmdline")
                .value_name("String")
                .required(true)
        )
        .arg(
            Arg::new("output")
                .long("output")
                .help("Specify output file path")
                .value_name("FILE")
                .required(true)
        )
        .arg(
            Arg::new("ramdisk")
                .long("ramdisk")
                .value_name("FILE")
                .required(true)
                .help("Sets path to a ramdisk file representing a cpio.gz archive")
                .action(ArgAction::Append)
        )
        .arg(
            Arg::new("signing-certificate")
                .long("signing-certificate")
                .help("Specify the path to the signing certificate")
                .requires("private-key"),
        )
        .arg(
            Arg::new("private-key")
                .long("private-key")
                .help("Path to a local key or KMS key ARN")
                .requires("signing-certificate"),
        )
        .arg(
            Arg::new("image_name")
                .long("name")
                .help("Name for enclave image")
        )
        .arg(
            Arg::new("image_version")
                .long("version")
                .help("Version of the enclave image")
        )
        .arg(
            Arg::new("metadata")
                .long("metadata")
                .help("Path to JSON containing the custom metadata provided by the user.")
        )
        .arg(
            Arg::new("arch")
                .long("arch")
                .help("Sets image architecture")
                .default_value("x86_64")
                .value_parser(["x86_64", "aarch64"])
        )
        .arg(
            Arg::new("build_time")
                .long("build-time")
                .help("Overrides image build time.")
                .default_value(now)
        )
        .arg(
            Arg::new("build_tool")
                .long("build-tool")
                .help("Image build tool name.")
                .default_value(build_tool)
        )
        .arg(
            Arg::new("build_tool_version")
                .long("build-tool-version")
                .help("Overrides image build tool version.")
                .default_value(build_tool_version)
        )
        .arg(
            Arg::new("img_os")
                .long("img-os")
                .help("Overrides image Operating System name.")
                .default_value(img_os)
        )
        .arg(
            Arg::new("img_kernel")
                .long("img-kernel")
                .help("Overrides image Operating System kernel version.")
                .default_value(img_kernel)
        )
        .arg(
            Arg::new("algo")
                .long("algo")
                .help("Sets algorithm to be used for measuring the image")
                .value_parser(["sha256", "sha384", "sha512"])
                .default_value("sha384")
        )
        .get_matches();

    let arch = matches.get_one::<String>("arch").expect("default value");

    let kernel_path = matches
        .get_one::<String>("kernel")
        .expect("Kernel path is a mandatory option");

    let cmdline = matches
        .get_one::<String>("cmdline")
        .expect("Cmdline is a mandatory option");

    let ramdisks: Vec<&str> = matches
        .get_many::<String>("ramdisk")
        .expect("At least one ramdisk should be specified")
        .map(|s| s.as_str())
        .collect();

    let output_path = matches
        .get_one::<String>("output")
        .expect("Output file should be provided");

    let signing_certificate = matches.get_one::<String>("signing-certificate");
    let private_key = matches.get_one::<String>("private-key");

    let sign_info = match (private_key, signing_certificate) {
        (Some(key), Some(cert)) => SignKeyData::new(key, Path::new(&cert)).map_or_else(
            |e| {
                eprintln!("Could not read signing info: {:?}", e);
                None
            },
            Some,
        ),
        _ => None,
    };

    let img_name = matches.get_one::<String>("image_name").map(String::from);
    let img_version = matches.get_one::<String>("image_name").map(String::from);
    let metadata_path = matches.get_one::<String>("metadata").map(String::from);
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
        sign_info,
        eif_info,
        arch,
    };

    let algo = matches
        .get_one::<String>("algo")
        .expect("Clap must specify default value");
    match algo.as_str() {
        "sha256" => build_eif(params, Sha256::new()),
        "sha512" => build_eif(params, Sha512::new()),
        "sha384" => build_eif(params, Sha384::new()),
        _ => unreachable!("Clap guarantees that we get only the specified values"),
    }
}

pub fn build_eif<T: Digest + Debug + Write + Clone>(params: EifBuildParameters, hasher: T) {
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
