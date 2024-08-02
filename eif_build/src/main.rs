// Copyright 2019-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Simple utility tool for building an EIF file.
//!
//! Example of usage:
//!
//!```sh
//! cargo run -p eif_build --target-dir=~/vmm-build -- --kernel bzImage \
//!   --cmdline "reboot=k initrd=0x2000000,3228672 root=/dev/ram0 panic=1 pci=off nomodules \
//!              console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd" \
//!   --ramdisk initramfs_x86.txt_part1.cpio.gz \
//!   --ramdisk initramfs_x86.txt_part2.cpio.gz \
//!   --output eif.bin
//!```
#![deny(warnings)]
use aws_nitro_enclaves_image_format::defs::{EifBuildInfo, EifIdentityInfo, EIF_HDR_ARCH_ARM64};
use aws_nitro_enclaves_image_format::utils::identity::parse_custom_metadata;
use aws_nitro_enclaves_image_format::{
    generate_build_info,
    utils::{get_pcrs, EifBuilder, SignEnclaveInfo},
};
use chrono::offset::Utc;
use clap::{Args, Parser, ValueEnum};
use serde_json::json;
use sha2::{Digest, Sha384};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

#[allow(non_camel_case_types)]
#[derive(Clone, Debug, ValueEnum)]
#[clap(rename_all = "snake_case")]
enum Arch {
    x86_64,
    aarch64,
}

// Work around https://github.com/clap-rs/clap/issues/5092 where an optional group of arguments
// isn't correctly set as required = false.
#[derive(Args, Debug)]
#[group(requires_all = ["signing_certificate", "private_key"])]
struct SignArgs {
    /// Specify the path to the signing certificate
    #[arg(long, required = false)]
    signing_certificate: PathBuf,
    /// Specify the path to the private-key
    #[arg(long, required = false)]
    private_key: PathBuf,
}

#[derive(Debug, Parser)]
#[command(
    about = "Builds an eif file",
    author,
    long_about,
    name = "Enclave image format builder",
    version
)]
struct CliArgs {
    /// Sets image architecture
    #[arg(long, value_enum, default_value_t = Arch::x86_64)]
    arch: Arch,
    /// Overrides image build time.
    #[arg(long, default_value_t = Utc::now().to_rfc3339())]
    build_time: String,
    /// Image build tool name.
    #[arg(long, default_value_t = env!("CARGO_PKG_NAME").into())]
    build_tool: String,
    /// Overrides image build tool version.
    #[arg(long, default_value_t = env!("CARGO_PKG_VERSION").into())]
    build_tool_version: String,
    /// Sets the cmdline
    #[arg(long, value_name = "String")]
    cmdline: String,
    /// Overrides image Operating System kernel version.
    #[arg(long, default_value_t = String::from("Unkown version"))]
    image_kernel: String,
    /// Name for enclave image
    #[arg(long)]
    image_name: Option<String>,
    /// Overrides image Operating System name.
    #[arg(long, default_value_t = String::from("Generic Linux"))]
    image_os: String,
    /// Version of the enclave image
    #[arg(long)]
    image_version: Option<String>,
    /// Sets path to a bzImage/Image file for x86_64/aarch64 architecture
    #[arg(long, value_name = "FILE")]
    kernel: PathBuf,
    /// Sets path to a bzImage.config/Image.config file for x86_64/aarch64 architecture
    #[arg(long, value_name = "FILE")]
    kernel_config: Option<PathBuf>,
    /// Path to JSON containing the custom metadata provided by the user.
    #[arg(long)]
    metadata: Option<PathBuf>,
    /// Specify output file path
    #[arg(long, value_name = "FILE")]
    output: PathBuf,
    /// Sets path to a ramdisk file representing a cpio.gz archive
    #[arg(long, required = true, value_name = "FILE")]
    ramdisk: Vec<PathBuf>,
    #[command(flatten)]
    sign: Option<SignArgs>,
}

fn main() {
    let opts = CliArgs::parse();

    let sign_info = opts.sign.map(|sign_opts| {
        SignEnclaveInfo::new(sign_opts.signing_certificate, sign_opts.private_key)
            .expect("Could not read signing info")
    });

    let metadata = opts.metadata.map_or(json!(null), |meta_path| {
        parse_custom_metadata(meta_path).expect("Can not parse specified metadata file")
    });

    let mut build_info = EifBuildInfo {
        build_time: opts.build_time,
        build_tool: opts.build_tool,
        build_tool_version: opts.build_tool_version,
        img_os: opts.image_os,
        img_kernel: opts.image_kernel,
    };

    if let Some(kernel_config) = opts.kernel_config {
        build_info = generate_build_info!(kernel_config).expect("Can not generate build info");
    }

    let img_name = if let Some(name) = opts.image_name {
        name
    } else {
        opts.kernel
            .file_name()
            .expect("Valid kernel file path should be provided")
            .to_str()
            .unwrap()
            .to_string()
    };
    let eif_info = EifIdentityInfo {
        img_name,
        img_version: opts.image_version.unwrap_or("1.0".into()),
        build_info,
        docker_info: json!(null),
        custom_info: metadata,
    };

    build_eif(
        opts.kernel,
        &opts.cmdline,
        &opts.ramdisk,
        opts.output,
        sign_info,
        eif_info,
        opts.arch,
    );
}

fn build_eif<P: AsRef<Path>>(
    kernel_path: P,
    cmdline: &str,
    ramdisks: &[P],
    output_path: P,
    sign_info: Option<SignEnclaveInfo>,
    eif_info: EifIdentityInfo,
    arch: Arch,
) {
    let hasher = Sha384::new();
    let mut output_file = OpenOptions::new()
        .read(true)
        .create(true)
        .write(true)
        .truncate(true)
        .open(output_path.as_ref())
        .expect("Could not create output file");

    let flags = match arch {
        Arch::aarch64 => EIF_HDR_ARCH_ARM64,
        Arch::x86_64 => 0,
    };

    let mut build = EifBuilder::new(
        kernel_path,
        cmdline.to_string(),
        sign_info,
        hasher.clone(),
        flags, // flags
        eif_info,
    );
    for ramdisk in ramdisks {
        build.add_ramdisk(ramdisk);
    }

    build.write_to(&mut output_file);
    let signed = build.is_signed();
    println!("Output file: {}", output_path.as_ref().display());
    build.measure();
    let measurements = get_pcrs(
        &mut build.image_hasher,
        &mut build.bootstrap_hasher,
        &mut build.customer_app_hasher,
        &mut build.certificate_hasher,
        hasher,
        signed,
    )
    .expect("Failed to get boot measurements.");

    println!("{}", serde_json::to_string_pretty(&measurements).unwrap());
}
