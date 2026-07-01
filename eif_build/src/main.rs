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

use aws_nitro_enclaves_image_format::defs::{
    EifBuildInfo, EifIdentityInfo, EIF_HDR_ARCH_ARM64, EIF_HDR_FLAG_CPU_ACCOUNTING,
    EIF_HDR_FLAG_CPU_OVERCOMMIT, EIF_HDR_FLAG_PCIE, EIF_HDR_FLAG_PCIE_HOTPLUG,
    EIF_HDR_FLAG_PCIE_NUMA, EIF_HDR_FLAG_PCIE_VIRTIO, EIF_HDR_FLAG_PCIE_VSOCK,
};
use aws_nitro_enclaves_image_format::utils::identity::parse_custom_metadata;
use aws_nitro_enclaves_image_format::{
    generate_build_info,
    utils::{EifBuilder, SignKeyData},
};
use chrono::offset::Utc;
use clap::{Arg, ArgAction, ArgMatches, Command};
use serde_json::json;
use sha2::digest::FixedOutputReset;
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
    /// Matched feature flags for the EIF header. Zero for a plain image.
    pub matched_flags: u16,
}

const MATCHED_FLAGS: [(&str, u16); 7] = [
    ("pcie", EIF_HDR_FLAG_PCIE),
    ("pcie_vsock", EIF_HDR_FLAG_PCIE_VSOCK),
    ("pcie_virtio", EIF_HDR_FLAG_PCIE_VIRTIO),
    ("pcie_hotplug", EIF_HDR_FLAG_PCIE_HOTPLUG),
    ("pcie_numa", EIF_HDR_FLAG_PCIE_NUMA),
    ("cpu_overcommit", EIF_HDR_FLAG_CPU_OVERCOMMIT),
    ("cpu_accounting", EIF_HDR_FLAG_CPU_ACCOUNTING),
];

/// Each option sets only its own bit, so the command line shows every bit
/// that goes into the header and PCR0. The argument rules enforce the flag
/// rules that the README lists.
fn matched_flag_args() -> [Arg; 7] {
    let flag = |id: &'static str, long: &'static str, help: &'static str| {
        Arg::new(id)
            .long(long)
            .help(help)
            .action(ArgAction::SetTrue)
    };
    [
        flag(
            "pcie",
            "pcie",
            "Set the PCIE matched flag, which every other matched flag needs.",
        ),
        flag(
            "pcie_vsock",
            "pcie-vsock",
            "Set the PCIE_VSOCK matched flag (needs --pcie).",
        )
        .requires("pcie")
        .conflicts_with_all(["pcie_virtio", "pcie_hotplug"]),
        flag(
            "pcie_virtio",
            "pcie-virtio",
            "Set the PCIE_VIRTIO matched flag (needs --pcie).",
        )
        .requires("pcie"),
        flag(
            "pcie_hotplug",
            "pcie-hotplug",
            "Set the PCIE_HOTPLUG matched flag (needs --pcie).",
        )
        .requires("pcie"),
        flag(
            "pcie_numa",
            "pcie-numa",
            "Set the PCIE_NUMA matched flag (needs --pcie).",
        )
        .requires("pcie"),
        flag(
            "cpu_overcommit",
            "cpu-overcommit",
            "Set the CPU_OVERCOMMIT matched flag (needs --pcie and --pcie-virtio).",
        )
        .requires("pcie")
        .requires("pcie_virtio")
        // clap skips a required option that conflicts with a present one.
        // Without this conflict, --pcie-vsock would excuse the missing
        // --pcie-virtio.
        .conflicts_with("pcie_vsock"),
        flag(
            "cpu_accounting",
            "cpu-accounting",
            "Set the CPU_ACCOUNTING matched flag (needs --pcie).",
        )
        .requires("pcie"),
    ]
}

fn matched_flags(matches: &ArgMatches) -> u16 {
    MATCHED_FLAGS
        .iter()
        .filter(|(id, _)| matches.get_flag(id))
        .fold(0, |flags, (_, bit)| flags | bit)
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
                .help(if cfg!(feature = "pkcs11") {
                    "Path to a local key, a KMS key ARN, or a PKCS#11 URI \
                     (pkcs11:...; module via the URI's module-path or the \
                     NITRO_CLI_PKCS11_MODULE env var)"
                } else {
                    "Path to a local key or KMS key ARN"
                })
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
        .args(matched_flag_args())
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

    let matched_flags = matched_flags(&matches);

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
    let img_version = matches.get_one::<String>("image_version").map(String::from);
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
        matched_flags,
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

pub fn build_eif<T: Digest + FixedOutputReset + Debug + Write + Clone>(
    params: EifBuildParameters,
    hasher: T,
) {
    let mut output_file = OpenOptions::new()
        .read(true)
        .create(true)
        .write(true)
        .truncate(true)
        .open(params.output_path)
        .expect("Could not create output file");

    let arch_flag = match params.arch {
        "aarch64" => EIF_HDR_ARCH_ARM64,
        "x86_64" => 0,
        _ => panic!("Invalid architecture: {}", params.arch),
    };
    let flags = arch_flag | params.matched_flags;

    let mut build = EifBuilder::new(
        Path::new(params.kernel_path),
        params.cmdline.to_string(),
        params.sign_info,
        hasher,
        flags, // flags
        params.eif_info,
    );
    for ramdisk in params.ramdisks {
        build.add_ramdisk(Path::new(ramdisk));
    }

    // For PCIE-flagged images, write_to's returned measurements include
    // PCR6, the whole-file measurement over the header-derived extent of
    // the finished output.
    let measurements = build.write_to(&mut output_file);
    println!("Output file: {}", params.output_path);

    println!("{}", serde_json::to_string_pretty(&measurements).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    fn parse(args: &[&str]) -> Result<u16, ErrorKind> {
        Command::new("eif_build")
            .args(matched_flag_args())
            .try_get_matches_from(std::iter::once("eif_build").chain(args.iter().copied()))
            .map(|matches| matched_flags(&matches))
            .map_err(|e| e.kind())
    }

    #[test]
    fn each_option_sets_only_its_own_bit() {
        assert_eq!(parse(&[]), Ok(0));
        let pcie = EIF_HDR_FLAG_PCIE;
        let virtio = pcie | EIF_HDR_FLAG_PCIE_VIRTIO;
        // Each option with the options it requires, and the flags expected.
        for (args, flags) in [
            (&["--pcie"][..], pcie),
            (&["--pcie", "--pcie-vsock"], pcie | EIF_HDR_FLAG_PCIE_VSOCK),
            (&["--pcie", "--pcie-virtio"], virtio),
            (
                &["--pcie", "--pcie-hotplug"],
                pcie | EIF_HDR_FLAG_PCIE_HOTPLUG,
            ),
            (&["--pcie", "--pcie-numa"], pcie | EIF_HDR_FLAG_PCIE_NUMA),
            (
                &["--pcie", "--cpu-accounting"],
                pcie | EIF_HDR_FLAG_CPU_ACCOUNTING,
            ),
            (
                &["--pcie", "--pcie-virtio", "--cpu-overcommit"],
                virtio | EIF_HDR_FLAG_CPU_OVERCOMMIT,
            ),
            // Every option that may be combined, at once.
            (
                &[
                    "--pcie",
                    "--pcie-virtio",
                    "--pcie-hotplug",
                    "--pcie-numa",
                    "--cpu-overcommit",
                    "--cpu-accounting",
                ],
                0x3b40,
            ),
        ] {
            assert_eq!(parse(args), Ok(flags), "{args:?}");
        }
    }

    #[test]
    fn rejects_invalid_flag_combinations() {
        for args in [
            &["--pcie-vsock"][..],
            &["--pcie-virtio"],
            &["--pcie-hotplug"],
            &["--pcie-numa"],
            &["--cpu-accounting"],
            &["--pcie-virtio", "--cpu-overcommit"],
            &["--pcie", "--cpu-overcommit"],
        ] {
            assert_eq!(
                parse(args),
                Err(ErrorKind::MissingRequiredArgument),
                "{args:?}"
            );
        }
        for args in [
            &["--pcie", "--pcie-vsock", "--pcie-virtio"][..],
            &["--pcie", "--pcie-vsock", "--pcie-hotplug"],
            &["--pcie", "--pcie-vsock", "--cpu-overcommit"],
        ] {
            assert_eq!(parse(args), Err(ErrorKind::ArgumentConflict), "{args:?}");
        }
    }
}
