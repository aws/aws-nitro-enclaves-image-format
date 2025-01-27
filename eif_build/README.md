## eif\_build

[![status]][actions] [![version]][crates.io] [![docs]][docs.rs] ![msrv]

[status]: https://img.shields.io/github/actions/workflow/status/aws/aws-nitro-enclaves-image-format/ci.yml?branch=main
[actions]: https://github.com/aws/aws-nitro-enclaves-image-format/actions?query=branch%3Amain
[version]: https://img.shields.io/crates/v/eif_build.svg
[crates.io]: https://crates.io/crates/eif_build
[docs]: https://img.shields.io/docsrs/eif_build
[docs.rs]: https://docs.rs/eif_build
[msrv]: https://img.shields.io/badge/MSRV-1.71.1-blue

This CLI tool provides a low level path to assemble an enclave image format (EIF) file used in AWS Nitro Enclaves.

## Security

See [CONTRIBUTING](../CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

## Building

To compile the `eif_build` tool, run

```sh
$ cargo build --all --release
```

The resulting binary will be under `./target/release/eif_build`.

## Usage

```plain
Enclave image format builder
Builds an eif file

USAGE:
    eif_build [OPTIONS] --kernel <FILE> --cmdline <String> --output <FILE> --ramdisk <FILE>

OPTIONS:
        --arch <(x86_64|aarch64)>
            Sets image architecture [default: x86_64]

        --build-time <build_time>
            Overrides image build time. [default: 2024-07-09T17:16:38.424202433+00:00]

        --build-tool <build_tool>
            Image build tool name. [default: eif_build]

        --build-tool-version <build_tool_version>
            Overrides image build tool version. [default: 0.2.0]

        --cmdline <String>
            Sets the cmdline

    -h, --help
            Print help information

        --img-kernel <img_kernel>
            Overrides image Operating System kernel version. [default: "Unknown version"]

        --img-os <img_os>
            Overrides image Operating System name. [default: "Generic Linux"]

        --kernel <FILE>
            Sets path to a bzImage/Image file for x86_64/aarch64 architecture

        --kernel_config <FILE>
            Sets path to a bzImage.config/Image.config file for x86_64/aarch64 architecture

        --metadata <metadata>
            Path to JSON containing the custom metadata provided by the user.

        --name <image_name>
            Name for enclave image

        --output <FILE>
            Specify output file path

        --private-key <private-key>
            Specify KMS key ARN, or the path to the local private key file

        --ramdisk <FILE>
            Sets path to a ramdisk file representing a cpio.gz archive

        --signing-certificate <signing-certificate>
            Specify the path to the signing certificate

        --version <image_version>
            Version of the enclave image

        --algo <(sha256|sha384|sha512)>
            Sets algorithm to measure the image [default: sha384]
```
