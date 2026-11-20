## eif\_build

[![status]][actions] [![version]][crates.io] [![docs]][docs.rs] ![msrv]

[status]: https://img.shields.io/github/actions/workflow/status/aws/aws-nitro-enclaves-image-format/ci.yml?branch=main
[actions]: https://github.com/aws/aws-nitro-enclaves-image-format/actions?query=branch%3Amain
[version]: https://img.shields.io/crates/v/eif_build.svg
[crates.io]: https://crates.io/crates/eif_build
[docs]: https://img.shields.io/docsrs/eif_build
[docs.rs]: https://docs.rs/eif_build
[msrv]: https://img.shields.io/badge/MSRV-1.94.1-blue

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

        --pcie
            Set the PCIE matched flag, which every other matched flag needs.

        --pcie-vsock
            Set the PCIE_VSOCK matched flag (needs --pcie).

        --pcie-virtio
            Set the PCIE_VIRTIO matched flag (needs --pcie).

        --pcie-hotplug
            Set the PCIE_HOTPLUG matched flag (needs --pcie).

        --pcie-numa
            Set the PCIE_NUMA matched flag (needs --pcie).

        --cpu-overcommit
            Set the CPU_OVERCOMMIT matched flag (needs --pcie and --pcie-virtio).

        --cpu-accounting
            Set the CPU_ACCOUNTING matched flag (needs --pcie).

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
            Specify KMS key ARN, the path to the local private key file, or a PKCS#11 URI
            (see "Signing with a PKCS#11 token")

        --ramdisk <FILE>
            Sets path to a ramdisk file representing a cpio.gz archive

        --signing-certificate <signing-certificate>
            Specify the path to the signing certificate

        --version <image_version>
            Version of the enclave image

        --algo <(sha256|sha384|sha512)>
            Sets algorithm to measure the image [default: sha384]
```

## Signing with a PKCS#11 token

The signing key can live on a PKCS#11 token, such as a YubiKey or an HSM, instead of in a
file. This needs the `pkcs11` feature, which is off by default:

```sh
$ cargo build --all --release --features pkcs11
```

Pass an [RFC 7512](https://www.rfc-editor.org/rfc/rfc7512) `pkcs11:` URI as the private key:

```sh
$ eif_build ... \
    --signing-certificate cert.pem \
    --private-key 'pkcs11:serial=12345678;id=%03?module-path=/usr/lib/x86_64-linux-gnu/libykcs11.so'
```

The URI must select one token and one private key on it:

| Attribute | Selects |
| --- | --- |
| `token`, `manufacturer`, `serial`, `model`, `slot-id` | The token. If more than one token is present, these must narrow it down to one. |
| `id`, `object` | The private key, by its `CKA_ID` and `CKA_LABEL`. |
| `module-path` (query) | The PKCS#11 module to load. Falls back to the `NITRO_CLI_PKCS11_MODULE` environment variable. |
| `pin-value` (query) | The user PIN. Falls back to the `NITRO_CLI_PKCS11_PIN` environment variable. |

Other attributes are rejected. The key must be an EC key and must be the key of the signing
certificate, which is checked before anything is signed.
