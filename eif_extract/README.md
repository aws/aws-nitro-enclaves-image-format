## eif\_extract

[![status]][actions] [![version]][crates.io] [![docs]][docs.rs] ![msrv]

[status]: https://img.shields.io/github/actions/workflow/status/aws/aws-nitro-enclaves-image-format/ci.yml?branch=main
[actions]: https://github.com/aws/aws-nitro-enclaves-image-format/actions?query=branch%3Amain
[version]: https://img.shields.io/crates/v/eif_extract.svg
[crates.io]: https://crates.io/crates/eif_extract
[docs]: https://img.shields.io/docsrs/eif_extract
[docs.rs]: https://docs.rs/eif_extract
[msrv]: https://img.shields.io/badge/MSRV-1.94.1-blue

This CLI tool extracts the sections of an enclave image format (EIF) file used in AWS Nitro Enclaves.
It is the counterpart of `eif_build`: the extracted files can be inspected (e.g. by container image scanners) or passed back to `eif_build` to assemble an image with the same measurements.

## Security

See [CONTRIBUTING](../CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

## Building

To compile the `eif_extract` tool, run

```sh
$ cargo build --all --release
```

The resulting binary will be under `./target/release/eif_extract`.

## Usage

```plain
Extracts the sections of an eif file

Usage: eif_extract --eif <FILE> --output-dir <DIR>

Options:
      --eif <FILE>        Sets path to the eif file to extract
      --output-dir <DIR>  Directory to extract the sections to. Existing files are not overwritten
  -h, --help              Print help
```

Sections are located through the offsets in the EIF header, the same way the Nitro hypervisor loads them, and are written to the output directory as:

| File                      | Section                                                          |
|---------------------------|------------------------------------------------------------------|
| `kernel`                  | `EifSectionKernel`                                               |
| `cmdline`                 | `EifSectionCmdline`                                              |
| `ramdisk0`, `ramdisk1`, … | `EifSectionRamdisk`, in image order                              |
| `metadata.json`           | `EifSectionMetadata`, as stored in the image                     |
| `custom_metadata.json`    | The `CustomMetadata` field of the metadata, if set               |
| `signature.cbor`          | `EifSectionSignature`, as stored in the image                    |
| `signing_certificate.pem` | The certificate of the PCR0 signature                            |

Ramdisks are `cpio` or `cpio.gz` archives and can be unpacked with e.g. `cpio -idm < ramdisk1` (after `gunzip`, if compressed).

After extraction, the `eif_build` command line that reassembles the image is printed:

```plain
$ eif_extract --eif enclave.eif --output-dir enclave
Extracted enclave.eif to enclave

To reassemble it, run:
eif_build --kernel enclave/kernel --cmdline 'reboot=k panic=30 console=ttyS0' --ramdisk enclave/ramdisk0 --ramdisk enclave/ramdisk1 --arch x86_64 --name enclave --version 1.0 --build-time 2026-01-01T00:00:00+00:00 --build-tool eif_build --build-tool-version 0.3.2 --img-os OS --img-kernel kernel --output <OUTPUT>
```

For unsigned images, the rebuilt image is identical to the original one.
Signed images get the same PCRs when rebuilt with the original private key, but a new signature.
`eif_build` does not set the `DockerInfo` metadata field, so images built by `nitro-cli` differ in their metadata section, which is not part of the PCRs.
