## aws-nitro-enclaves-image-format

[![status]][actions] [![version]][crates.io] [![docs]][docs.rs] ![msrv]

[status]: https://img.shields.io/github/actions/workflow/status/aws/aws-nitro-enclaves-image-format/ci.yml?branch=main
[actions]: https://github.com/aws/aws-nitro-enclaves-image-format/actions?query=branch%3Amain
[version]: https://img.shields.io/crates/v/aws-nitro-enclaves-image-format.svg
[crates.io]: https://crates.io/crates/aws-nitro-enclaves-image-format
[docs]: https://img.shields.io/docsrs/aws-nitro-enclaves-image-format
[docs.rs]: https://docs.rs/aws-nitro-enclaves-image-format
[msrv]: https://img.shields.io/badge/MSRV-1.71.1-blue

This library provides the definition of the enclave image format (EIF) file.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

## Enclave Image File (EIF) Specification

Date: 2024-06-21

### Background

AWS Nitro Enclaves ([Official documentation](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)) is an Amazon EC2 feature that allows you to create isolated compute environments, called enclaves, from Amazon EC2 instances.
Enclaves are separate, hardened, and highly-constrained virtual machines. They provide only secure local socket connectivity with their parent instance.
They have no persistent storage, interactive access, or external networking.

To run your application in an enclave, your application needs to be packaged into an Enclave Image File (EIF).
An EIF is self contained - everything your application needs to run within an enclave is part of the file (e.g. operating system, your application, root file system).

### The File Format

#### High Level Structure

On a high level an Enclave Image File consists of a general header and multiple data sections, each with their local header:

```
+-------------------------+
|        EifHeader        |
+-------------------------+
|   EifSectionHeader 0    |
+-------------------------+
|      Data Section 0     |
+-------------------------+
|   EifSectionHeader 1    |
+-------------------------+
|      Data Section 1     |
+-------------------------+
>          ...            <
+-------------------------+
|   EifSectionHeader n    |
+-------------------------+
|      Data Section n     |
+-------------------------+
```

The Enclave Image File format supports a variety of data section types. The data section types can be mandatory or optional.
Each section contains a specific type of data needed to run your application within a Nitro Enclave, the specifics of which are specified below in [Data sections](#data-sections).

#### `EifHeader`

The `EifHeader` is a general description of an enclave image file and provides metadata on the file as a whole.
It has a fixed size of 548 bytes and the byte-order for all multi-byte fields is big-endian. The `EifHeader` is structured as follows:

```
0x0000  +--------+--------+--------+--------+
        |               magic               |
0x0004  +--------+--------+--------+--------+
        |     version     |      flags      |
0x0008  +--------+--------+--------+--------+
        |                                   |
        +            default_mem            +
        |                                   |
0x0010  +--------+--------+--------+--------+
        |                                   |
        +            default_cpus           +
        |                                   |
0x0018  +--------+--------+--------+--------+
        |    reserved     |   num_sections  |
0x001c  +--------+--------+--------+--------+
        |                                   |
        +          section_offset 0         +
        |                                   |
        +--------+--------+--------+--------+
        >                ...                <
        +--------+--------+--------+--------+
        |                                   |
        +          section_offset 31        +
        |                                   |
0x011c  +--------+--------+--------+--------+
        |                                   |
        +           section_size 0          +
        |                                   |
        +--------+--------+--------+--------+
        >                ...                <
        +--------+--------+--------+--------+
        |                                   |
        +           section_size 31         +
        |                                   |
0x021c  +--------+--------+--------+--------+
        +             reserved              |
0x0220  +--------+--------+--------+--------+
        |              crc_32               |
0x0224  +--------+--------+--------+--------+
```

All reserved fields are ignored by the virtualization stack.

##### `magic`

The `magic` field is a constant value chosen to easily identify enclave image files.
The value equates to the ASCII string `.eif` or `[0x2e, 0x65, 0x69, 0x66]` as byte array.

##### `version`

The `version` field encodes the specification version of the enclave image file.
It is necessary to determine the file format version and chose the correct handling according to it.

The latest version of the EIF format is `4`.
The version gets incremented whenever a backwards incompatible change or addition to the file format is introduced.

###### EIF format version history:

* Version `0`: internal development version
* Version `1`: internal development version
* Version `2`: initial publicly released version as published in [aws-nitro-enclaves-cli v0.1.0](https://github.com/aws/aws-nitro-enclaves-cli/releases/tag/v0.1.0) (initial public pre-release) on 2020-08-13.
This initial version set the basic file format structure and supported the base section types `EifSectionKernel`, `EifSectionCmdline`, and `EifSectionRamdisk`.
* Version `3`: published in [aws-nitro-enclaves-cli v1.0.10](https://github.com/aws/aws-nitro-enclaves-cli/releases/tag/v1.0.10) (initial public production release) on 2021-04-29.
This version added optional support for image signing through section type `EifSectionSignature`.
* Version `4`: published in [aws-nitro-enclaves-cli v1.2.0](https://github.com/aws/aws-nitro-enclaves-cli/releases/tag/v1.2.0) on 2022-03-08.
This version added a new mandatory section type `EifSectionMetadata` containing metadata about the environment the EIF was built in.

*Versions `0` and `1` have not been published as part of any tooling release.
They are not supported anymore and will fail at the crc check stage of loading the enclave image file.*

*Versions `2` and `3` both behave the same way.
As the `EifSectionSignature` section type has not been defined in version `2` and is optional in version `3` they are effectively handled the same.*

*Version `4` introduced the `EifSectionMetadata` as a mandatory section and checks that it is part of an enclave image file.
Apart from that it is handled the same way as Version `3`.*

*Versions `>4` are reserved for the future and yield undefined behavior.*

##### `flags`

The `flags` bit-field encodes properties for the file and the environment the file is targeted for.
The structure of the flags field is as follows:

```
 f e d c b a 9 8 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             |a|
|                             |r|
|          reserved           |c|
|                             |h|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
* `arch`: determines the CPU architecture of the enclave this image file is for: `0` for `x86_64`, `1` for `aarch64`.
This flag is mandatory and an EIF with an architecture other than the architecture of the enclave will be rejected.

##### `default_mem`

The `default_mem` field describes the default amount of main memory in bytes for the enclave this image is going to run on.
Currently this field is unused by the virtualization stack and [aws-nitro-enclaves-cli](https://github.com/aws/aws-nitro-enclaves-cli).

##### `default_cpus`

The `default_cpus` field describes the default number of vCPUs for the enclave this image is going to run on.
Currently this field is unused by the virtualization stack and [aws-nitro-enclaves-cli](https://github.com/aws/aws-nitro-enclaves-cli).

##### `num_sections`

The `num_sections` field describes how many data sections an enclave image file contains.
The value range for this is between 2 and 32 (`MAX_NUM_SECTIONS`).

##### `section_offsets`

The `section_offsets` field is an array of 32 (`MAX_NUM_SECTIONS`) 8-byte values.
The first `num_secions` entries in this array each describe the position of one data section within the file in bytes from the file start.
All used entries have to be ordered in the same order as the corresponding data sections in the file,
meaning `section_offsets[0]` describes the file offset for the first data section in the file,
`section_offset[1]` describes the file offset for the second data section in the file and so on.

##### `section_sizes`

The `section_sizes` field is an array of 32 (`MAX_NUM_SECTIONS`) 8-byte values.
The first `num_sections` entries in this array each describe the size of one data section within the file in bytes.
All used entries have to be ordered in the same order as the corresponding data sections in the file,
meaning `section_sizes[0]` describes the size of the first data section in the file,
`section_sizes[1]`  describes the size of the second data section in the file and so on.
The `section sizes` as set in this array only cover the size of the data in a section and do not include the size of section headers.

##### `eif_crc32`

The `eif_crc32` field contains the crc32 checksum over the whole file except this `eif_crc32` field itself;
this checksum includes `EifHeader` and all sections, including their respective section headers, in the order they appear in the file.

#### Data sections

An enclave image file contains multiple data sections of different types, each with a distinct purpose.
The high level format is common between all section types, consisting of an `EifSectionHeader` and binary data.
Sections cannot overlap each other and must not overflow out of 64-bit address space.

The ordering of the different section types within one enclave image file is mostly unconstrained.
The only constraint on ordering the sections is that all `EifSectionRamdisk` sections must be located after the `EifSectionKernel` section.

##### `EifSectionHeader`

The section header is a basic description of a section:

```
0x0000  +--------+--------+--------+--------+
        |  section_type   |      flags      |
0x0004  +--------+--------+--------+--------+
        |                                   |
        +           section_size            +
        |                                   |
0x000c  +--------+--------+--------+--------+
```

###### `section_type`

The `section_type` field describes the kind of section.
The following is a list of valid section types and their numeric value.
A detailed description of each section type follows below.

* `EifSectionInvalid (0x00)`
* `EifSectionKernel (0x01)`
* `EifSectionCmdline (0x02)`
* `EifSectionRamdisk (0x03)`
* `EifSectionSignature (0x04)` (introduced in version 3 of the EIF format)
* `EifSectionMetadata (0x05)` (introduced in version 4 of the EIF format)

Enclave image files containing an `EifSectionInvalid` section or sections with a type outside of the above range (`>= 6`) will be rejected by the virtualization stack.

###### `flags`

The `flags` bit-field can be used to encode properties of the binary data in a section.
It is currently not used by any section type and is reserved for future use.

###### `section_size`

The `section_size` field describes the size in bytes of the sections data.
It must match the corresponding section_sizes entry in the global EifHeader structure.

##### `EifSectionKernel`

The `EifSectionKernel` section data contains a Linux kernel image to be run within the enclave.
The file format for that depends on the CPU architecture of your instance and its enclave.
For `x86_64` instances the kernel section data has to be a `bzImage` (Refer to the [`x86_64` boot protocol for details](https://www.kernel.org/doc/Documentation/x86/boot.txt)).
For `aarch64` instances the kernel section data has to be an uncompressed kernel `Image` file (Refer to the [`arm64` boot protocol for details](https://www.kernel.org/doc/Documentation/arm64/booting.txt)).

The [aws-nitro-enclaves-cli](https://github.com/aws/aws-nitro-enclaves-cli) provides pre-built kernel images for both architectures:
* `x86_64`: [`blobs/x86_64/bzImage`](https://github.com/aws/aws-nitro-enclaves-cli/blob/main/blobs/x86_64/bzImage)
* `aarch64`: [`blobs/aarch64/Image`](https://github.com/aws/aws-nitro-enclaves-cli/blob/main/blobs/aarch64/Image)

`EifSectionKernel` section is a mandatory section and every enclave image file must contain exactly one `EifSectionKernel` section.

##### `EifSectionCmdline`

The `EifSectionCmdline` section data contains a string with Linux kernel cmdline parameters for the enclave kernel.
The kernel cmdline can be used to configure certain aspects of the kernel at boot time ([Documentation of kernel-parameters](https://www.kernel.org/doc/Documentation/admin-guide/kernel-parameters.txt)).

The [aws-nitro-enclaves-cli](https://github.com/aws/aws-nitro-enclaves-cli) provides kernel cmdlines for both architectures (compatible with the pre-built kernel images in the same location):
* `x86_64`: [`blobs/x86_64/cmdline`](https://github.com/aws/aws-nitro-enclaves-cli/blob/main/blobs/x86_64/cmdline)
* `aarch64`: [`blobs/aarch64/cmdline`](https://github.com/aws/aws-nitro-enclaves-cli/blob/main/blobs/aarch64/cmdline)

`EifSectionCmdline` section is a mandatory section and every enclave image file must contain exactly one `EifSectionCmdline` section.

##### `EifSectionRamdisk`

The `EifSectionRamdisk` section contains data that is going to be part of the root file system of the enclave in `cpio` or `cpio.gz` (compressed) format.
All data of `EifSectionRamdisk` sections are concatenated to act together as one `initramfs` (See [Background on ramdisk composition and loading](#background-on-ramdisk-composition-and-loading) below).

All `EifSectionRamdisk` sections must be positioned after the `EifSectionKernel` section within an enclave image file.

###### Example: ramdisks created with [aws-nitro-enclaves-cli](https://github.com/aws/aws-nitro-enclaves-cli)

When creating an enclave image file through the [aws-nitro-enclaves-cli](https://github.com/aws/aws-nitro-enclaves-cli), two `EifSectionRamdisk` sections are created.
The first ramdisk is the same for all applications and contains two main parts:

* **An init executable:** The init process is the first user-space process started by the kernel.
The task of the init process is to bring up the systems user-space and start relevant services.
For Nitro Enclaves, the init processes tasks are reduced to the bare minimum of mounting special filesystems and files (i.e. procfs, sysfs, /dev), initializing the console device, loading the driver to interact with the Nitro Security Module, and launching the user application.
The code for the minimal init process can be found in [aws-nitro-enclaves-sdk-bootstrap](https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap/blob/main/init/init.c),
and the [aws-nitro-enclaves-cli](https://github.com/aws/aws-nitro-enclaves-cli) provides pre-compiled executables of it for both architectures:
  * `x86_64`: [`blobs/x86_64/init`](https://github.com/aws/aws-nitro-enclaves-cli/blob/main/blobs/x86_64/init)
  * `aarch64`: [`blobs/aarch64/init`](https://github.com/aws/aws-nitro-enclaves-cli/blob/main/blobs/aarch64/init)
* **The `nsm.ko` driver:** This is a loadable driver module for the Linux kernel which facilitates access to the Nitro Secure Module (NSM).
The driver exposes a special device in the enclave to communicate with the hypervisor to retrieve an attestation document, which can be used to prove the identity of the enclave.
The source code for the NSM driver can be found in [aws-nitro-enclaves-sdk-bootstrap](https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap/tree/main/nsm-driver),
starting with Linux kernel series v6.8 the driver is part of the upstream Linux kernel.
The [aws-nitro-enclaves-cli](https://github.com/aws/aws-nitro-enclaves-cli) provides pre-compiled versions of this driver for both architectures (compatible with the pre-built kernel images in the same location):
  * `x86_64`: [`blobs/x86_64/nsm.ko`](https://github.com/aws/aws-nitro-enclaves-cli/blob/main/blobs/x86_64/nsm.ko)
  * `aarch64`: [`blobs/aarch64/nsm.ko`](https://github.com/aws/aws-nitro-enclaves-cli/blob/main/blobs/aarch64/nsm.ko)

The second ramdisk contains the application specific data and has three major parts:

* **The root file system:** This is a filesystem providing all the software and runtime environment needed by the application as shipped in the applications docker image.
* **`cmd` file:** The `cmd` file contains the default entry point of the application as specified in the Dockerfile through `CMD` (or `ENTRYPOINT` if `CMD` is not specified).
* **`env` file:** The `env` file contains the environment variables of the application as specified in the Dockerfile through `ENV`.

###### Background on ramdisk composition and loading

The Linux kernel supports various models of booting a system and bringing up user-space.
One mechanism is through the Linux kernel’s `initramfs` format (See [Linux kernel documentation `driver-api/early-userspace/buffer-format.rst`](https://www.kernel.org/doc/Documentation/driver-api/early-userspace/buffer-format.rst)).
An `initramfs` consists of a collection of `cpio` files, either uncompressed (`.cpio`) or compressed (`.cpio.gz`).
The Linux kernel contains a minimal interpreter for these files to load `initramfs` and construct the root file system from them.
The `initramfs` usually contains a basic user-space to bootstrap a system and bring up additional devices like hard disks to switch to the final file system from disk.
In the case of Nitro Enclaves, there is no support for persistent storage like hard disks, so the whole system is booted from and contained in the initramfs.

For Nitro Enclaves, no bootloader is employed to load the kernel and ramdisks into memory.
That part is performed by the hypervisor, which loads the kernel and ramdisk data into the enclaves memory before starting the enclave.
The resulting enclave memory on startup is populated as follows from the EIF (For an example EIF with three ramdisk sections):

```
                                                        Enclave Memory Layout
+-------------------------+                             +--------------------+
|        EifHeader        |                             |       zeroes       | 0x0
+-------------------------+                             >         ...        <
|   EifSectionHeader 0    |                             |                    |
+-------------------------+>--------------------------->+--------------------+
|      Kernel Image       |                             |    Kernel Image    |
+-------------------------+   +------------------------>+--------------------+ --+
|   EifSectionHeader 1    |   |                         |   Ramdisk (init)   |   |
+-------------------------+   |   +-------------------->+--------------------+   |
|      Kernel Cmdline     |   |   |                     |   Ramdisk (user0)  |    > initramfs
+-------------------------+   |   |   +---------------->+--------------------+   |
|   EifSectionHeader 2    |   |   |   |                 |   Ramdisk (user1)  |   |
+-------------------------+>--+   |   |                 +--------------------+ --
|      Ramdisk (init)     |       |   |                 |                    |
+-------------------------+       |   |                 |       zeroes       |
|   EifSectionHeader 3    |       |   |                 >        ...         <
+-------------------------+>------+   |                 |                    | 0xffffffffffffffff
|      Ramdisk (user0)    |           |                 +--------------------+
+-------------------------+           |
|   EifSectionHeader 4    |           |
+-------------------------+>----------+
|      Ramdisk (user1)    |
+-------------------------+
|   EifSectionHeader 5    |
+-------------------------+
|      Signature Data     |
+-------------------------+
|   EifSectionHeader 6    |
+-------------------------+
|         Metadata        |
+-------------------------+
```

##### `EifSectionSignature`

The `EifSectionSignature` section was introduced as an optional section in file format version 3.
The section data has a maximum size of 32768 bytes (`SIGNATURE_MAX_SIZE`).

The data format for the `EifSectionSignature` section is Concise Binary Object Representation (CBOR) as introduced in [RFC8949](https://datatracker.ietf.org/doc/html/rfc8949).
The CBOR data contains an array of two-tuples, each containing a serialized signing certificate and a serialized CBOR Object Signing and Encryption (COSE) Sign1 object as described in [RFC8152](https://datatracker.ietf.org/doc/html/rfc8152).
Although the `EifSectionSignature` section allows for multiple such tuples, only the first of these objects is currently verified against PCR0.
This means the only relevant data to sign and add to the `EifSectionSignature` section is the tuple `(0, PCR0)`.

The overall structure of the CBOR data in `EifSectionSignature` can be described as follows, where `>>>>` and `<<<<` describe entry and exit boundaries of nested serialized CBOR data:

```
Array(1) {
    Map(2) {
        [0] {
            Text(19)                                                 // key = "signing_certificate"
            Array<Uint8>(len(cbor_serialize(cert)))                  // value = CBOR serialized certificate
        },
        [1] {
            Text(9)                                                  // key = "signature"
            Array<Uint8>(len(cbor_serialize(cose_sign1))             // value = CBOR serialized COSE_Sign1 object
            >>>>
                Array(4) {
                    [0] ByteString(len(cbor_serialize(protected))),  // CBOR serialized COSE protected header
                    >>>>
                        Map(1) {
                            unsigned(1)                              // key = 1 (alg)
                            negative(<val>)                          // value = Signing Algorithm (-7 for ES256, -35 for ES384, -36 for ES512)
                        }
                    <<<<
                    [1] Map(0),                                      // CBOR serialized COSE unprotected header (empty)
                    [2] BytesString(len(cbor_serialize(payload))),   // CBOR serialized COSE_Sign1 payload
                    >>>>
                        Map(2) {
                            [0] {
                                Text(14)                             // key = "register_index"
                                Unsigned(<idx>)                      // value = <idx> (Index of which PCR got signed)
                            },
                            [1] {
                                Text(14)                             // key = "register_value"
                                Array<Uint8>(48)                     // value = PCR<idx> value bytes
                            },
                        }
                    <<<<
                    [3] BytesString(len(<signature>))                // Signature bytes
                }
            <<<<
        }
    }
}
```

###### Background on COSE Sign1 and usage in EIF

COSE Sign1 provides a signature structure to have a message signed by a single signer:

```
+-------------------------+-----------------+-------------------+
|      COSE Headers       |     Payload     |     Signature     |
+- - - - - - - - - - - - -+- - - - - - - - -+- - - - - - - - - -+
| protected | unprotected |    plaintext    |  signature bytes  |
+-------------------------+-----------------+-------------------+
```

The COSE Headers are divided into two buckets, the protected bucket contains metadata for the signature layer that is part of the data being signed (covered/protected by the signature),
while the unprotected bucket contains metadata that does not contribute towards the signature.
Each bucket is a map of key-value pairs. The payload is the plaintext data that is being signed.
The signature contains the signature bytes.

For the usage in EIF the data contained in the different parts of the COSE Sign1 object is as follows:

* The protected bucket of COSE Headers only contains one key-value pair identifying the used signature algorithm.
* The unprotected bucket of COSE Headers is empty.
* The payload contains a tuple describing one platform configuration register (PCR) for the EIF file, specifically a two-tuple containing the PCRs index and it’s value.
(More details on PCRs can be found below in section [EIF Measurements](#eif-measurements)).
* The Signature contains an Elliptic Curve Digital Signature Algorithm (ECDSA) signature of the protected headers and payload with one of the following ECDSA variants: ES256, ES384, and ES512.

##### `EifSectionMetadata`

The `EifSectionMetadata` section was introduced as a mandatory section in file format version 4.
The section data contains JSON describing the build environment that produced the enclave image file according to the following JSON schema:

```
{
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://github.com/aws/aws-nitro-enclaves-image-format",
    "title": "EIF Metadata Content",
    "description": "Format Content of EIFSection of type EifSectionMetadata",
    "type": "object",
    "properties": {
        "ImageName": {
            "type": "string",
            "description": "Name of the EIF image"
        },
        "ImageVersion": {
            "type": "string",
            "description": "EIF version for this image file"
        },
        "BuildMetadata": {
            "type": "object",
            "description": "Metadata on the build environment",
            "properties": {
                "BuildTime": {
                    "type": "string",
                    "description": "Time the image was build at"
                },
                "BuildTool": {
                    "type": "string",
                    "description": "Name of the tool that produced the image"
                },
                "BuildToolVersion": {
                    "type": "string",
                    "description": "Version of the tool that produced the image"
                },
                "OperatingSystem": {
                    "type": "string",
                    "description": "Name of the OS the image was build on"
                },
                "KernelVersion": {
                    "type": "string",
                    "description": "Kernel version of the build host"
                }
            },
            "required": [ "BuildTime", "BuildTool", "BuildToolVersion", "OperatingSystem", "KernelVersion" ]
        },
        "DockerInfo": {
            "type": "object",
            "description": "Metadata on the docker image this EIF was based on, as produced by `docker image inspect`"
        },
        "CustomMetadata": {
            "type": "object",
            "description": "Optional custom metadata to annotate the EIF with"
        }
    },
    "required": [ "ImageName", "ImageVersion", "BuildMetadata", "DockerInfo" ]
}
```

The `EifSectionMetadata` section is not part of any measurement for an enclave and does not get validated by the hypervisor, beyond checking for its existence with file format version 4 and above.

### EIF Measurements

Nitro Enclaves includes attestation mechanisms to prove its identity and build trust with external services.
As part of these measurements the enclave exposes a set of platform configuration registers (PCRs), each providing a set of hashes over some identifying data for the enclaves configuration and code.
For the EIF files, there are four PCRs that describe it. They are `PCR0`, `PCR1`, `PCR2`, and `PCR8`:

```
PCR0                                  PCR1  PCR2  PCR8*
  |     +-------------------------+     |     |     |
  |     |        EifHeader        |     |     |     |
  |     +-------------------------+     |     |     |
  |     |   EifSectionHeader 0    |     |     |     |
  |     +-------------------------+     |     |     |
  +----<|      Kernel Image       |>----+     |     |
  |     +-------------------------+     |     |     |
  |     |   EifSectionHeader 1    |     |     |     |
  |     +-------------------------+     |     |     |
  +----<|      Kernel Cmdline     |>----+     |     |
  |     +-------------------------+     |     |     |
  |     |   EifSectionHeader 2    |     |     |     |
  |     +-------------------------+     |     |     |
  +----<|      Ramdisk (init)     |>----+     |     |
  |     +-------------------------+           |     |
  |     |   EifSectionHeader 3    |           |     |
  |     +-------------------------+           |     |
  +----<|     Ramdisk (user0)     |>----------+     |
  |     +-------------------------+           |     |
  |     |   EifSectionHeader 4    |           |     |
  |     +-------------------------+           |     |
  +----<|     Ramdisk (user1)     |>----------+     |
        +-------------------------+                 |
        |   EifSectionHeader 5    |                 |
        +-------------------------+                 |
        |      Signature Data     |>----------------+
        +-------------------------+
        |   EifSectionHeader 6    |
        +-------------------------+
        |         Metadata        |
        +-------------------------+
```

All EIF specific PCRs are calculated in a multi-level scheme containing a fixed initial state and a digest over specific parts of the EIF.
They are calculated as the sha384 message digest (described in [RFC6234](https://datatracker.ietf.org/doc/html/rfc6234)) over the concatenation of the `initial_digest` and the `content_digest`:

```
PCRX = sha384sum( initial_digest.content_digest )
```

The `initial_digest` is the same for all PCRs and consists of 48 zero-bytes.
The `content_digest` contains data on different parts of an EIF depending on the PCR.

#### `PCR0`

`PCR0` contains a measurement of all the data influencing the runtime of code in an EIF.
It includes a sha384 message digest over the contiguous data of the `EifSectionKernel`, `EifSectionCmdline`, and all `EifSectionRamdisk` sections in the order they are present in the enclave image file.
For `PCR0` this means `content_digest` is calculated as follows:

```
content_digest[PCR0] = sha384sum( data(EifSectionKernel).data(EifSectionCmdline).data(EifSectionRamdisk[..]) )
```

*Note: The order of elements in that calculation depends on the order of sections in the EIF.
Only the data for each section is part of the calculation, the headers are excluded.*

#### `PCR1`

`PCR1` contains a measurement of all the data influencing the bootstrap and kernel in an EIF.
It includes a sha384 message digest over the contiguous data of the `EifSectionKernel`, `EifSectionCmdline`, and the first `EifSectionRamdisk` sections in the order they are present in the enclave image file.
For `PCR1` this means `content_digest` is calculated as follows:

```
content_digest[PCR1] = sha384sum( data(EifSectionKernel).data(EifSectionCmdline).data(EifSectionRamdiks[0]) )
```

*Note: The order of elements in that calculation depends on the order of sections in the EIF.
Only the data for each section is part of the calculation, the headers are excluded.*

#### `PCR2`

`PCR2` contains a measurement of the user application in an EIF.
It includes a sha384 message digest over the contiguous data of all `EifSectionRamdisk` sections excluding the first `EifSectionRamdisk` section in the order they are present in the enclave image file.
For `PCR2` this means `content_digest` is calculated as follows:

```
content_digest[PCR2] = sha384sum( data(EifSectionRamdisk[1..]) )
```

*Note: The order of elements in that calculation depends on the order of sections in the EIF.
Only the data for each section is part of the calculation, the headers are excluded.*

#### `PCR8`

`PCR8` is populated only if an `EifSectionSignature` section is part of the enclave image file.
In that case `PCR8` contains a measurement over the DER representation of the certificate used to sign `PCR0` and contained in `EifSectionSignature`.
For `PCR8` this means `content_digest` is calculated as follows:

```
content_digest[PCR8] = sha384sum( signing_certificate_in_DER )
