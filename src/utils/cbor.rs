// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! CBOR encoding for the EIF signature section and the signed PCR payload.

use serde::de::DeserializeOwned;
use serde::Serialize;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Serialize `value` to CBOR.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

/// Deserialize a value from CBOR. Trailing bytes are an error.
pub fn from_slice<T: DeserializeOwned>(mut bytes: &[u8]) -> Result<T, Error> {
    let value = ciborium::from_reader(&mut bytes)?;
    if !bytes.is_empty() {
        return Err(format!("{} trailing byte(s) after CBOR value", bytes.len()).into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defs::{PcrInfo, PcrSignature};

    // Bytes as written by serde_cbor 0.11, the encoder used up to 0.8.0.
    // PcrInfo { register_index: 0, register_value: 0x00..=0x2f }
    const PCR_INFO_0_8_0: &str = "a26e72656769737465725f696e646578006e72656769737465725f76616c75659830000102030405060708090a0b0c0d0e0f101112131415161718181819181a181b181c181d181e181f1820182118221823182418251826182718281829182a182b182c182d182e182f";
    // vec![PcrSignature { signing_certificate: b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    //                     signature: [0xd2, 0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0, 0x40, 0x40] }]
    const SIGNATURE_0_8_0: &str = "81a2737369676e696e675f6365727469666963617465983b182d182d182d182d182d1842184518471849184e182018431845185218541849184618491843184118541845182d182d182d182d182d0a184d1849184918420a182d182d182d182d182d1845184e1844182018431845185218541849184618491843184118541845182d182d182d182d182d0a697369676e61747572658a18d21884184418a1011838182218a018401840";

    #[test]
    fn pcr_info_bytes_match_0_8_0() {
        let pcr_info = PcrInfo::new(0, (0u8..48).collect());
        assert_eq!(hex::encode(to_vec(&pcr_info).unwrap()), PCR_INFO_0_8_0);
    }

    #[test]
    fn signature_section_bytes_match_0_8_0() {
        let section = vec![PcrSignature {
            signing_certificate: b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
                .to_vec(),
            signature: vec![0xd2, 0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0, 0x40, 0x40],
        }];
        assert_eq!(hex::encode(to_vec(&section).unwrap()), SIGNATURE_0_8_0);
    }

    #[test]
    fn reads_0_8_0_signature_section() {
        let bytes = hex::decode(SIGNATURE_0_8_0).unwrap();
        let section: Vec<PcrSignature> = from_slice(&bytes).unwrap();
        assert_eq!(section.len(), 1);
        assert!(section[0].signing_certificate.starts_with(b"-----BEGIN"));
        assert_eq!(section[0].signature.len(), 10);
    }

    #[test]
    fn round_trip() {
        let pcr_info = PcrInfo::new(3, vec![0xab; 48]);
        let decoded: PcrInfo = from_slice(&to_vec(&pcr_info).unwrap()).unwrap();
        assert_eq!(decoded.register_index, 3);
        assert_eq!(decoded.register_value, vec![0xab; 48]);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = hex::decode(PCR_INFO_0_8_0).unwrap();
        bytes.push(0x00);
        assert!(from_slice::<PcrInfo>(&bytes).is_err());
    }
}
