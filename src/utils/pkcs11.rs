// Copyright 2019-2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! PKCS#11 signing backend for EIF images.
//!
//! This lets an EIF be signed by a private key that lives on a hardware token
//! (e.g. a YubiKey PIV slot) instead of a PEM file on disk. The signing key is
//! selected with an RFC 7512 `pkcs11:` URI passed in place of the `--private-key`
//! path; the token's PKCS#11 module (`.so`) is located via the URI's `module-path`
//! attribute or the `NITRO_CLI_PKCS11_MODULE` environment variable and dlopen'd at
//! runtime, so there is no link-time dependency on any particular token library.
//!
//! EIF/PCR signing is ECDSA-only (COSE ES256/ES384/ES512); Nitro uses ES384 =
//! ECDSA P-384 + SHA-384. The token must therefore hold an EC key (secp384r1 for a
//! stock Nitro setup). Only the private-key operation runs on the token: COSE hands
//! `SigningPrivateKey::sign` the already-hashed digest, and PKCS#11 `C_Sign` with
//! `CKM_ECDSA` returns the raw `R||S` pair that COSE expects verbatim. Public-key
//! parameters and verification are served from the signing certificate, so no public
//! object has to be read back from the token.

use aws_nitro_enclaves_cose::crypto::{
    MessageDigest, SignatureAlgorithm, SigningPrivateKey, SigningPublicKey,
};
use aws_nitro_enclaves_cose::error::CoseError;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use openssl::pkey::{PKey, Public};
use openssl::x509::X509;

/// Environment variable naming the PKCS#11 module (`.so`) when the `pkcs11:` URI does
/// not carry a `module-path` attribute.
const MODULE_ENV: &str = "NITRO_CLI_PKCS11_MODULE";
/// Environment variable holding the token PIN when the URI has no `pin-value`.
const PIN_ENV: &str = "NITRO_CLI_PKCS11_PIN";

/// Parsed subset of an RFC 7512 `pkcs11:` URI plus the resolved module path/PIN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pkcs11Uri {
    /// PKCS#11 module shared object to load (from `module-path` or `MODULE_ENV`).
    pub module_path: String,
    /// CKA_ID of the private key object (from `id`), if given.
    pub key_id: Option<Vec<u8>>,
    /// CKA_LABEL of the private key object (from `object`), if given.
    pub key_label: Option<String>,
    /// Token slot id (from `slot-id`), if given; otherwise the first slot with a token.
    pub slot_id: Option<u64>,
    /// User PIN (from `pin-value` or `PIN_ENV`), if any.
    pub pin: Option<String>,
}

impl Pkcs11Uri {
    /// Parse a `pkcs11:` URI, resolving the module path and PIN from the environment
    /// when they are not present as URI attributes.
    pub fn parse(uri: &str) -> Result<Self, String> {
        let rest = uri
            .strip_prefix("pkcs11:")
            .ok_or_else(|| format!("not a pkcs11 URI: {uri:?}"))?;

        // RFC 7512: path attributes (';'-separated) then optional query ('?') with
        // '&'-separated attributes. We read from both into one lookup.
        let (path_part, query_part) = match rest.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (rest, None),
        };

        let mut key_id = None;
        let mut key_label = None;
        let mut slot_id = None;
        let mut module_path = None;
        let mut pin = None;

        let path_attrs = path_part.split(';').filter(|s| !s.is_empty());
        let query_attrs = query_part
            .into_iter()
            .flat_map(|q| q.split('&'))
            .filter(|s| !s.is_empty());

        for attr in path_attrs.chain(query_attrs) {
            let (k, v) = attr
                .split_once('=')
                .ok_or_else(|| format!("malformed pkcs11 URI attribute: {attr:?}"))?;
            match k {
                "id" => key_id = Some(percent_decode(v)?),
                "object" => key_label = Some(String::from_utf8(percent_decode(v)?).map_err(|e| {
                    format!("pkcs11 URI 'object' is not valid UTF-8: {e}")
                })?),
                "slot-id" => {
                    slot_id = Some(v.parse::<u64>().map_err(|e| {
                        format!("pkcs11 URI 'slot-id' is not a number: {e}")
                    })?)
                }
                "module-path" => module_path = Some(percent_decode_str(v)?),
                "pin-value" => pin = Some(percent_decode_str(v)?),
                // Ignore attributes we don't act on (token, manufacturer, type, ...).
                _ => {}
            }
        }

        let module_path = module_path
            .or_else(|| std::env::var(MODULE_ENV).ok())
            .ok_or_else(|| {
                format!(
                    "no PKCS#11 module: set a 'module-path' in the URI or the {MODULE_ENV} \
                     environment variable"
                )
            })?;
        let pin = pin.or_else(|| std::env::var(PIN_ENV).ok());

        Ok(Pkcs11Uri {
            module_path,
            key_id,
            key_label,
            slot_id,
            pin,
        })
    }
}

/// Percent-decode an RFC 7512 attribute value into raw bytes.
fn percent_decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .ok_or_else(|| format!("truncated percent-escape in {s:?}"))?;
                let hi = hex_val(hex[0])?;
                let lo = hex_val(hex[1])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Percent-decode into a UTF-8 string (for module paths and PINs).
fn percent_decode_str(s: &str) -> Result<String, String> {
    String::from_utf8(percent_decode(s)?)
        .map_err(|e| format!("percent-decoded value is not valid UTF-8: {e}"))
}

fn hex_val(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex digit {:?} in percent-escape", c as char)),
    }
}

/// A signing key held on a PKCS#11 token, selected by a `pkcs11:` URI. The private
/// operation runs on the token; parameters/verification use the certificate's public
/// key (`pub_key`), so this implements the COSE signing traits directly.
pub struct Pkcs11Key {
    uri: Pkcs11Uri,
    pub_key: PKey<Public>,
}

impl Pkcs11Key {
    /// Build a signer from a `pkcs11:` URI and the PEM signing certificate whose public
    /// key pairs with the token key.
    pub fn new(uri: &str, cert_pem: &[u8]) -> Result<Self, String> {
        let uri = Pkcs11Uri::parse(uri)?;
        let cert = X509::from_pem(cert_pem)
            .map_err(|e| format!("Failed to parse signing certificate: {e}"))?;
        let pub_key = cert
            .public_key()
            .map_err(|e| format!("Failed to read public key from certificate: {e}"))?;
        // Fail early on a non-EC or unsupported-curve certificate rather than at sign time.
        pub_key
            .get_parameters()
            .map_err(|e| format!("Signing certificate key is unusable for EIF signing: {e}"))?;
        Ok(Pkcs11Key { uri, pub_key })
    }

    /// Open a session, log in, locate the private key described by the URI, and run
    /// `CKM_ECDSA` over `digest`. The whole operation is kept in one scope so the
    /// PKCS#11 context outlives the session it owns.
    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, String> {
        let pkcs11 = Pkcs11::new(self.uri.module_path.as_str()).map_err(|e| {
            format!("Failed to load PKCS#11 module {:?}: {e}", self.uri.module_path)
        })?;
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(|e| format!("Failed to initialize PKCS#11 module: {e}"))?;

        let slots = pkcs11
            .get_slots_with_token()
            .map_err(|e| format!("Failed to enumerate PKCS#11 slots: {e}"))?;
        let slot = match self.uri.slot_id {
            Some(id) => slots
                .into_iter()
                .find(|s| s.id() == id)
                .ok_or_else(|| format!("no PKCS#11 slot with id {id}"))?,
            None => slots
                .into_iter()
                .next()
                .ok_or_else(|| "no PKCS#11 slot with a token present".to_string())?,
        };

        let session = pkcs11
            .open_ro_session(slot)
            .map_err(|e| format!("Failed to open PKCS#11 session: {e}"))?;
        if let Some(pin) = &self.uri.pin {
            session
                .login(UserType::User, Some(&AuthPin::new(pin.clone())))
                .map_err(|e| format!("PKCS#11 login failed: {e}"))?;
        }

        let mut template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
        if let Some(id) = &self.uri.key_id {
            template.push(Attribute::Id(id.clone()));
        }
        if let Some(label) = &self.uri.key_label {
            template.push(Attribute::Label(label.clone().into_bytes()));
        }
        let key = session
            .find_objects(&template)
            .map_err(|e| format!("Failed to search for PKCS#11 private key: {e}"))?
            .into_iter()
            .next()
            .ok_or_else(|| "no matching PKCS#11 private key found for the URI".to_string())?;

        // CKM_ECDSA signs a pre-computed digest (COSE already hashed the payload) and
        // returns the raw fixed-length R||S concatenation COSE expects.
        session
            .sign(&Mechanism::Ecdsa, key, digest)
            .map_err(|e| format!("PKCS#11 signing failed: {e}"))
    }
}

impl SigningPublicKey for Pkcs11Key {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        self.pub_key.get_parameters()
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        self.pub_key.verify(digest, signature)
    }
}

impl SigningPrivateKey for Pkcs11Key {
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
        self.sign_digest(digest)
            .map_err(|e| CoseError::SignatureError(e.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("%01").unwrap(), vec![0x01]);
        assert_eq!(percent_decode("%03%ab").unwrap(), vec![0x03, 0xab]);
        assert_eq!(percent_decode("abc").unwrap(), b"abc".to_vec());
        assert!(percent_decode("%0").is_err()); // truncated
        assert!(percent_decode("%zz").is_err()); // bad hex
    }

    #[test]
    fn test_parse_uri_full() {
        let uri = "pkcs11:id=%03;object=eif-signer;slot-id=0?module-path=/usr/lib/libykcs11.so&pin-value=123456";
        let p = Pkcs11Uri::parse(uri).unwrap();
        assert_eq!(p.key_id, Some(vec![0x03]));
        assert_eq!(p.key_label.as_deref(), Some("eif-signer"));
        assert_eq!(p.slot_id, Some(0));
        assert_eq!(p.module_path, "/usr/lib/libykcs11.so");
        assert_eq!(p.pin.as_deref(), Some("123456"));
    }

    #[test]
    fn test_parse_uri_module_from_env() {
        // MODULE_ENV is process-global; keep every set/remove of it in this single test
        // so it can't race with another parallel test reading the same variable.
        std::env::remove_var(MODULE_ENV);
        // With no module-path in the URI and the env var unset, parsing must fail.
        assert!(Pkcs11Uri::parse("pkcs11:id=%01").is_err());
        // With the env var set, the module path is taken from it.
        std::env::set_var(MODULE_ENV, "/opt/libykcs11.so");
        let p = Pkcs11Uri::parse("pkcs11:id=%01").unwrap();
        assert_eq!(p.module_path, "/opt/libykcs11.so");
        assert_eq!(p.key_id, Some(vec![0x01]));
        assert_eq!(p.slot_id, None);
        std::env::remove_var(MODULE_ENV);
    }

    #[test]
    fn test_parse_uri_rejects_non_pkcs11() {
        assert!(Pkcs11Uri::parse("/path/to/key.pem").is_err());
    }
}
