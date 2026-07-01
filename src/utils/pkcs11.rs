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
//! The URI must identify exactly one token and exactly one private key on it. The
//! token is matched on `slot-id`, `token`, `manufacturer`, `serial` and `model`, the
//! key on `id` and `object`. Attributes this module does not act on are rejected
//! rather than ignored, and the PIN is only ever sent to the one token that matched.
//!
//! EIF/PCR signing is ECDSA-only (COSE ES256/ES384/ES512); Nitro uses ES384 =
//! ECDSA P-384 + SHA-384. The token must therefore hold an EC key (secp384r1 for a
//! stock Nitro setup). Only the private-key operation runs on the token: COSE hands
//! `SigningPrivateKey::sign` the already-hashed digest, and PKCS#11 `C_Sign` with
//! `CKM_ECDSA` returns the raw `R||S` pair that COSE expects verbatim.
//!
//! The signature algorithm is taken from the signing certificate, so the token key
//! must be the certificate's key. That is checked when the key is loaded, by comparing
//! the certificate's public key with the token's public key object for the private key.
//! A token that does not expose that object cannot be checked up front; every signature
//! is therefore also verified against the certificate before it is returned.

use aws_nitro_enclaves_cose::crypto::{
    MessageDigest, SignatureAlgorithm, SigningPrivateKey, SigningPublicKey,
};
use aws_nitro_enclaves_cose::error::CoseError;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use openssl::bn::BigNumContext;
use openssl::ec::PointConversionForm;
use openssl::pkey::{PKey, Public};
use openssl::x509::X509;
use std::sync::Mutex;

/// Environment variable naming the PKCS#11 module (`.so`) when the `pkcs11:` URI does
/// not carry a `module-path` attribute.
const MODULE_ENV: &str = "NITRO_CLI_PKCS11_MODULE";
/// Environment variable holding the token PIN when the URI has no `pin-value`.
const PIN_ENV: &str = "NITRO_CLI_PKCS11_PIN";

/// Parsed subset of an RFC 7512 `pkcs11:` URI plus the resolved module path/PIN.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pkcs11Uri {
    /// PKCS#11 module shared object to load (from `module-path` or `MODULE_ENV`).
    pub module_path: String,
    /// CKA_ID of the private key object (from `id`), if given.
    pub key_id: Option<Vec<u8>>,
    /// CKA_LABEL of the private key object (from `object`), if given.
    pub key_label: Option<String>,
    /// Slot id the token must be in (from `slot-id`), if given.
    pub slot_id: Option<u64>,
    /// Token label (from `token`), if given.
    pub token_label: Option<String>,
    /// Token manufacturer (from `manufacturer`), if given.
    pub token_manufacturer: Option<String>,
    /// Token serial number (from `serial`), if given.
    pub token_serial: Option<String>,
    /// Token model (from `model`), if given.
    pub token_model: Option<String>,
    /// User PIN (from `pin-value` or `PIN_ENV`), if any.
    pub pin: Option<String>,
}

/// What `C_GetTokenInfo` reports about the token in a slot. The strings are stripped
/// of their blank padding, as RFC 7512 matching requires.
#[derive(Debug)]
struct TokenId<'a> {
    slot_id: u64,
    label: &'a str,
    manufacturer: &'a str,
    serial: &'a str,
    model: &'a str,
}

impl Pkcs11Uri {
    /// Parse a `pkcs11:` URI, resolving the module path and PIN from the environment
    /// when they are not present as URI attributes.
    pub fn parse(uri: &str) -> Result<Self, String> {
        let rest = uri
            .strip_prefix("pkcs11:")
            .ok_or_else(|| format!("not a pkcs11 URI: {uri:?}"))?;

        // RFC 7512: path attributes (';'-separated) then an optional query ('?') with
        // '&'-separated attributes.
        let (path_part, query_part) = match rest.split_once('?') {
            Some((p, q)) => (p, q),
            None => (rest, ""),
        };

        let mut parsed = Pkcs11Uri::default();
        let mut module_path = None;

        for attr in path_part.split(';').filter(|s| !s.is_empty()) {
            let (name, value) = split_attribute(attr)?;
            match name {
                "id" => set_once(&mut parsed.key_id, name, percent_decode(value)?)?,
                "object" => set_once(&mut parsed.key_label, name, decode_str(name, value)?)?,
                "type" => {
                    if value != "private" {
                        return Err(format!(
                            "pkcs11 URI 'type' must be 'private' to select a signing key, \
                             not {value:?}"
                        ));
                    }
                }
                "slot-id" => {
                    let id = value
                        .parse::<u64>()
                        .map_err(|e| format!("pkcs11 URI 'slot-id' is not a number: {e}"))?;
                    set_once(&mut parsed.slot_id, name, id)?
                }
                "token" => set_once(&mut parsed.token_label, name, decode_str(name, value)?)?,
                "manufacturer" => set_once(
                    &mut parsed.token_manufacturer,
                    name,
                    decode_str(name, value)?,
                )?,
                "serial" => set_once(&mut parsed.token_serial, name, decode_str(name, value)?)?,
                "model" => set_once(&mut parsed.token_model, name, decode_str(name, value)?)?,
                // An attribute that narrows the selection must not be dropped silently.
                _ => return Err(format!("unsupported pkcs11 URI attribute: {name:?}")),
            }
        }

        for attr in query_part.split('&').filter(|s| !s.is_empty()) {
            let (name, value) = split_attribute(attr)?;
            match name {
                "module-path" => set_once(&mut module_path, name, decode_str(name, value)?)?,
                "pin-value" => set_once(&mut parsed.pin, name, decode_str(name, value)?)?,
                _ => return Err(format!("unsupported pkcs11 URI query attribute: {name:?}")),
            }
        }

        parsed.module_path = module_path
            .or_else(|| std::env::var(MODULE_ENV).ok())
            .ok_or_else(|| {
                format!(
                    "no PKCS#11 module: set a 'module-path' in the URI or the {MODULE_ENV} \
                     environment variable"
                )
            })?;
        parsed.pin = parsed.pin.or_else(|| std::env::var(PIN_ENV).ok());

        Ok(parsed)
    }

    /// Whether every token attribute given in the URI matches `token`.
    fn matches_token(&self, token: &TokenId) -> bool {
        fn matches(wanted: &Option<String>, actual: &str) -> bool {
            wanted.as_deref().is_none_or(|w| w == actual)
        }

        self.slot_id.is_none_or(|id| id == token.slot_id)
            && matches(&self.token_label, token.label)
            && matches(&self.token_manufacturer, token.manufacturer)
            && matches(&self.token_serial, token.serial)
            && matches(&self.token_model, token.model)
    }
}

fn split_attribute(attr: &str) -> Result<(&str, &str), String> {
    attr.split_once('=')
        .ok_or_else(|| format!("malformed pkcs11 URI attribute: {attr:?}"))
}

/// Store an attribute value, rejecting a second occurrence of the same attribute.
fn set_once<T>(slot: &mut Option<T>, name: &str, value: T) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("pkcs11 URI attribute {name:?} is given twice"));
    }
    Ok(())
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

/// Percent-decode the value of attribute `name` into a UTF-8 string.
fn decode_str(name: &str, value: &str) -> Result<String, String> {
    String::from_utf8(percent_decode(value)?)
        .map_err(|e| format!("pkcs11 URI {name:?} is not valid UTF-8: {e}"))
}

fn hex_val(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!(
            "invalid hex digit {:?} in percent-escape",
            c as char
        )),
    }
}

/// Find the one slot whose token matches the URI. More than one match is an error:
/// picking one would send the PIN to, and sign with, a token the user did not name.
fn select_slot(pkcs11: &Pkcs11, uri: &Pkcs11Uri) -> Result<Slot, String> {
    let slots = pkcs11
        .get_slots_with_token()
        .map_err(|e| format!("Failed to enumerate PKCS#11 slots: {e}"))?;

    let mut matching = Vec::new();
    for slot in slots {
        // A slot whose token cannot be read is not a candidate, and neither is an
        // uninitialized token, which holds no keys (SoftHSM always offers one).
        let Ok(info) = pkcs11.get_token_info(slot) else {
            continue;
        };
        if !info.token_initialized() {
            continue;
        }
        let token = TokenId {
            slot_id: slot.id(),
            label: info.label(),
            manufacturer: info.manufacturer_id(),
            serial: info.serial_number(),
            model: info.model(),
        };
        if uri.matches_token(&token) {
            matching.push((slot, format!("{token:?}")));
        }
    }

    match matching.len() {
        0 => Err("no PKCS#11 token matches the URI".to_string()),
        1 => Ok(matching.remove(0).0),
        n => Err(format!(
            "{n} PKCS#11 tokens match the URI; add a 'slot-id', 'serial' or 'token' \
             attribute to select one of: {}",
            matching
                .into_iter()
                .map(|(_, token)| token)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Find the one private key on the token that the URI describes.
fn find_private_key(session: &Session, uri: &Pkcs11Uri) -> Result<ObjectHandle, String> {
    let mut template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
    if let Some(id) = &uri.key_id {
        template.push(Attribute::Id(id.clone()));
    }
    if let Some(label) = &uri.key_label {
        template.push(Attribute::Label(label.clone().into_bytes()));
    }
    let keys = session
        .find_objects(&template)
        .map_err(|e| format!("Failed to search for PKCS#11 private key: {e}"))?;

    match keys.as_slice() {
        [key] => Ok(*key),
        [] if uri.pin.is_none() => Err(format!(
            "no matching PKCS#11 private key found for the URI; private keys are usually \
             only visible after login, and no PIN was given ('pin-value' or {PIN_ENV})"
        )),
        [] => Err("no matching PKCS#11 private key found for the URI".to_string()),
        keys => Err(format!(
            "{} PKCS#11 private keys match the URI; add an 'id' or 'object' attribute to \
             select one",
            keys.len()
        )),
    }
}

/// The certificate key's public point in uncompressed form (`04 || X || Y`).
fn certificate_ec_point(pub_key: &PKey<Public>) -> Result<Vec<u8>, String> {
    let to_err = |e| format!("Failed to read the signing certificate's EC public key: {e}");
    let ec_key = pub_key.ec_key().map_err(to_err)?;
    let mut ctx = BigNumContext::new().map_err(to_err)?;
    ec_key
        .public_key()
        .to_bytes(ec_key.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(to_err)
}

/// The contents of a DER OCTET STRING, if `der` is exactly one.
fn unwrap_octet_string(der: &[u8]) -> Option<&[u8]> {
    match der {
        [0x04, len, rest @ ..] if *len < 0x80 && rest.len() == usize::from(*len) => Some(rest),
        [0x04, 0x81, len, rest @ ..] if rest.len() == usize::from(*len) => Some(rest),
        _ => None,
    }
}

/// Compare a token's `CKA_EC_POINT` with the certificate's public point. PKCS#11
/// specifies the DER OCTET STRING wrapping of the point; some tokens return it bare.
fn ec_point_matches(token_point: &[u8], cert_point: &[u8]) -> bool {
    token_point == cert_point || unwrap_octet_string(token_point) == Some(cert_point)
}

/// Fail if the token's public key for `key` is not the certificate's.
///
/// A private key object does not expose its public half, so this reads the public key
/// object that shares the private key's `CKA_ID`, which is how PKCS#11 pairs the two.
/// If the token has no such object there is nothing to compare, and the mismatch is
/// instead caught by the verification in `sign`.
fn check_key_matches_certificate(
    session: &Session,
    key: ObjectHandle,
    cert_point: &[u8],
) -> Result<(), String> {
    let to_err = |e| format!("Failed to read the PKCS#11 public key: {e}");

    let id = match session
        .get_attributes(key, &[AttributeType::Id])
        .map_err(to_err)?
        .pop()
    {
        Some(Attribute::Id(id)) if !id.is_empty() => id,
        _ => return Ok(()),
    };
    let public_keys = session
        .find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY), Attribute::Id(id)])
        .map_err(to_err)?;

    let mut compared = false;
    for public_key in public_keys {
        let attributes = session
            .get_attributes(public_key, &[AttributeType::EcPoint])
            .map_err(to_err)?;
        if let Some(Attribute::EcPoint(point)) = attributes.first() {
            if ec_point_matches(point, cert_point) {
                return Ok(());
            }
            compared = true;
        }
    }

    if compared {
        Err(
            "the PKCS#11 private key does not match the public key of the signing certificate"
                .to_string(),
        )
    } else {
        Ok(())
    }
}

/// A signing key held on a PKCS#11 token, selected by a `pkcs11:` URI. The private
/// operation runs on the token; parameters/verification use the certificate's public
/// key (`pub_key`), so this implements the COSE signing traits directly.
pub struct Pkcs11Key {
    /// Logged-in session on the token; it keeps the PKCS#11 module loaded. `Session` is
    /// `Send` but not `Sync`, and the mutex keeps `SignKey` shareable between threads.
    session: Mutex<Session>,
    key: ObjectHandle,
    pub_key: PKey<Public>,
}

impl Pkcs11Key {
    /// Build a signer from a `pkcs11:` URI and the PEM signing certificate whose public
    /// key pairs with the token key. This opens a session on the token, logs in, and
    /// fails unless the URI selects exactly one private key that matches the certificate.
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
        let cert_point = certificate_ec_point(&pub_key)?;

        let pkcs11 = Pkcs11::new(uri.module_path.as_str())
            .map_err(|e| format!("Failed to load PKCS#11 module {:?}: {e}", uri.module_path))?;
        // cryptoki does not finalize the module when the context is dropped, so an
        // earlier key from the same module leaves it initialized.
        match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) | Err(Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(e) => return Err(format!("Failed to initialize PKCS#11 module: {e}")),
        }

        let slot = select_slot(&pkcs11, &uri)?;
        let session = pkcs11
            .open_ro_session(slot)
            .map_err(|e| format!("Failed to open PKCS#11 session: {e}"))?;
        if let Some(pin) = &uri.pin {
            // Login state is shared by every session this process has on the token.
            match session.login(UserType::User, Some(&AuthPin::new(pin.as_str().into()))) {
                Ok(()) | Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
                Err(e) => return Err(format!("PKCS#11 login failed: {e}")),
            }
        }

        let key = find_private_key(&session, &uri)?;
        check_key_matches_certificate(&session, key, &cert_point)?;

        Ok(Pkcs11Key {
            session: Mutex::new(session),
            key,
            pub_key,
        })
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
        let session = self
            .session
            .lock()
            .map_err(|_| CoseError::SignatureError("PKCS#11 session lock is poisoned".into()))?;

        // CKM_ECDSA signs a pre-computed digest (COSE already hashed the payload) and
        // returns the raw fixed-length R||S concatenation COSE expects.
        let signature = session
            .sign(&Mechanism::Ecdsa, self.key, digest)
            .map_err(|e| {
                CoseError::SignatureError(format!("PKCS#11 signing failed: {e}").into())
            })?;

        // Never hand back a signature the certificate cannot verify. This is the only
        // check for a token without a public key object to compare when loading the key.
        if !self.pub_key.verify(digest, &signature)? {
            return Err(CoseError::SignatureError(
                "the PKCS#11 signature does not verify against the signing certificate".into(),
            ));
        }
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token<'a>(slot_id: u64, label: &'a str, serial: &'a str) -> TokenId<'a> {
        TokenId {
            slot_id,
            label,
            manufacturer: "Yubico (www.yubico.com)",
            serial,
            model: "YubiKey YK5",
        }
    }

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
        let uri = "pkcs11:token=YubiKey%20PIV%20%2312345678;manufacturer=Yubico%20%28www.yubico.com%29;\
                   serial=12345678;model=YubiKey%20YK5;id=%03;object=eif-signer;type=private;slot-id=0\
                   ?module-path=/usr/lib/libykcs11.so&pin-value=123456";
        let p = Pkcs11Uri::parse(uri).unwrap();
        assert_eq!(p.key_id, Some(vec![0x03]));
        assert_eq!(p.key_label.as_deref(), Some("eif-signer"));
        assert_eq!(p.slot_id, Some(0));
        assert_eq!(p.token_label.as_deref(), Some("YubiKey PIV #12345678"));
        assert_eq!(
            p.token_manufacturer.as_deref(),
            Some("Yubico (www.yubico.com)")
        );
        assert_eq!(p.token_serial.as_deref(), Some("12345678"));
        assert_eq!(p.token_model.as_deref(), Some("YubiKey YK5"));
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

    #[test]
    fn test_parse_uri_rejects_what_it_would_ignore() {
        for (uri, expected) in [
            // Attributes that narrow the selection but are not acted on.
            ("pkcs11:slot-description=x?module-path=/m.so", "unsupported"),
            (
                "pkcs11:library-manufacturer=x?module-path=/m.so",
                "unsupported",
            ),
            (
                "pkcs11:id=%01?module-path=/m.so&pin-source=/pin",
                "unsupported",
            ),
            // A query attribute in the path, and the reverse.
            ("pkcs11:module-path=/m.so", "unsupported"),
            ("pkcs11:id=%01?module-path=/m.so&serial=1", "unsupported"),
            // Only a private key can sign.
            ("pkcs11:type=cert?module-path=/m.so", "'type'"),
            ("pkcs11:serial=1;serial=2?module-path=/m.so", "twice"),
            ("pkcs11:serial?module-path=/m.so", "malformed"),
        ] {
            let err = Pkcs11Uri::parse(uri).unwrap_err();
            assert!(err.contains(expected), "{}: {}", uri, err);
        }
    }

    #[test]
    fn test_matches_token() {
        let parse = |path: &str| Pkcs11Uri::parse(&format!("pkcs11:{path}?module-path=/m.so"));
        let first = token(0, "YubiKey PIV #111", "111");
        let second = token(1, "YubiKey PIV #222", "222");

        // No token attribute: every token matches, so two tokens are ambiguous.
        let any = parse("id=%01").unwrap();
        assert!(any.matches_token(&first) && any.matches_token(&second));

        for path in [
            "serial=222",
            "token=YubiKey%20PIV%20%23222",
            "slot-id=1",
            "model=YubiKey%20YK5;serial=222",
        ] {
            let uri = parse(path).unwrap();
            assert!(!uri.matches_token(&first), "{}", path);
            assert!(uri.matches_token(&second), "{}", path);
        }

        // Every given attribute has to match.
        let uri = parse("serial=222;slot-id=0").unwrap();
        assert!(!uri.matches_token(&first) && !uri.matches_token(&second));
        let uri = parse("manufacturer=Nitrokey;serial=222").unwrap();
        assert!(!uri.matches_token(&second));
    }

    #[test]
    fn test_ec_point_matches() {
        let p256 = [&[0x04u8][..], &[0xab; 64]].concat();
        let p521 = [&[0x04u8][..], &[0xcd; 132]].concat();
        let wrapped_p256 = [&[0x04u8, 65][..], &p256].concat();
        let wrapped_p521 = [&[0x04u8, 0x81, 133][..], &p521].concat();

        assert!(ec_point_matches(&p256, &p256));
        assert!(ec_point_matches(&wrapped_p256, &p256));
        assert!(ec_point_matches(&wrapped_p521, &p521));

        assert!(!ec_point_matches(&wrapped_p256, &p521));
        assert!(!ec_point_matches(&wrapped_p521[..100], &p521));
        let mut other = wrapped_p256.clone();
        *other.last_mut().unwrap() ^= 1;
        assert!(!ec_point_matches(&other, &p256));
    }

    /// Tests against a real token. They need SoftHSM v2 and run only when
    /// `TEST_SOFTHSM2_MODULE` names its module:
    ///
    /// ```sh
    /// TEST_SOFTHSM2_MODULE=/usr/lib/softhsm/libsofthsm2.so cargo test --features pkcs11
    /// ```
    ///
    /// The tokens are created in a temporary directory; nothing outside it is touched.
    mod softhsm {
        use super::*;
        use crate::utils::eif_signer::{EifSigner, SignKeyData};
        use aws_nitro_enclaves_cose::{crypto::Openssl, CoseSign1};
        use cryptoki::session::Session;
        use openssl::asn1::Asn1Time;
        use openssl::ec::{EcGroup, EcKey, EcPoint};
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::Private;
        use openssl::x509::{X509Builder, X509NameBuilder};
        use std::io::Write;
        use tempfile::{NamedTempFile, TempDir};

        const MODULE_VAR: &str = "TEST_SOFTHSM2_MODULE";
        const SO_PIN: &str = "so-pin-1234";
        const PIN: &str = "user-pin-1234";
        /// DER encoding of the secp384r1 OID, 1.3.132.0.34.
        const SECP384R1: [u8; 7] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

        /// Create and initialize a token with the given label; returns its serial.
        fn init_token(pkcs11: &Pkcs11, label: &str) -> String {
            // SoftHSM always offers one slot with an uninitialized token.
            let slot = pkcs11
                .get_slots_with_token()
                .unwrap()
                .into_iter()
                .find(|slot| !pkcs11.get_token_info(*slot).unwrap().token_initialized())
                .unwrap();
            pkcs11
                .init_token(slot, &AuthPin::new(SO_PIN.into()), label)
                .unwrap();
            let session = pkcs11.open_rw_session(slot).unwrap();
            session
                .login(UserType::So, Some(&AuthPin::new(SO_PIN.into())))
                .unwrap();
            session.init_pin(&AuthPin::new(PIN.into())).unwrap();
            pkcs11
                .get_token_info(slot)
                .unwrap()
                .serial_number()
                .to_string()
        }

        /// A logged-in read/write session on the token with the given label.
        fn open_token(pkcs11: &Pkcs11, label: &str) -> Session {
            let slot = pkcs11
                .get_slots_with_token()
                .unwrap()
                .into_iter()
                .find(|slot| pkcs11.get_token_info(*slot).unwrap().label() == label)
                .unwrap();
            let session = pkcs11.open_rw_session(slot).unwrap();
            session
                .login(UserType::User, Some(&AuthPin::new(PIN.into())))
                .unwrap();
            session
        }

        /// Generate a P-384 key pair on the token; returns the public key object and
        /// the public key itself.
        fn generate_key(session: &Session, id: u8, label: &str) -> (ObjectHandle, PKey<Public>) {
            let (public, _private) = session
                .generate_key_pair(
                    &Mechanism::EccKeyPairGen,
                    &[
                        Attribute::Token(true),
                        Attribute::Verify(true),
                        Attribute::EcParams(SECP384R1.to_vec()),
                        Attribute::Id(vec![id]),
                        Attribute::Label(label.as_bytes().to_vec()),
                    ],
                    &[
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                        Attribute::Id(vec![id]),
                        Attribute::Label(label.as_bytes().to_vec()),
                    ],
                )
                .unwrap();

            let Some(Attribute::EcPoint(point)) = session
                .get_attributes(public, &[AttributeType::EcPoint])
                .unwrap()
                .pop()
            else {
                panic!("no CKA_EC_POINT on the generated public key");
            };
            let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            let point = EcPoint::from_bytes(&group, unwrap_octet_string(&point).unwrap(), &mut ctx)
                .unwrap();
            let key = EcKey::from_public_key(&group, &point).unwrap();
            (public, PKey::from_ec_key(key).unwrap())
        }

        /// A PEM certificate file for `pub_key`. Who issued it does not matter to EIF
        /// signing, so it is signed with a throwaway key.
        fn certificate_file(pub_key: &PKey<Public>) -> NamedTempFile {
            let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
            let issuer: PKey<Private> =
                PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
            let mut name = X509NameBuilder::new().unwrap();
            name.append_entry_by_text("CN", "pkcs11-test").unwrap();
            let name = name.build();

            let mut builder = X509Builder::new().unwrap();
            builder.set_subject_name(&name).unwrap();
            builder.set_issuer_name(&name).unwrap();
            builder.set_pubkey(pub_key).unwrap();
            builder
                .set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            builder
                .set_not_after(&Asn1Time::days_from_now(1).unwrap())
                .unwrap();
            builder.sign(&issuer, MessageDigest::sha384()).unwrap();

            let mut file = NamedTempFile::new().unwrap();
            file.write_all(&builder.build().to_pem().unwrap()).unwrap();
            file
        }

        fn load(uri: &str, cert: &NamedTempFile) -> Result<SignKeyData, String> {
            SignKeyData::new(uri, cert.path())
        }

        // One test, because a PKCS#11 module is initialized once per process and
        // SOFTHSM2_CONF is process-global.
        #[test]
        fn test_sign_with_token() {
            let Ok(module) = std::env::var(MODULE_VAR) else {
                eprintln!("{MODULE_VAR} is not set; skipping the PKCS#11 token tests");
                return;
            };

            let dir = TempDir::new().unwrap();
            let conf = dir.path().join("softhsm2.conf");
            std::fs::write(
                &conf,
                format!(
                    "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
                    dir.path().display()
                ),
            )
            .unwrap();
            std::env::set_var("SOFTHSM2_CONF", &conf);

            // Two tokens. The first holds two keys, of which the second key loses its
            // public key object; the second token holds a key with the same id as the
            // first token's first key.
            let (serial, first_key, second_key) = {
                let pkcs11 = Pkcs11::new(&module).unwrap();
                pkcs11
                    .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
                    .unwrap();
                let serial = init_token(&pkcs11, "eif-token");
                init_token(&pkcs11, "other-token");

                let session = open_token(&pkcs11, "eif-token");
                let (_, first_key) = generate_key(&session, 1, "eif-signer");
                let (second_public, second_key) = generate_key(&session, 2, "no-public-key");
                session.destroy_object(second_public).unwrap();
                generate_key(&open_token(&pkcs11, "other-token"), 1, "eif-signer");
                (serial, first_key, second_key)
            };
            let first_cert = certificate_file(&first_key);
            let second_cert = certificate_file(&second_key);
            let query = format!("?module-path={module}&pin-value={PIN}");

            // The URI has to pick one token ...
            let err = load(&format!("pkcs11:id=%01{query}"), &first_cert)
                .err()
                .unwrap();
            assert!(err.contains("2 PKCS#11 tokens match"), "{}", err);
            let err = load(&format!("pkcs11:serial=0;id=%01{query}"), &first_cert)
                .err()
                .unwrap();
            assert!(err.contains("no PKCS#11 token matches"), "{}", err);
            // ... and one key on it.
            let err = load(&format!("pkcs11:token=eif-token{query}"), &first_cert)
                .err()
                .unwrap();
            assert!(err.contains("2 PKCS#11 private keys match"), "{}", err);
            let err = load(
                &format!("pkcs11:token=eif-token;id=%09{query}"),
                &first_cert,
            )
            .err()
            .unwrap();
            assert!(err.contains("no matching PKCS#11 private key"), "{}", err);

            // Without a PIN the private key is not visible.
            let err = load(
                &format!("pkcs11:token=eif-token;id=%01?module-path={module}"),
                &first_cert,
            )
            .err()
            .unwrap();
            assert!(err.contains("no PIN was given"), "{}", err);

            // A key that is not the certificate's is rejected when it is loaded: the
            // same id on the other token, and the other key on the same token.
            for (uri, cert) in [
                (
                    format!("pkcs11:token=other-token;id=%01{query}"),
                    &first_cert,
                ),
                (
                    format!("pkcs11:token=eif-token;id=%01{query}"),
                    &second_cert,
                ),
            ] {
                let err = load(&uri, cert).err().unwrap();
                assert!(err.contains("does not match the public key"), "{}", err);
            }

            // The matching key signs, whether the token is named by label or serial,
            // and the signature verifies against the certificate.
            for uri in [
                format!("pkcs11:token=eif-token;id=%01{query}"),
                format!("pkcs11:serial={serial};object=eif-signer;type=private{query}"),
            ] {
                let signer = EifSigner::new(Some(load(&uri, &first_cert).unwrap())).unwrap();
                let signature = signer.sign(b"payload").unwrap();
                let cose = CoseSign1::from_bytes(&signature.signature).unwrap();
                assert!(cose.verify_signature::<Openssl>(&first_key).unwrap());
                assert!(!cose.verify_signature::<Openssl>(&second_key).unwrap());
            }

            // Without a public key object the key cannot be compared when it is loaded,
            // so a mismatch surfaces when signing and no signature is returned.
            let uri = format!("pkcs11:token=eif-token;id=%02{query}");
            let signer = EifSigner::new(Some(load(&uri, &first_cert).unwrap())).unwrap();
            let err = signer.sign(b"payload").err().unwrap();
            assert!(
                err.contains("does not verify against the signing"),
                "{}",
                err
            );
            // With its own certificate the same key signs.
            let signer = EifSigner::new(Some(load(&uri, &second_cert).unwrap())).unwrap();
            let signature = signer.sign(b"payload").unwrap();
            let cose = CoseSign1::from_bytes(&signature.signature).unwrap();
            assert!(cose.verify_signature::<Openssl>(&second_key).unwrap());
        }
    }
}
