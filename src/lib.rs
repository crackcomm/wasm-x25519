use std::convert::TryInto;

use js_sys::{Error as JsError, Uint8Array};
use wasm_bindgen::prelude::*;

use rand::rngs::OsRng;

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Digest, Verifier};

use subtle::ConstantTimeEq;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// #[wasm_bindgen]
// extern "C" {
//     #[wasm_bindgen(typescript_type = "[Uint8Array, Uint8Array]")]
//     pub type KeyPair;
// }

/// Calculate a shared secret from one party's secret key and another party's public key.
///
/// # Inputs
///
/// * `secret_key`: Party _A_ **x25519** secret key (32 bytes).
/// * `public_key`: Party _B_ **x25519** public key (32 bytes).
///
/// # Returns
///
/// * `shared_key`: Shared **x25519** secret key.
///
#[wasm_bindgen(catch)]
pub fn x25519_shared(secret_key: &[u8], public_key: &[u8]) -> Result<Uint8Array, JsValue> {
    let secret_key: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| JsError::new("SecretKey"))?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| JsError::new("PublicKey"))?;
    let secret = x25519_dalek::StaticSecret::from(secret_key);
    let public = x25519_dalek::PublicKey::from(public_key);
    let shared = secret.diffie_hellman(&public);
    if shared.as_bytes().ct_eq(&[0u8; 32]).into() {
        Err(JsError::new("InvalidSharedSecret").into())
    } else {
        Ok(shared.as_bytes()[..].into())
    }
}

/// Generates a random 32 byte secret seed.
#[wasm_bindgen]
pub fn generate_seed() -> Result<Uint8Array, JsValue> {
    // Instances of this secret are automatically overwritten with zeroes when they fall out of scope.
    let secret_key = ed25519_dalek::SecretKey::generate(&mut OsRng);
    Ok(Uint8Array::from(&secret_key.to_bytes()[..]).into())
}

/// Expands **ed25519** seed to a `private` key.
#[wasm_bindgen]
pub fn expand_seed(secret_seed: &[u8]) -> Result<Uint8Array, JsValue> {
    let secret_key =
        ed25519_dalek::SecretKey::from_bytes(secret_seed).map_err(|_| JsError::new("SecretKey"))?;
    let secret_key = ed25519_dalek::ExpandedSecretKey::from(&secret_key);
    Ok(Uint8Array::from(&secret_key.to_bytes()[..]).into())
}

/// Derives **ed25519** `public` key from expanded `private` key.
#[wasm_bindgen]
pub fn ed25519_public(secret_key: &[u8]) -> Result<Uint8Array, JsValue> {
    let secret_key = ed25519_dalek::ExpandedSecretKey::from_bytes(secret_key)
        .map_err(|_| JsError::new("SecretKey"))?;
    let public_key = ed25519_dalek::PublicKey::from(&secret_key);
    Ok(Uint8Array::from(&public_key.to_bytes()[..]).into())
}

/// Calculates a signature of a message.
///
/// # Inputs
///
/// * `secret_key`: Expanded **ed25519** secret key.
/// * `message`: Message to sign. It should be a hash.
///
/// # Returns
///
/// * `signature`: **ed25519** signature.
///
#[wasm_bindgen]
pub fn ed25519_sign(exp_secret_key: &[u8], message: &[u8]) -> Result<Uint8Array, JsValue> {
    let secret = ed25519_dalek::ExpandedSecretKey::from_bytes(&exp_secret_key)
        .map_err(|_| JsError::new("ExpandedSecretKey"))?;
    let public_key = ed25519_dalek::PublicKey::from(&secret);
    let signature = secret.sign(message, &public_key);
    Ok(signature.to_bytes()[..].into())
}

/// Derives **x25519** public key from a secret key.
#[wasm_bindgen]
pub fn x25519_public(secret_key: &[u8]) -> Result<Uint8Array, JsValue> {
    let secret_key: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| JsError::new("SecretKey"))?;
    let secret = x25519_dalek::StaticSecret::from(secret_key);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok(public.as_bytes()[..].into())
}

/// Converts **ed25519** public key to **x25519** public key.
///
/// It will throw an error to prevent one-way operation with
/// uknown `sign` parameter. It enforces `sign` parameter to
/// be `0`. Setting force to `true` will ignore that rule.
#[wasm_bindgen]
pub fn ed25519_to_x25519(public_key: &[u8], force: Option<bool>) -> Result<Uint8Array, JsValue> {
    let compressed = CompressedEdwardsY::from_slice(public_key);
    let sign_bit = compressed.as_bytes()[31] >> 7;
    if sign_bit == 1 && !force.unwrap_or(false) {
        return Err(JsError::new("OneWayNonDH").into());
    }
    let public_key = compressed
        .decompress()
        .ok_or_else(|| JsError::new("PublicKey"))?
        .to_montgomery()
        .to_bytes();
    Ok(public_key[..].into())
}

/// Converts **x25519** public key to **ed25519** public key.
///
/// # Inputs
///
/// * `public_key`: **x25519** public key.
/// * `sign`: `Some(0)` and `None` denotes positive and `Some(1)` negative.
///
/// # Returns
///
/// * `public_key`: **ed25519** public key.
///
#[wasm_bindgen]
pub fn x25519_to_ed25519(public_key: &[u8], sign: Option<u8>) -> Result<Uint8Array, JsValue> {
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| JsError::new("Size"))?;
    let public_key = MontgomeryPoint(public_key)
        .to_edwards(sign.unwrap_or(0))
        .ok_or_else(|| JsError::new("EdwardsPoint"))?
        .compress();
    Ok(public_key.to_bytes()[..].into())
}

/// Verifies a signature of a message. See [`verify_strict`].
///
/// # Inputs
///
/// * `signature`: **ed25519** signature (64 bytes).
/// * `message`: Message this signature is verified against.
/// * `public_key`: **ed25519** public key of signer.
///
/// # Returns
///
/// * `success`: Verification result, `true` when checked.
///
/// [`verify_strict`]: https://docs.rs/ed25519-dalek/1.0.1/ed25519_dalek/struct.Keypair.html#method.verify_strict
#[wasm_bindgen]
pub fn ed25519_verify_strict(
    signature: &[u8],
    message: &[u8],
    public_key: &[u8],
) -> Result<bool, JsValue> {
    let public_key =
        ed25519_dalek::PublicKey::from_bytes(public_key).map_err(|_| JsError::new("PublicKey"))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| JsError::new("Signature"))?;
    let signature = ed25519_dalek::Signature::new(signature);
    public_key
        .verify_strict(message, &signature)
        .map_err(|_| JsError::new("SignatureVerification").into())
        .map(|_| true)
}

/// Verifies a signature of a message. See [`verify`].
///
/// # Inputs
///
/// * `signature`: **ed25519** signature (64 bytes).
/// * `message`: Message this signature is verified against.
/// * `public_key`: **ed25519** public key of signer.
///
/// # Returns
///
/// * `success`: Verification result, `true` when checked.
///
/// [`verify`]: https://docs.rs/ed25519-dalek/1.0.1/ed25519_dalek/struct.PublicKey.html#method.verify
#[wasm_bindgen]
pub fn ed25519_verify_legacy(
    signature: &[u8],
    message: &[u8],
    public_key: &[u8],
) -> Result<bool, JsValue> {
    let public_key =
        ed25519_dalek::PublicKey::from_bytes(public_key).map_err(|_| JsError::new("PublicKey"))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| JsError::new("Signature"))?;
    let signature = ed25519_dalek::Signature::new(signature);
    public_key
        .verify(message, &signature)
        .map_err(|_| JsError::new("SignatureVerification").into())
        .map(|_| true)
}

/// JavaScript wrapper of SHA512 hasher.
#[wasm_bindgen]
pub struct JsSha512(ed25519_dalek::Sha512);

/// Creates a new SHA512 hasher.
#[wasm_bindgen]
pub fn sha512_new() -> JsSha512 {
    JsSha512(ed25519_dalek::Sha512::new())
}

/// Updates SHA512 `hasher` with `data`.
#[wasm_bindgen]
pub fn sha512_update(hasher: &mut JsSha512, data: &[u8]) {
    hasher.0.update(data);
}

/// Updates SHA512 `hasher` with `data`.
#[wasm_bindgen]
pub fn sha512_update_str(hasher: &mut JsSha512, data: &str) {
    hasher.0.update(data);
}

#[wasm_bindgen]
pub fn sha512_finalize(hasher: &mut JsSha512) -> Uint8Array {
    hasher.0.finalize_reset().as_slice().into()
}
