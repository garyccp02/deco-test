// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! HMAC is specified in [RFC 2104].
//!
//! After a `Key` is constructed, it can be used for multiple signing or
//! verification operations. Separating the construction of the key from the
//! rest of the HMAC operation allows the per-key precomputation to be done
//! only once, instead of it being done in every HMAC operation.
//!
//! Frequently all the data to be signed in a message is available in a single
//! contiguous piece. In that case, the module-level `sign` function can be
//! used. Otherwise, if the input is in multiple parts, `Context` should be
//! used.
//!
//! # Examples:
//!
//! ## Signing a value and verifying it wasn't tampered with
//!
//! ```
//! use ring::{hmac, rand};
//!
//! let rng = rand::SystemRandom::new();
//! let key = hmac::Key::generate(hmac::HMAC_SHA256, &rng)?;
//!
//! let msg = "hello, world";
//!
//! let tag = hmac::sign(&key, msg.as_bytes());
//!
//! // [We give access to the message to an untrusted party, and they give it
//! // back to us. We need to verify they didn't tamper with it.]
//!
//! hmac::verify(&key, msg.as_bytes(), tag.as_ref())?;
//!
//! # Ok::<(), ring::error::Unspecified>(())
//! ```
//!
//! ## Using the one-shot API:
//!
//! ```
//! use ring::{digest, hmac, rand};
//! use ring::rand::SecureRandom;
//!
//! let msg = "hello, world";
//!
//! // The sender generates a secure key value and signs the message with it.
//! // Note that in a real protocol, a key agreement protocol would be used to
//! // derive `key_value`.
//! let rng = rand::SystemRandom::new();
//! let key_value: [u8; digest::SHA256_OUTPUT_LEN] = rand::generate(&rng)?.expose();
//!
//! let s_key = hmac::Key::new(hmac::HMAC_SHA256, key_value.as_ref());
//! let tag = hmac::sign(&s_key, msg.as_bytes());
//!
//! // The receiver (somehow!) knows the key value, and uses it to verify the
//! // integrity of the message.
//! let v_key = hmac::Key::new(hmac::HMAC_SHA256, key_value.as_ref());
//! hmac::verify(&v_key, msg.as_bytes(), tag.as_ref())?;
//!
//! # Ok::<(), ring::error::Unspecified>(())
//! ```
//!
//! ## Using the multi-part API:
//! ```
//! use ring::{digest, hmac, rand};
//! use ring::rand::SecureRandom;
//!
//! let parts = ["hello", ", ", "world"];
//!
//! // The sender generates a secure key value and signs the message with it.
//! // Note that in a real protocol, a key agreement protocol would be used to
//! // derive `key_value`.
//! let rng = rand::SystemRandom::new();
//! let mut key_value: [u8; digest::SHA384_OUTPUT_LEN] = rand::generate(&rng)?.expose();
//!
//! let s_key = hmac::Key::new(hmac::HMAC_SHA384, key_value.as_ref());
//! let mut s_ctx = hmac::Context::with_key(&s_key);
//! for part in &parts {
//!     s_ctx.update(part.as_bytes());
//! }
//! let tag = s_ctx.sign();
//!
//! // The receiver (somehow!) knows the key value, and uses it to verify the
//! // integrity of the message.
//! let v_key = hmac::Key::new(hmac::HMAC_SHA384, key_value.as_ref());
//! let mut msg = Vec::<u8>::new();
//! for part in &parts {
//!     msg.extend(part.as_bytes());
//! }
//! hmac::verify(&v_key, &msg.as_ref(), tag.as_ref())?;
//!
//! # Ok::<(), ring::error::Unspecified>(())
//! ```
//!
//! [RFC 2104]: https://tools.ietf.org/html/rfc2104
//! [code for `ring::pbkdf2`]:
//!     https://github.com/briansmith/ring/blob/main/src/pbkdf2.rs
//! [code for `ring::hkdf`]:
//!     https://github.com/briansmith/ring/blob/main/src/hkdf.rs

use crate::{constant_time, digest, error, hkdf, rand};

use std::fs;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;

const emp_path: &str = "./rustls/src/emp/emp-sh2pc/2pc_hmac/";

/// An HMAC algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Algorithm(&'static digest::Algorithm);

impl Algorithm {
    /// The digest algorithm this HMAC algorithm is based on.
    #[inline]
    pub fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.0
    }
}

/// HMAC using SHA-1. Obsolete.
pub static HMAC_SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm(&digest::SHA1_FOR_LEGACY_USE_ONLY);

/// HMAC using SHA-256.
pub static HMAC_SHA256: Algorithm = Algorithm(&digest::SHA256);

/// HMAC using SHA-384.
pub static HMAC_SHA384: Algorithm = Algorithm(&digest::SHA384);

/// HMAC using SHA-512.
pub static HMAC_SHA512: Algorithm = Algorithm(&digest::SHA512);

/// A deprecated alias for `Tag`.
#[deprecated(note = "`Signature` was renamed to `Tag`. This alias will be removed soon.")]
pub type Signature = Tag;

/// An HMAC tag.
///
/// For a given tag `t`, use `t.as_ref()` to get the tag value as a byte slice.
#[derive(Clone, Copy, Debug)]
pub struct Tag(digest::Digest);

impl AsRef<[u8]> for Tag {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// A key to use for HMAC signing.
#[derive(Clone)]
pub struct Key {
    inner: digest::BlockContext,
    outer: digest::BlockContext,
}

/// `hmac::SigningKey` was renamed to `hmac::Key`.
#[deprecated(note = "Renamed to `hmac::Key`.")]
pub type SigningKey = Key;

/// `hmac::VerificationKey` was merged into `hmac::Key`.
#[deprecated(
    note = "The distinction between verification & signing keys was removed. Use `hmac::Key`."
)]
pub type VerificationKey = Key;

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("Key")
            .field("algorithm", self.algorithm().digest_algorithm())
            .finish()
    }
}

impl Key {

    // [DECO]
    pub fn read(self) {
        unsafe {println!("inner: {:?}", self.inner.state.as32);}
        unsafe {println!("outer: {:?}", self.outer.state.as32);}
    }

    /// Generate an HMAC signing key using the given digest algorithm with a
    /// random value generated from `rng`.
    ///
    /// The key will be `digest_alg.output_len` bytes long, based on the
    /// recommendation in [RFC 2104 Section 3].
    ///
    /// [RFC 2104 Section 3]: https://tools.ietf.org/html/rfc2104#section-3
    pub fn generate(
        algorithm: Algorithm,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::Unspecified> {
        Self::construct(algorithm, |buf| rng.fill(buf))
    }

    fn construct<F>(algorithm: Algorithm, fill: F) -> Result<Self, error::Unspecified>
    where
        F: FnOnce(&mut [u8]) -> Result<(), error::Unspecified>,
    {
        let mut key_bytes = [0; digest::MAX_OUTPUT_LEN];
        let key_bytes = &mut key_bytes[..algorithm.0.output_len];
        fill(key_bytes)?;
        Ok(Self::new(algorithm, key_bytes))
    }

    /// Construct an HMAC signing key using the given digest algorithm and key
    /// value.
    ///
    /// `key_value` should be a value generated using a secure random number
    /// generator (e.g. the `key_value` output by
    /// `SealingKey::generate_serializable()`) or derived from a random key by
    /// a key derivation function (e.g. `ring::hkdf`). In particular,
    /// `key_value` shouldn't be a password.
    ///
    /// As specified in RFC 2104, if `key_value` is shorter than the digest
    /// algorithm's block length (as returned by `digest::Algorithm::block_len`,
    /// not the digest length returned by `digest::Algorithm::output_len`) then
    /// it will be padded with zeros. Similarly, if it is longer than the block
    /// length then it will be compressed using the digest algorithm.
    ///
    /// You should not use keys larger than the `digest_alg.block_len` because
    /// the truncation described above reduces their strength to only
    /// `digest_alg.output_len * 8` bits. Support for such keys is likely to be
    /// removed in a future version of *ring*.
    pub fn new(algorithm: Algorithm, key_value: &[u8]) -> Self {

        println!("key_value: {:?}", key_value);

        let digest_alg = algorithm.0;
        let mut key = Self {
            inner: digest::BlockContext::new(digest_alg),
            outer: digest::BlockContext::new(digest_alg),
        };

        let key_hash;
        let key_value = if key_value.len() <= digest_alg.block_len {
            key_value
        } else {
            key_hash = digest::digest(digest_alg, key_value);
            key_hash.as_ref()
        };

        const IPAD: u8 = 0x36;

        let mut padded_key = [IPAD; digest::MAX_BLOCK_LEN];
        let padded_key = &mut padded_key[..digest_alg.block_len];

        // If the key is shorter than one block then we're supposed to act like
        // it is padded with zero bytes up to the block length. `x ^ 0 == x` so
        // we can just leave the trailing bytes of `padded_key` untouched.
        for (padded_key, key_value) in padded_key.iter_mut().zip(key_value.iter()) {
            *padded_key ^= *key_value;
        }
        key.inner.update(&padded_key);

        const OPAD: u8 = 0x5C;

        // Remove the `IPAD` masking, leaving the unmasked padded key, then
        // mask with `OPAD`, all in one step.
        for b in padded_key.iter_mut() {
            *b ^= IPAD ^ OPAD;
        }
        key.outer.update(&padded_key);

        println!("key inner {:?}", &key.inner.completed_data_blocks);
        println!("key outer {:?}", &key.outer.completed_data_blocks);
        unsafe{println!("key.inner.state.as64[1] {:?}", &key.inner.state.as64[1]);}
        unsafe{println!("key.inner.state.as32[1] {:?}", &key.inner.state.as32[1]);}
        unsafe{println!("key.inner.state.as64[0] {:?}", &key.inner.state.as64[0]);}
        unsafe{println!("key.inner.state.as32[0] {:?}", &key.inner.state.as32[0]);}
        println!("---------------------------------");
        unsafe{println!("key.outer.state.as64[1] {:?}", &key.outer.state.as64[1]);}
        unsafe{println!("key.outer.state.as32[1] {:?}", &key.outer.state.as32[1]);}
        unsafe{println!("key.outer.state.as64[0] {:?}", &key.outer.state.as64[0]);}
        unsafe{println!("key.outer.state.as32[0] {:?}", &key.outer.state.as32[0]);}
        println!("---------------------------------");

        key
    }

    /// The digest algorithm for the key.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        Algorithm(self.inner.algorithm)
    }

    // TLS 1.2
    // extented master secret: generate key
    pub fn deco_tls12_extended_master_secret_key_curve25519(
        algorithm: Algorithm, 
        input: String,
        target_ip_with_port: &str,
        target_ip: &str,
        key_ipad_filename: String,
        key_opad_filename: String
    ) { //-> Self {
        
        // 0. Do 2PC mod add
        // 1. Reverse ems_sum_c_le to big endian
        // 2. Reverse ems_sum_c_be by bytes
        // 3. Padding with 0s
        // 4. input XOR ipad/opad
        // 5. Do 2PC-HMAC with little endian

        println!("====== Start: 2PC mod add ======");
        let output_filename = "tls12_ems_s1s2sum.txt".to_string();
        call_emp_2pc_tls12_ems_s1s2sum(
            input.clone(), 
            output_filename.clone(),
            target_ip.clone()
        );
    
        let fs_ems_ipad = format!("{}{}", emp_path, output_filename.clone());
        let mut ems_sum_c_le = fs::read_to_string(fs_ems_ipad).expect("failed reading");
        println!("Client share: {:?}", ems_sum_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_sum_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_sum_v_le);

        // 1. Reverse ems_sum_c_le to big endian
        let ems_sum_c_be: String = ems_sum_c_le.chars().rev().collect();
        // let ems_sum_v_be: String = ems_sum_v_le.chars().rev().collect();
        // let mut sum = string_xor(ems_sum_c_be.clone(), ems_sum_v_be.clone());
        // println!("sum: {:?}", sum);
        println!("====== End: 2PC mod add ======");

        // 2. Reverse ems_sum_c_be by bytes
        let mut test_sum: String = ems_sum_c_be.clone();
        let mut test_sum_byte = String::new();
        for i in 0..32 {
            let ss: String = test_sum.chars().skip(i*8).take(8).collect();
            test_sum_byte = format!("{}{}", ss, test_sum_byte);
        }
        println!("test_sum_byte: {:?}", test_sum_byte);


        println!("====== Start: 2PC-HMAC (ipad) ======");
        // 3. Padding with 0s
        let mut ems_sum_c_be: String = test_sum_byte.clone();
        for _ in 0..256 {
            ems_sum_c_be = format!("{}{}", ems_sum_c_be, "0");
        }
        println!("ems_sum_c_be: {}", ems_sum_c_be);

        // 4. input XOR ipad/opad
        // Handle padding to 512 bits
        let ipad_one_byte = String::from("00110110"); // 0x36
        let opad_one_byte = String::from("01011100"); // 0x5C
        let mut ipad = String::new();
        let mut opad = String::new();
        for i in 0..64 {
            ipad = format!("{}{}", ipad, ipad_one_byte);
            opad = format!("{}{}", opad, opad_one_byte);
        }
        println!("ipad: {}", ipad);
        println!("opad: {}", opad);

        // HS client share XOR padding
        let mut ems_sum_c_be_ipad = string_xor(ems_sum_c_be.clone(), ipad.clone());
        let mut ems_sum_c_be_opad = string_xor(ems_sum_c_be.clone(), opad.clone());

        // 5. Do 2PC-HMAC with little endian
        let ems_sum_c_le_ipad: String = ems_sum_c_be_ipad.chars().rev().collect();
        let ems_sum_c_le_opad: String = ems_sum_c_be_opad.chars().rev().collect();

        let output_filename = key_ipad_filename.clone();
        call_emp_2pc_hmac_key_iopad(
            ems_sum_c_le_ipad.clone(), 
            output_filename.clone(), 
            target_ip.clone()
        );

        let fs_ems_ipad = format!("{}{}", emp_path, output_filename.clone());
        let mut ems_sum_ipad_c_le = fs::read_to_string(fs_ems_ipad).expect("failed reading");
        println!("Client share: {:?}", ems_sum_ipad_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_sum_ipad_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_sum_ipad_v_le);

        // let ems_sum_ipad_c_be: String = ems_sum_ipad_c_le.chars().rev().collect();
        // let ems_sum_ipad_v_be: String = ems_sum_ipad_v_le.chars().rev().collect();
        // let mut ems_sum_ipad_be = string_xor(ems_sum_ipad_c_be.clone(), ems_sum_ipad_v_be.clone());
        println!("====== End: 2PC-HMAC (ipad) ======");

        println!("====== Start: 2PC-HMAC (opad) ======");
        let output_filename = key_opad_filename.clone();
        call_emp_2pc_hmac_key_iopad(
            ems_sum_c_le_opad.clone(), 
            output_filename.clone(), 
            target_ip.clone()
        );

        let fs_ems_opad = format!("{}{}", emp_path, output_filename.clone());
        let mut ems_sum_opad_c_le = fs::read_to_string(fs_ems_opad).expect("failed reading");
        println!("Client share: {:?}", ems_sum_opad_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_sum_opad_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_sum_opad_v_le);

        // let ems_sum_opad_c_be: String = ems_sum_opad_c_le.chars().rev().collect();
        // let ems_sum_opad_v_be: String = ems_sum_opad_v_le.chars().rev().collect();
        // let mut ems_sum_opad_be = string_xor(ems_sum_opad_c_be.clone(), ems_sum_opad_v_be.clone());
        println!("====== End: 2PC-HMAC (opad) ======");

        // let key_ipad_state: digest::State = be_bin_string_to_state(ems_sum_ipad_be);
        // let key_opad_state: digest::State = be_bin_string_to_state(ems_sum_opad_be);

        // let digest_alg = algorithm.0;
        // // println!("digest_alg: {:?}", digest_alg);
        // let mut key = Self {
        //     inner: digest::BlockContext::new(digest_alg),
        //     outer: digest::BlockContext::new(digest_alg),
        // };

        // key.inner.update_with_states(key_ipad_state);
        // key.outer.update_with_states(key_opad_state);

        // key
    }

    // TLS 1.2
    // extented master secret: generate key
    pub fn deco_tls12_extended_master_secret_key_secp256r1(
        algorithm: Algorithm, 
        input: String,
        target_ip_with_port: &str,
        target_ip: &str,
        key_ipad_filename: String,
        key_opad_filename: String
    ) { //-> Self {
        
        // 0. Do 2PC mod add
        // 1. Reverse ems_sum_c_le to big endian
        // 2. Padding with 0s
        // 3. input XOR ipad/opad
        // 4. Do 2PC-HMAC with little endian

        println!("====== Start: 2PC mod add ======");
        let output_filename = "tls12_ems_s1s2sum.txt".to_string();
        call_emp_2pc_tls12_ems_s1s2sum_secp256r1(
            input.clone(), 
            output_filename.clone(),
            target_ip.clone()
        );
    
        let fs_ems_ipad = format!("{}{}", emp_path, output_filename.clone());
        let mut ems_sum_c_le = fs::read_to_string(fs_ems_ipad).expect("failed reading");
        println!("Client share: {:?}", ems_sum_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_sum_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_sum_v_le);

        // 1. Reverse ems_sum_c_le to big endian
        let mut ems_sum_c_be: String = ems_sum_c_le.chars().rev().collect();

        // let ems_sum_v_be: String = ems_sum_v_le.chars().rev().collect();
        // let mut sum = string_xor(ems_sum_c_be.clone(), ems_sum_v_be.clone());
        // println!("sum: {:?}", sum);
        println!("====== End: 2PC mod add ======");

        println!("====== Start: 2PC-HMAC (ipad) ======");
        // 2. Padding with 0s
        // let mut ems_sum_c_be: String = test_sum_byte.clone();
        for _ in 0..256 {
            ems_sum_c_be = format!("{}{}", ems_sum_c_be, "0");
        }
        println!("ems_sum_c_be: {}", ems_sum_c_be);

        // 3. input XOR ipad/opad
        // Handle padding to 512 bits
        let ipad_one_byte = String::from("00110110"); // 0x36
        let opad_one_byte = String::from("01011100"); // 0x5C
        let mut ipad = String::new();
        let mut opad = String::new();
        for i in 0..64 {
            ipad = format!("{}{}", ipad, ipad_one_byte);
            opad = format!("{}{}", opad, opad_one_byte);
        }
        println!("ipad: {}", ipad);
        println!("opad: {}", opad);

        // HS client share XOR padding
        let mut ems_sum_c_be_ipad = string_xor(ems_sum_c_be.clone(), ipad.clone());
        let mut ems_sum_c_be_opad = string_xor(ems_sum_c_be.clone(), opad.clone());

        // 4. Do 2PC-HMAC with little endian
        let ems_sum_c_le_ipad: String = ems_sum_c_be_ipad.chars().rev().collect();
        let ems_sum_c_le_opad: String = ems_sum_c_be_opad.chars().rev().collect();

        let output_filename = key_ipad_filename.clone();
        call_emp_2pc_hmac_key_iopad(
            ems_sum_c_le_ipad.clone(), 
            output_filename.clone(), 
            target_ip.clone()
        );

        let fs_ems_ipad = format!("{}{}", emp_path, output_filename.clone());
        let mut ems_sum_ipad_c_le = fs::read_to_string(fs_ems_ipad).expect("failed reading");
        println!("Client share: {:?}", ems_sum_ipad_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_sum_ipad_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_sum_ipad_v_le);

        // let ems_sum_ipad_c_be: String = ems_sum_ipad_c_le.chars().rev().collect();
        // let ems_sum_ipad_v_be: String = ems_sum_ipad_v_le.chars().rev().collect();
        // let mut ems_sum_ipad_be = string_xor(ems_sum_ipad_c_be.clone(), ems_sum_ipad_v_be.clone());
        println!("====== End: 2PC-HMAC (ipad) ======");

        println!("====== Start: 2PC-HMAC (opad) ======");
        let output_filename = key_opad_filename.clone();
        call_emp_2pc_hmac_key_iopad(
            ems_sum_c_le_opad.clone(), 
            output_filename.clone(), 
            target_ip.clone()
        );

        let fs_ems_opad = format!("{}{}", emp_path, output_filename.clone());
        let mut ems_sum_opad_c_le = fs::read_to_string(fs_ems_opad).expect("failed reading");
        println!("Client share: {:?}", ems_sum_opad_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_sum_opad_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_sum_opad_v_le);

        // let ems_sum_opad_c_be: String = ems_sum_opad_c_le.chars().rev().collect();
        // let ems_sum_opad_v_be: String = ems_sum_opad_v_le.chars().rev().collect();
        // let mut ems_sum_opad_be = string_xor(ems_sum_opad_c_be.clone(), ems_sum_opad_v_be.clone());
        println!("====== End: 2PC-HMAC (opad) ======");

        // let key_ipad_state: digest::State = be_bin_string_to_state(ems_sum_ipad_be);
        // let key_opad_state: digest::State = be_bin_string_to_state(ems_sum_opad_be);

        // let digest_alg = algorithm.0;
        // // println!("digest_alg: {:?}", digest_alg);
        // let mut key = Self {
        //     inner: digest::BlockContext::new(digest_alg),
        //     outer: digest::BlockContext::new(digest_alg),
        // };

        // key.inner.update_with_states(key_ipad_state);
        // key.outer.update_with_states(key_opad_state);

        // key
    }

    // TLS 1.2
    // key expansion: generate key
    pub fn deco_tls12_key_expansion_key(
        algorithm: Algorithm, 
        ems_phash1_2_filename: String,
        ems_phash2_2_filename: String,
        target_ip_with_port: &str,
        target_ip: &str,
        key_ipad_filename: String,
        key_opad_filename: String
    ) -> Self {

        // 1. Type conversion with padding of zeros
        // 2. input XOR ipad/opad
        // 3. Do 2PC-HMAC with little endian
        
        // 1. Type conversion with padding of zeros
        let fs_phash1_2 = format!("{}{}", emp_path, ems_phash1_2_filename.clone());
        let mut ems_phash1_2_c_le = fs::read_to_string(fs_phash1_2).expect("failed reading");
        println!("ems_phash1_2_c_le: {:?}", ems_phash1_2_c_le);

        let fs_phash2_2 = format!("{}{}", emp_path, ems_phash2_2_filename.clone());
        let mut ems_phash2_2_c_le = fs::read_to_string(fs_phash2_2).expect("failed reading");
        println!("ems_phash2_2_c_le: {:?}", ems_phash2_2_c_le);

        let ems_phash1_2_c_be: String = ems_phash1_2_c_le.chars().rev().collect();
        let ems_phash2_2_c_be: String = ems_phash2_2_c_le.chars().rev().collect();

        let mut ke_key_be = format!("{}{}", ems_phash1_2_c_be, ems_phash2_2_c_be);
        ke_key_be = ke_key_be[0..384].to_string();
        while ke_key_be.len() < 512 {
            ke_key_be = format!("{}{}", ke_key_be, "0");
        }

        // 4. input XOR ipad/opad
        // Handle padding to 512 bits
        let ipad_one_byte = String::from("00110110"); // 0x36
        let opad_one_byte = String::from("01011100"); // 0x5C
        let mut ipad = String::new();
        let mut opad = String::new();
        for i in 0..64 {
            ipad = format!("{}{}", ipad, ipad_one_byte);
            opad = format!("{}{}", opad, opad_one_byte);
        }
        println!("ipad: {}", ipad);
        println!("opad: {}", opad);

        // HS client share XOR padding
        let mut ke_key_c_be_ipad = string_xor(ke_key_be.clone(), ipad.clone());
        let mut ke_key_c_be_opad = string_xor(ke_key_be.clone(), opad.clone());

        let ke_key_c_le_ipad: String = ke_key_c_be_ipad.chars().rev().collect();
        let ke_key_c_le_opad: String = ke_key_c_be_opad.chars().rev().collect();

        // 5. Do 2PC-HMAC with little endian
        let output_filename = key_ipad_filename.clone();
        call_emp_2pc_hmac_key_iopad(
            ke_key_c_le_ipad.clone(), 
            output_filename.clone(), 
            target_ip.clone()
        );

        let fs_ke_ipad = format!("{}{}", emp_path, output_filename.clone());
        let mut ke_key_ipad_c_le = fs::read_to_string(fs_ke_ipad).expect("failed reading");
        println!("Client share: {:?}", ke_key_ipad_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ke_key_ipad_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ke_key_ipad_v_le);

        // let ke_key_ipad_c_be: String = ke_key_ipad_c_le.chars().rev().collect();
        // let ke_key_ipad_v_be: String = ke_key_ipad_v_le.chars().rev().collect();
        // let mut ke_key_ipad_be = string_xor(ke_key_ipad_c_be.clone(), ke_key_ipad_v_be.clone());
        println!("====== End: 2PC-HMAC (ipad) ======");

        println!("====== Start: 2PC-HMAC (opad) ======");
        let output_filename = key_opad_filename.clone();
        call_emp_2pc_hmac_key_iopad(
            ke_key_c_le_opad.clone(), 
            output_filename.clone(), 
            target_ip.clone()
        );

        let fs_ke_opad = format!("{}{}", emp_path, output_filename.clone());
        let mut ke_key_opad_c_le = fs::read_to_string(fs_ke_opad).expect("failed reading");
        println!("Client share: {:?}", ke_key_opad_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ke_key_opad_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ke_key_opad_v_le);

        // let ke_key_opad_c_be: String = ke_key_opad_c_le.chars().rev().collect();
        // let ke_key_opad_v_be: String = ke_key_opad_v_le.chars().rev().collect();
        // let mut ke_key_opad_be = string_xor(ke_key_opad_c_be.clone(), ke_key_opad_v_be.clone());
        println!("====== End: 2PC-HMAC (opad) ======");

        // let key_ipad_state: digest::State = be_bin_string_to_state(ke_key_ipad_be);
        // let key_opad_state: digest::State = be_bin_string_to_state(ke_key_opad_be);
        let key_ipad_state: digest::State = be_bin_string_to_state(ke_key_ipad_c_le);
        let key_opad_state: digest::State = be_bin_string_to_state(ke_key_opad_c_le);

        let digest_alg = algorithm.0;
        // println!("digest_alg: {:?}", digest_alg);
        let mut key = Self {
            inner: digest::BlockContext::new(digest_alg),
            outer: digest::BlockContext::new(digest_alg),
        };

        key.inner.update_with_states(key_ipad_state);
        key.outer.update_with_states(key_opad_state);

        key

    }

    pub fn deco_tls12_ke_recursive_hmac(
        algorithm: Algorithm, 
        seed: &[u8],
        target_ip_with_port: &str,
        target_ip: &str,
        key_ipad_filename: String,
        key_opad_filename: String,
        a1_1_filename: String,
        a1_2_filename: String,
        a2_filename: String,
        a3_filename: String,
        phash1_1_filename: String,
        phash1_2_filename: String,
        phash2_1_filename: String,
        phash2_2_filename: String,
    ) -> [u8; 48] {
        let fs: String = String::from(emp_path);

        // Get key shares
        let fs_ipad = format!("{}{}", fs, key_ipad_filename);
        let mut ipad_le = fs::read_to_string(fs_ipad).expect("failed reading");

        let fs_opad = format!("{}{}", fs, key_opad_filename);
        let mut opad_le = fs::read_to_string(fs_opad).expect("failed reading");

        println!("====== Start: 2PC-HMAC (A1) ======");
        // seed binary
        let seed_length: usize = seed.len() * 8;
        let padding: String = format!("{:b}", seed_length+512);
        println!("padding: {:?}", padding);
        let mut seed_bin: String = String::new();
        for i in 0..seed.len() {
            let mut entry = format!("{:b}", seed[i]);
            while entry.len() < 8 {
                entry = format!("{}{}", "0", entry);
            }
            seed_bin = format!("{}{}", seed_bin, entry);
        }

        // message input of A1
        let mut input_bin = format!("{}1", seed_bin.clone());
        while input_bin.len() < 1024 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        // input_bin = input_bin.chars().rev().collect();

        let mut a1_1_msg: String = (input_bin.clone())[0..512].to_string();
        a1_1_msg = a1_1_msg.chars().rev().collect();

        handle_emp_2pc_tls12_sha256(
            a1_1_msg,
            ipad_le.clone(),
            a1_1_filename.clone(),
            target_ip.clone()
        );

        let fs_a1_1 = format!("{}{}", emp_path, a1_1_filename.clone());
        let mut ke_a1_1_c_le = fs::read_to_string(fs_a1_1).expect("failed reading");
        println!("Client share: {:?}", ke_a1_1_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ke_a1_1_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ke_a1_1_v_le);

        // let ke_a1_1_c_be: String = ke_a1_1_c_le.chars().rev().collect();
        // let ke_a1_1_v_be: String = ke_a1_1_v_le.chars().rev().collect();
        // let mut ke_phash_1_1_be = string_xor(ke_a1_1_c_be.clone(), ke_a1_1_v_be.clone());

        // let ke_a1_1_state: digest::State = be_bin_string_to_state(ke_phash_1_1_be);

        let mut a1_2_msg: String = (input_bin.clone())[512..1024].to_string();
        a1_2_msg = a1_2_msg.chars().rev().collect();
        call_emp_2pc_hmac_expand(
            a1_2_msg,
            ke_a1_1_c_le.clone(),
            opad_le.clone(),
            a1_2_filename.clone(),
            target_ip.clone()
        );

        let fs_a1_2 = format!("{}{}", emp_path, a1_2_filename.clone());
        let mut ke_a1_2_c_le = fs::read_to_string(fs_a1_2).expect("failed reading");
        println!("Client share: {:?}", ke_a1_2_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ke_a1_2_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ke_a1_2_v_le);

        // let ke_a1_2_c_be: String = ke_a1_2_c_le.chars().rev().collect();
        // let ke_a1_2_v_be: String = ke_a1_2_v_le.chars().rev().collect();
        // let mut ke_a1_2_be = string_xor(ke_a1_2_c_be.clone(), ke_a1_2_v_be.clone());

        // let ke_a1_2_state: digest::State = be_bin_string_to_state(ke_a1_2_be);
        println!("====== End: 2PC-HMAC (A1) ======");

        println!("====== Start: 2PC-HMAC (P_hash[1]) ======");
        // message input of A1
        let mut phash_1_1_input: String = ke_a1_2_c_le.clone();
        phash_1_1_input = phash_1_1_input.chars().rev().collect();
        let padding: String = format!("{:b}", seed_length+256+512);
        println!("padding: {:?}", padding);
        let mut input_bin: String = format!("{}{}1", phash_1_1_input, seed_bin.clone());
        while input_bin.len() < 1024 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        // input_bin = input_bin.chars().rev().collect();
        let mut phash1_1_msg: String = (input_bin.clone())[0..512].to_string();
        phash1_1_msg = phash1_1_msg.chars().rev().collect();

        handle_emp_2pc_tls12_sha256(
            phash1_1_msg,
            ipad_le.clone(),
            phash1_1_filename.clone(),
            target_ip.clone()
        );

        let fs_phash1_1 = format!("{}{}", emp_path, phash1_1_filename.clone());
        let mut ke_phash1_1_c_le = fs::read_to_string(fs_phash1_1).expect("failed reading");
        println!("Client share: {:?}", ke_phash1_1_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ke_phash1_1_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ke_phash1_1_v_le);

        // let ke_phash1_1_c_be: String = ke_phash1_1_c_le.chars().rev().collect();
        // let ke_phash1_1_v_be: String = ke_phash1_1_v_le.chars().rev().collect();
        // let mut ke_phash_1_1_be = string_xor(ke_phash1_1_c_be.clone(), ke_phash1_1_v_be.clone());

        // let ke_phash_1_1_state: digest::State = be_bin_string_to_state(ke_phash_1_1_be);

        let mut phash1_2_msg: String = (input_bin.clone())[512..1024].to_string();
        phash1_2_msg = phash1_2_msg.chars().rev().collect();
        call_emp_2pc_hmac_expand(
            phash1_2_msg,
            ke_phash1_1_c_le.clone(),
            opad_le.clone(),
            phash1_2_filename.clone(),
            target_ip.clone()
        );

        let fs_phash1_2 = format!("{}{}", emp_path, phash1_2_filename.clone());
        let mut ke_phash1_2_c_le = fs::read_to_string(fs_phash1_2).expect("failed reading");
        println!("Client share: {:?}", ke_phash1_2_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ke_phash1_2_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ke_phash1_2_v_le);

        // let ke_phash1_2_c_be: String = ke_phash1_2_c_le.chars().rev().collect();
        // let ke_phash1_2_v_be: String = ke_phash1_2_v_le.chars().rev().collect();
        // let mut ke_phash_1_2_be = string_xor(ke_phash1_2_c_be.clone(), ke_phash1_2_v_be.clone());

        // let ke_phash_1_2_state: digest::State = be_bin_string_to_state(ke_phash_1_2_be);
        println!("====== End: 2PC-HMAC (P_hash[1]) ======");

        println!("====== Start: 2PC-HMAC (A2) ======");
        // message input of A2
        let ke_a1_2_c_be: String = ke_a1_2_c_le.chars().rev().collect();
        let mut padding = format!("{:b}", ke_a1_2_c_be.len()+512);
        println!("padding: {:?}", padding);
        let mut input_bin = format!("{}1", ke_a1_2_c_be.clone());
        while input_bin.len() < 512 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        input_bin = input_bin.chars().rev().collect();

        handle_emp_2pc_tls12_expand(
            input_bin,
            ipad_le.clone(),
            opad_le.clone(),
            a2_filename.clone(),
            target_ip.clone()
        );
        let fs_a2 = format!("{}{}", emp_path, a2_filename.clone());
        let mut ke_a2_c_le = fs::read_to_string(fs_a2).expect("failed reading");
        println!("Client share: {:?}", ke_a2_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ke_a2_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ke_a2_v_le);

        // let ke_a2_c_be: String = ke_a2_c_le.chars().rev().collect();
        // let ke_a2_v_be: String = ke_a2_v_le.chars().rev().collect();
        // let mut ke_a2_be = string_xor(ke_a2_c_be.clone(), ke_a2_v_be.clone());

        // let ke_a2_state: digest::State = be_bin_string_to_state(ke_a2_be);
        println!("====== End: 2PC-HMAC (A2) ======");

        println!("====== Start: 2PC-HMAC (P_hash[2]) ======");
        // message input of A2
        let ke_a2_c_be: String = ke_a2_c_le.chars().rev().collect();
        let padding: String = format!("{:b}", seed_length+256+512);
        println!("padding: {:?}", padding);
        let mut input_bin: String = format!("{}{}1", ke_a2_c_be, seed_bin.clone());
        while input_bin.len() < 1024 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        // input_bin = input_bin.chars().rev().collect();
        let mut phash2_1_msg: String = (input_bin.clone())[0..512].to_string();
        phash2_1_msg = phash2_1_msg.chars().rev().collect();

        handle_emp_2pc_tls12_sha256(
            phash2_1_msg,
            ipad_le.clone(),
            phash2_1_filename.clone(),
            target_ip.clone()
        );

        let fs_phash2_1 = format!("{}{}", emp_path, phash2_1_filename.clone());
        let mut ke_phash2_1_c_le = fs::read_to_string(fs_phash2_1).expect("failed reading");
        println!("Client share: {:?}", ke_phash2_1_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ke_phash2_1_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ke_phash2_1_v_le);

        // let ke_phash2_1_c_be: String = ke_phash2_1_c_le.chars().rev().collect();
        // let ke_phash2_1_v_be: String = ke_phash2_1_v_le.chars().rev().collect();
        // let mut ke_phash_2_1_be = string_xor(ke_phash2_1_c_be.clone(), ke_phash2_1_v_be.clone());

        // let ke_phash_2_1_state: digest::State = be_bin_string_to_state(ke_phash_2_1_be);

        let mut phash2_2_msg: String = (input_bin.clone())[512..1024].to_string();
        phash2_2_msg = phash2_2_msg.chars().rev().collect();
        call_emp_2pc_hmac_expand(
            phash2_2_msg,
            ke_phash2_1_c_le.clone(),
            opad_le.clone(),
            phash2_2_filename.clone(),
            target_ip.clone()
        );

        let fs_phash2_2 = format!("{}{}", emp_path, phash2_2_filename.clone());
        let mut ke_phash2_2_c_le = fs::read_to_string(fs_phash2_2).expect("failed reading");
        println!("Client share: {:?}", ke_phash2_2_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ke_phash2_2_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ke_phash2_2_v_le);

        // let ke_phash2_2_c_be: String = ke_phash2_2_c_le.chars().rev().collect();
        // let ke_phash2_2_v_be: String = ke_phash2_2_v_le.chars().rev().collect();
        // let mut ke_phash_2_2_be = string_xor(ke_phash2_2_c_be.clone(), ke_phash2_2_v_be.clone());

        // let ke_phash_2_2_state: digest::State = be_bin_string_to_state(ke_phash_2_2_be);
        println!("====== End: 2PC-HMAC (P_hash[2]) ======");

        println!("====== Start: 2PC-HMAC (A3) ======");
        // message input of A3
        let ke_a2_c_be: String = ke_a2_c_le.chars().rev().collect();
        let mut padding = format!("{:b}", ke_a2_c_be.len()+512);
        println!("padding: {:?}", padding);
        let mut input_bin = format!("{}1", ke_a2_c_be.clone());
        while input_bin.len() < 512 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        input_bin = input_bin.chars().rev().collect();

        handle_emp_2pc_tls12_expand(
            input_bin,
            ipad_le.clone(),
            opad_le.clone(),
            a3_filename.clone(),
            target_ip.clone()
        );
        let fs_a3 = format!("{}{}", emp_path, a3_filename.clone());
        let mut ke_a3_c_le = fs::read_to_string(fs_a3).expect("failed reading");
        println!("Client share: {:?}", ke_a3_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ke_a3_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ke_a3_v_le);

        // let ke_a3_c_be: String = ke_a3_c_le.chars().rev().collect();
        // let ke_a3_v_be: String = ke_a3_v_le.chars().rev().collect();
        // let mut ke_a3_be = string_xor(ke_a3_c_be.clone(), ke_a3_v_be.clone());

        // let ke_a3_state: digest::State = be_bin_string_to_state(ke_a3_be.clone());
        println!("====== End: 2PC-HMAC (A3) ======");

        let ke_phash1_2_c_be: String = ke_phash1_2_c_le.chars().rev().collect();
        let ke_phash2_2_c_be: String = ke_phash2_2_c_le.chars().rev().collect();
        let phash_1_vec = be_bin_string_to_vec_u8(ke_phash1_2_c_be.clone());
        let phash_2_vec = be_bin_string_to_vec_u8(ke_phash2_2_c_be.clone());
        // let phash_1_vec = be_bin_string_to_vec_u8(ke_phash_1_2_be.clone());
        // let phash_2_vec = be_bin_string_to_vec_u8(ke_phash_2_2_be.clone());
        let mut output: [u8; 48] = [0; 48];
        for i in 0..32 {
            output[i] = phash_1_vec[i];
        }
        for i in 32..48 {
            output[i] = phash_2_vec[i-32];
        }

        println!("out: {:?}", output);

        output
    }

    pub fn deco_tls12_ems_recursive_hmac(
        algorithm: Algorithm, 
        seed: &[u8],
        target_ip_with_port: &str,
        target_ip: &str,
        key_ipad_filename: String,
        key_opad_filename: String,
        a1_filename: String,
        a2_filename: String,
        a3_filename: String,
        phash1_1_filename: String,
        phash1_2_filename: String,
        phash2_1_filename: String,
        phash2_2_filename: String,
    ) -> [u8; 48] {
        let fs: String = String::from(emp_path);

        // Get key shares
        let fs_ipad = format!("{}{}", fs, key_ipad_filename);
        let mut ipad_le = fs::read_to_string(fs_ipad).expect("failed reading");

        let fs_opad = format!("{}{}", fs, key_opad_filename);
        let mut opad_le = fs::read_to_string(fs_opad).expect("failed reading");
        
        // For A1
        println!("====== Start: 2PC-HMAC (A1) ======");
        // seed binary
        let seed_length: usize = seed.len() * 8;
        let padding: String = format!("{:b}", seed_length+512);
        println!("padding: {:?}", padding);
        let mut seed_bin: String = String::new();
        for i in 0..seed.len() {
            let mut entry = format!("{:b}", seed[i]);
            while entry.len() < 8 {
                entry = format!("{}{}", "0", entry);
            }
            seed_bin = format!("{}{}", seed_bin, entry);
        }

        // message input of A1
        let mut input_bin = format!("{}1", seed_bin.clone());
        while input_bin.len() < 512 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        input_bin = input_bin.chars().rev().collect();

        call_emp_2pc_hmac_expand(
            input_bin,
            ipad_le.clone(),
            opad_le.clone(),
            a1_filename.clone(),
            target_ip.clone()
        );
        let fs_a1 = format!("{}{}", emp_path, a1_filename.clone());
        let mut ems_a1_c_le = fs::read_to_string(fs_a1).expect("failed reading");
        println!("Client share: {:?}", ems_a1_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_a1_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_a1_v_le);

        // let ems_a1_c_be: String = ems_a1_c_le.chars().rev().collect();
        // let ems_a1_v_be: String = ems_a1_v_le.chars().rev().collect();
        // let mut ems_a1_be = string_xor(ems_a1_c_be.clone(), ems_a1_v_be.clone());

        // let ems_a1_state: digest::State = be_bin_string_to_state(ems_a1_be);
        println!("====== End: 2PC-HMAC (A1) ======");

        println!("====== Start: 2PC-HMAC (P_hash[1]) ======");
        // message input of A1
        let ems_a1_c_be: String = ems_a1_c_le.chars().rev().collect();
        let padding: String = format!("{:b}", seed_length+256+512);
        println!("padding: {:?}", padding);
        let mut input_bin: String = format!("{}{}1", ems_a1_c_be, seed_bin.clone());
        while input_bin.len() < 1024 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        // input_bin = input_bin.chars().rev().collect();
        let mut phash1_1_msg: String = (input_bin.clone())[0..512].to_string();
        phash1_1_msg = phash1_1_msg.chars().rev().collect();

        handle_emp_2pc_tls12_sha256(
            phash1_1_msg,
            ipad_le.clone(),
            phash1_1_filename.clone(),
            target_ip.clone()
        );

        let fs_phash1_1 = format!("{}{}", emp_path, phash1_1_filename.clone());
        let mut ems_phash1_1_c_le = fs::read_to_string(fs_phash1_1).expect("failed reading");
        println!("Client share: {:?}", ems_phash1_1_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_phash1_1_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_phash1_1_v_le);

        // let ems_phash1_1_c_be: String = ems_phash1_1_c_le.chars().rev().collect();
        // let ems_phash1_1_v_be: String = ems_phash1_1_v_le.chars().rev().collect();
        // let mut ems_phash_1_1_be = string_xor(ems_phash1_1_c_be.clone(), ems_phash1_1_v_be.clone());

        // let ems_phash_1_1_state: digest::State = be_bin_string_to_state(ems_phash_1_1_be);

        let mut phash1_2_msg: String = (input_bin.clone())[512..1024].to_string();
        phash1_2_msg = phash1_2_msg.chars().rev().collect();
        call_emp_2pc_hmac_expand(
            phash1_2_msg,
            ems_phash1_1_c_le.clone(),
            opad_le.clone(),
            phash1_2_filename.clone(),
            target_ip.clone()
        );

        let fs_phash1_2 = format!("{}{}", emp_path, phash1_2_filename.clone());
        let mut ems_phash1_2_c_le = fs::read_to_string(fs_phash1_2).expect("failed reading");
        println!("Client share: {:?}", ems_phash1_2_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_phash1_2_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_phash1_2_v_le);

        // let ems_phash1_2_c_be: String = ems_phash1_2_c_le.chars().rev().collect();
        // let ems_phash1_2_v_be: String = ems_phash1_2_v_le.chars().rev().collect();
        // let mut ems_phash_1_2_be = string_xor(ems_phash1_2_c_be.clone(), ems_phash1_2_v_be.clone());

        // let ems_phash_1_2_state: digest::State = be_bin_string_to_state(ems_phash_1_2_be);
        println!("====== End: 2PC-HMAC (P_hash[1]) ======");

        println!("====== Start: 2PC-HMAC (A2) ======");
        // message input of A2
        let ems_a1_c_be: String = ems_a1_c_le.chars().rev().collect();
        let mut padding = format!("{:b}", ems_a1_c_be.len()+512);
        println!("padding: {:?}", padding);
        let mut input_bin = format!("{}1", ems_a1_c_be.clone());
        while input_bin.len() < 512 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        input_bin = input_bin.chars().rev().collect();

        handle_emp_2pc_tls12_expand(
            input_bin,
            ipad_le.clone(),
            opad_le.clone(),
            a2_filename.clone(),
            target_ip.clone()
        );
        let fs_a2 = format!("{}{}", emp_path, a2_filename.clone());
        let mut ems_a2_c_le = fs::read_to_string(fs_a2).expect("failed reading");
        println!("Client share: {:?}", ems_a2_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_a2_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_a2_v_le);

        // let ems_a2_c_be: String = ems_a2_c_le.chars().rev().collect();
        // let ems_a2_v_be: String = ems_a2_v_le.chars().rev().collect();
        // let mut ems_a2_be = string_xor(ems_a2_c_be.clone(), ems_a2_v_be.clone());

        // let ems_a2_state: digest::State = be_bin_string_to_state(ems_a2_be);
        println!("====== End: 2PC-HMAC (A2) ======");

        println!("====== Start: 2PC-HMAC (P_hash[2]) ======");
        // message input of A2
        let ems_a2_c_be: String = ems_a2_c_le.chars().rev().collect();
        let padding: String = format!("{:b}", seed_length+256+512);
        println!("padding: {:?}", padding);
        let mut input_bin: String = format!("{}{}1", ems_a2_c_be, seed_bin.clone());
        while input_bin.len() < 1024 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        // input_bin = input_bin.chars().rev().collect();
        let mut phash2_1_msg: String = (input_bin.clone())[0..512].to_string();
        phash2_1_msg = phash2_1_msg.chars().rev().collect();

        handle_emp_2pc_tls12_sha256(
            phash2_1_msg,
            ipad_le.clone(),
            phash2_1_filename.clone(),
            target_ip.clone()
        );

        let fs_phash2_1 = format!("{}{}", emp_path, phash2_1_filename.clone());
        let mut ems_phash2_1_c_le = fs::read_to_string(fs_phash2_1).expect("failed reading");
        println!("Client share: {:?}", ems_phash2_1_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_phash2_1_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_phash2_1_v_le);

        // let ems_phash2_1_c_be: String = ems_phash2_1_c_le.chars().rev().collect();
        // let ems_phash2_1_v_be: String = ems_phash2_1_v_le.chars().rev().collect();
        // let mut ems_phash_2_1_be = string_xor(ems_phash2_1_c_be.clone(), ems_phash2_1_v_be.clone());

        // let ems_phash_2_1_state: digest::State = be_bin_string_to_state(ems_phash_2_1_be);

        let mut phash2_2_msg: String = (input_bin.clone())[512..1024].to_string();
        phash2_2_msg = phash2_2_msg.chars().rev().collect();
        call_emp_2pc_hmac_expand(
            phash2_2_msg,
            ems_phash2_1_c_le.clone(),
            opad_le.clone(),
            phash2_2_filename.clone(),
            target_ip.clone()
        );

        let fs_phash2_2 = format!("{}{}", emp_path, phash2_2_filename.clone());
        let mut ems_phash2_2_c_le = fs::read_to_string(fs_phash2_2).expect("failed reading");
        println!("Client share: {:?}", ems_phash2_2_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_phash2_2_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_phash2_2_v_le);

        // let ems_phash2_2_c_be: String = ems_phash2_2_c_le.chars().rev().collect();
        // let ems_phash2_2_v_be: String = ems_phash2_2_v_le.chars().rev().collect();
        // let mut ems_phash_2_2_be = string_xor(ems_phash2_2_c_be.clone(), ems_phash2_2_v_be.clone());

        // let ems_phash_2_2_state: digest::State = be_bin_string_to_state(ems_phash_2_2_be);
        println!("====== End: 2PC-HMAC (P_hash[2]) ======");

        println!("====== Start: 2PC-HMAC (A3) ======");
        // message input of A3
        let ems_a2_c_be: String = ems_a2_c_le.chars().rev().collect();
        let mut padding = format!("{:b}", ems_a2_c_be.len()+512);
        println!("padding: {:?}", padding);
        let mut input_bin = format!("{}1", ems_a2_c_be.clone());
        while input_bin.len() < 512 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        input_bin = input_bin.chars().rev().collect();

        handle_emp_2pc_tls12_expand(
            input_bin,
            ipad_le.clone(),
            opad_le.clone(),
            a3_filename.clone(),
            target_ip.clone()
        );
        let fs_a3 = format!("{}{}", emp_path, a3_filename.clone());
        let mut ems_a3_c_le = fs::read_to_string(fs_a3).expect("failed reading");
        println!("Client share: {:?}", ems_a3_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_a3_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_a3_v_le);

        // let ems_a3_c_be: String = ems_a3_c_le.chars().rev().collect();
        // let ems_a3_v_be: String = ems_a3_v_le.chars().rev().collect();
        // let mut ems_a3_be = string_xor(ems_a3_c_be.clone(), ems_a3_v_be.clone());

        // let ems_a3_state: digest::State = be_bin_string_to_state(ems_a3_be.clone());
        println!("====== End: 2PC-HMAC (A3) ======");

        let ems_phash1_2_c_be: String = ems_phash1_2_c_le.chars().rev().collect();
        let ems_phash2_2_c_be: String = ems_phash2_2_c_le.chars().rev().collect();
        let phash_1_vec = be_bin_string_to_vec_u8(ems_phash1_2_c_be.clone());
        let phash_2_vec = be_bin_string_to_vec_u8(ems_phash2_2_c_be.clone());
        // let phash_1_vec = be_bin_string_to_vec_u8(ems_phash_1_2_be.clone());
        // let phash_2_vec = be_bin_string_to_vec_u8(ems_phash_2_2_be.clone());
        let mut output: [u8; 48] = [0; 48];
        for i in 0..32 {
            output[i] = phash_1_vec[i];
        }
        for i in 32..48 {
            output[i] = phash_2_vec[i-32];
        }

        println!("out: {:?}", output);

        output
    }

    pub fn deco_tls12_ms_recursive_hmac(
        algorithm: Algorithm, 
        seed: &[u8],
        target_ip_with_port: &str,
        target_ip: &str,
        key_ipad_filename: String,
        key_opad_filename: String,
        a1_1_filename: String,
        a1_2_filename: String,
        a2_filename: String,
        a3_filename: String,
        phash1_1_filename: String,
        phash1_2_filename: String,
        phash2_1_filename: String,
        phash2_2_filename: String,
    ) -> [u8; 48] {
        let fs: String = String::from(emp_path);

        // Get key shares
        let fs_ipad = format!("{}{}", fs, key_ipad_filename);
        let mut ipad_le = fs::read_to_string(fs_ipad).expect("failed reading");

        let fs_opad = format!("{}{}", fs, key_opad_filename);
        let mut opad_le = fs::read_to_string(fs_opad).expect("failed reading");
        
        // For A1
        println!("====== Start: 2PC-HMAC (A1) ======");
        // seed binary
        let seed_length: usize = seed.len() * 8;
        let padding: String = format!("{:b}", seed_length+512);
        println!("padding: {:?}", padding);
        let mut seed_bin: String = String::new();
        for i in 0..seed.len() {
            let mut entry = format!("{:b}", seed[i]);
            while entry.len() < 8 {
                entry = format!("{}{}", "0", entry);
            }
            seed_bin = format!("{}{}", seed_bin, entry);
        }

        // message input of A1
        let mut input_bin = format!("{}1", seed_bin.clone());
        while input_bin.len() < 1024 - padding.len() { // 512+512
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        // input_bin = input_bin.chars().rev().collect();

        let mut a1_1_msg: String = (input_bin.clone())[0..512].to_string();
        a1_1_msg = a1_1_msg.chars().rev().collect();

        handle_emp_2pc_tls12_sha256(
            a1_1_msg,
            ipad_le.clone(),
            a1_1_filename.clone(),
            target_ip.clone()
        );

        let fs_a1_1 = format!("{}{}", emp_path, a1_1_filename.clone());
        let mut ems_a1_1_c_le = fs::read_to_string(fs_a1_1).expect("failed reading");
        println!("Client share: {:?}", ems_a1_1_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_a1_1_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_a1_1_v_le);

        // let ems_a1_1_c_be: String = ems_a1_1_c_le.chars().rev().collect();
        // let ems_a1_1_v_be: String = ems_a1_1_v_le.chars().rev().collect();
        // let mut ems_phash_1_1_be = string_xor(ems_a1_1_c_be.clone(), ems_a1_1_v_be.clone());

        // let ems_a1_1_state: digest::State = be_bin_string_to_state(ems_phash_1_1_be);

        let mut a1_2_msg: String = (input_bin.clone())[512..1024].to_string();
        a1_2_msg = a1_2_msg.chars().rev().collect();
        call_emp_2pc_hmac_expand(
            a1_2_msg,
            ems_a1_1_c_le.clone(),
            opad_le.clone(),
            a1_2_filename.clone(),
            target_ip.clone()
        );

        let fs_a1_2 = format!("{}{}", emp_path, a1_2_filename.clone());
        let mut ems_a1_2_c_le = fs::read_to_string(fs_a1_2).expect("failed reading");
        println!("Client share: {:?}", ems_a1_2_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_a1_2_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_a1_2_v_le);

        // let ems_a1_2_c_be: String = ems_a1_2_c_le.chars().rev().collect();
        // let ems_a1_2_v_be: String = ems_a1_2_v_le.chars().rev().collect();
        // let mut ems_a1_2_be = string_xor(ems_a1_2_c_be.clone(), ems_a1_2_v_be.clone());

        // let ems_a1_2_state: digest::State = be_bin_string_to_state(ke_a1_2_be);
        println!("====== End: 2PC-HMAC (A1) ======");

        println!("====== Start: 2PC-HMAC (P_hash[1]) ======");
        // message input of A1
        let ems_a1_c_be: String = ems_a1_2_c_le.chars().rev().collect();
        let padding: String = format!("{:b}", seed_length+256+512);
        println!("padding: {:?}", padding);
        let mut input_bin: String = format!("{}{}1", ems_a1_c_be, seed_bin.clone());
        while input_bin.len() < 1024 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        // input_bin = input_bin.chars().rev().collect();
        let mut phash1_1_msg: String = (input_bin.clone())[0..512].to_string();
        phash1_1_msg = phash1_1_msg.chars().rev().collect();

        handle_emp_2pc_tls12_sha256(
            phash1_1_msg,
            ipad_le.clone(),
            phash1_1_filename.clone(),
            target_ip.clone()
        );

        let fs_phash1_1 = format!("{}{}", emp_path, phash1_1_filename.clone());
        let mut ems_phash1_1_c_le = fs::read_to_string(fs_phash1_1).expect("failed reading");
        println!("Client share: {:?}", ems_phash1_1_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_phash1_1_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_phash1_1_v_le);

        // let ems_phash1_1_c_be: String = ems_phash1_1_c_le.chars().rev().collect();
        // let ems_phash1_1_v_be: String = ems_phash1_1_v_le.chars().rev().collect();
        // let mut ems_phash_1_1_be = string_xor(ems_phash1_1_c_be.clone(), ems_phash1_1_v_be.clone());

        // let ems_phash_1_1_state: digest::State = be_bin_string_to_state(ems_phash_1_1_be);

        let mut phash1_2_msg: String = (input_bin.clone())[512..1024].to_string();
        phash1_2_msg = phash1_2_msg.chars().rev().collect();
        call_emp_2pc_hmac_expand(
            phash1_2_msg,
            ems_phash1_1_c_le.clone(),
            opad_le.clone(),
            phash1_2_filename.clone(),
            target_ip.clone()
        );

        let fs_phash1_2 = format!("{}{}", emp_path, phash1_2_filename.clone());
        let mut ems_phash1_2_c_le = fs::read_to_string(fs_phash1_2).expect("failed reading");
        println!("Client share: {:?}", ems_phash1_2_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_phash1_2_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_phash1_2_v_le);

        // let ems_phash1_2_c_be: String = ems_phash1_2_c_le.chars().rev().collect();
        // let ems_phash1_2_v_be: String = ems_phash1_2_v_le.chars().rev().collect();
        // let mut ems_phash_1_2_be = string_xor(ems_phash1_2_c_be.clone(), ems_phash1_2_v_be.clone());

        // let ems_phash_1_2_state: digest::State = be_bin_string_to_state(ems_phash_1_2_be);
        println!("====== End: 2PC-HMAC (P_hash[1]) ======");

        println!("====== Start: 2PC-HMAC (A2) ======");
        // message input of A2
        let ems_a1_c_be: String = ems_a1_2_c_le.chars().rev().collect();
        let mut padding = format!("{:b}", ems_a1_c_be.len()+512);
        println!("padding: {:?}", padding);
        let mut input_bin = format!("{}1", ems_a1_c_be.clone());
        while input_bin.len() < 512 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        input_bin = input_bin.chars().rev().collect();

        handle_emp_2pc_tls12_expand(
            input_bin,
            ipad_le.clone(),
            opad_le.clone(),
            a2_filename.clone(),
            target_ip.clone()
        );
        let fs_a2 = format!("{}{}", emp_path, a2_filename.clone());
        let mut ems_a2_c_le = fs::read_to_string(fs_a2).expect("failed reading");
        println!("Client share: {:?}", ems_a2_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_a2_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_a2_v_le);

        // let ems_a2_c_be: String = ems_a2_c_le.chars().rev().collect();
        // let ems_a2_v_be: String = ems_a2_v_le.chars().rev().collect();
        // let mut ems_a2_be = string_xor(ems_a2_c_be.clone(), ems_a2_v_be.clone());

        // let ems_a2_state: digest::State = be_bin_string_to_state(ems_a2_be);
        println!("====== End: 2PC-HMAC (A2) ======");

        println!("====== Start: 2PC-HMAC (P_hash[2]) ======");
        // message input of A2
        let ems_a2_c_be: String = ems_a2_c_le.chars().rev().collect();
        let padding: String = format!("{:b}", seed_length+256+512);
        println!("padding: {:?}", padding);
        let mut input_bin: String = format!("{}{}1", ems_a2_c_be, seed_bin.clone());
        while input_bin.len() < 1024 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        // input_bin = input_bin.chars().rev().collect();
        let mut phash2_1_msg: String = (input_bin.clone())[0..512].to_string();
        phash2_1_msg = phash2_1_msg.chars().rev().collect();

        handle_emp_2pc_tls12_sha256(
            phash2_1_msg,
            ipad_le.clone(),
            phash2_1_filename.clone(),
            target_ip.clone()
        );

        let fs_phash2_1 = format!("{}{}", emp_path, phash2_1_filename.clone());
        let mut ems_phash2_1_c_le = fs::read_to_string(fs_phash2_1).expect("failed reading");
        println!("Client share: {:?}", ems_phash2_1_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_phash2_1_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_phash2_1_v_le);

        // let ems_phash2_1_c_be: String = ems_phash2_1_c_le.chars().rev().collect();
        // let ems_phash2_1_v_be: String = ems_phash2_1_v_le.chars().rev().collect();
        // let mut ems_phash_2_1_be = string_xor(ems_phash2_1_c_be.clone(), ems_phash2_1_v_be.clone());

        // let ems_phash_2_1_state: digest::State = be_bin_string_to_state(ems_phash_2_1_be);

        let mut phash2_2_msg: String = (input_bin.clone())[512..1024].to_string();
        phash2_2_msg = phash2_2_msg.chars().rev().collect();
        call_emp_2pc_hmac_expand(
            phash2_2_msg,
            ems_phash2_1_c_le.clone(),
            opad_le.clone(),
            phash2_2_filename.clone(),
            target_ip.clone()
        );

        let fs_phash2_2 = format!("{}{}", emp_path, phash2_2_filename.clone());
        let mut ems_phash2_2_c_le = fs::read_to_string(fs_phash2_2).expect("failed reading");
        println!("Client share: {:?}", ems_phash2_2_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_phash2_2_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_phash2_2_v_le);

        // let ems_phash2_2_c_be: String = ems_phash2_2_c_le.chars().rev().collect();
        // let ems_phash2_2_v_be: String = ems_phash2_2_v_le.chars().rev().collect();
        // let mut ems_phash_2_2_be = string_xor(ems_phash2_2_c_be.clone(), ems_phash2_2_v_be.clone());

        // let ems_phash_2_2_state: digest::State = be_bin_string_to_state(ems_phash_2_2_be);
        println!("====== End: 2PC-HMAC (P_hash[2]) ======");

        println!("====== Start: 2PC-HMAC (A3) ======");
        // message input of A3
        let ems_a2_c_be: String = ems_a2_c_le.chars().rev().collect();
        let mut padding = format!("{:b}", ems_a2_c_be.len()+512);
        println!("padding: {:?}", padding);
        let mut input_bin = format!("{}1", ems_a2_c_be.clone());
        while input_bin.len() < 512 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        input_bin = input_bin.chars().rev().collect();

        handle_emp_2pc_tls12_expand(
            input_bin,
            ipad_le.clone(),
            opad_le.clone(),
            a3_filename.clone(),
            target_ip.clone()
        );
        let fs_a3 = format!("{}{}", emp_path, a3_filename.clone());
        let mut ems_a3_c_le = fs::read_to_string(fs_a3).expect("failed reading");
        println!("Client share: {:?}", ems_a3_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let ems_a3_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", ems_a3_v_le);

        // let ems_a3_c_be: String = ems_a3_c_le.chars().rev().collect();
        // let ems_a3_v_be: String = ems_a3_v_le.chars().rev().collect();
        // let mut ems_a3_be = string_xor(ems_a3_c_be.clone(), ems_a3_v_be.clone());

        // let ems_a3_state: digest::State = be_bin_string_to_state(ems_a3_be.clone());
        println!("====== End: 2PC-HMAC (A3) ======");

        let ems_phash1_2_c_be: String = ems_phash1_2_c_le.chars().rev().collect();
        let ems_phash2_2_c_be: String = ems_phash2_2_c_le.chars().rev().collect();
        let phash_1_vec = be_bin_string_to_vec_u8(ems_phash1_2_c_be.clone());
        let phash_2_vec = be_bin_string_to_vec_u8(ems_phash2_2_c_be.clone());
        // let phash_1_vec = be_bin_string_to_vec_u8(ems_phash_1_2_be.clone());
        // let phash_2_vec = be_bin_string_to_vec_u8(ems_phash_2_2_be.clone());
        let mut output: [u8; 48] = [0; 48];
        for i in 0..32 {
            output[i] = phash_1_vec[i];
        }
        for i in 32..48 {
            output[i] = phash_2_vec[i-32];
        }

        println!("out: {:?}", output);

        output
    }

    pub fn deco_tls12_cf_sf_recursive_hmac(
        algorithm: Algorithm, 
        seed: &[u8],
        target_ip_with_port: &str,
        target_ip: &str,
        key_ipad_filename: String,
        key_opad_filename: String,
        a1_filename: String,
        a2_filename: String,
        phash1_1_filename: String,
        phash1_2_filename: String,
    ) -> [u8; 12] {
        let fs: String = String::from(emp_path);

        // Get key shares
        let fs_ipad = format!("{}{}", fs, key_ipad_filename);
        let mut ipad_le = fs::read_to_string(fs_ipad).expect("failed reading");

        let fs_opad = format!("{}{}", fs, key_opad_filename);
        let mut opad_le = fs::read_to_string(fs_opad).expect("failed reading");
        
        // For A1
        println!("====== Start: 2PC-HMAC (A1) ======");
        // seed binary
        let seed_length: usize = seed.len() * 8;
        let padding: String = format!("{:b}", seed_length+512);
        println!("padding: {:?}", padding);
        let mut seed_bin: String = String::new();
        for i in 0..seed.len() {
            let mut entry = format!("{:b}", seed[i]);
            while entry.len() < 8 {
                entry = format!("{}{}", "0", entry);
            }
            seed_bin = format!("{}{}", seed_bin, entry);
        }

        // message input of A1
        let mut input_bin = format!("{}1", seed_bin.clone());
        while input_bin.len() < 512 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        input_bin = input_bin.chars().rev().collect();

        call_emp_2pc_hmac_expand(
            input_bin,
            ipad_le.clone(),
            opad_le.clone(),
            a1_filename.clone(),
            target_ip.clone()
        );
        let fs_a1 = format!("{}{}", emp_path, a1_filename.clone());
        let mut cf_a1_c_le = fs::read_to_string(fs_a1).expect("failed reading");
        println!("Client share: {:?}", cf_a1_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let cf_a1_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", cf_a1_v_le);

        // let cf_a1_c_be: String = cf_a1_c_le.chars().rev().collect();
        // let cf_a1_v_be: String = cf_a1_v_le.chars().rev().collect();
        // let mut cf_a1_be = string_xor(cf_a1_c_be.clone(), cf_a1_v_be.clone());

        // let cf_a1_state: digest::State = be_bin_string_to_state(cf_a1_be);
        println!("====== End: 2PC-HMAC (A1) ======");

        println!("====== Start: 2PC-HMAC (P_hash[1]) ======");
        // message input of A1
        let cf_a1_c_be: String = cf_a1_c_le.chars().rev().collect();
        let padding: String = format!("{:b}", seed_length+256+512);
        println!("padding: {:?}", padding);
        let mut input_bin: String = format!("{}{}1", cf_a1_c_be, seed_bin.clone());
        while input_bin.len() < 1024 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        // input_bin = input_bin.chars().rev().collect();
        let mut phash1_1_msg: String = (input_bin.clone())[0..512].to_string();
        phash1_1_msg = phash1_1_msg.chars().rev().collect();

        handle_emp_2pc_tls12_sha256(
            phash1_1_msg,
            ipad_le.clone(),
            phash1_1_filename.clone(),
            target_ip.clone()
        );

        let fs_phash1_1 = format!("{}{}", emp_path, phash1_1_filename.clone());
        let mut cf_phash1_1_c_le = fs::read_to_string(fs_phash1_1).expect("failed reading");
        println!("Client share: {:?}", cf_phash1_1_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let cf_phash1_1_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", cf_phash1_1_v_le);

        // let cf_phash1_1_c_be: String = cf_phash1_1_c_le.chars().rev().collect();
        // let cf_phash1_1_v_be: String = cf_phash1_1_v_le.chars().rev().collect();
        // let mut cf_phash_1_1_be = string_xor(cf_phash1_1_c_be.clone(), cf_phash1_1_v_be.clone());

        // let cf_phash_1_1_state: digest::State = be_bin_string_to_state(cf_phash_1_1_be);

        let mut phash1_2_msg: String = (input_bin.clone())[512..1024].to_string();
        phash1_2_msg = phash1_2_msg.chars().rev().collect();
        call_emp_2pc_hmac_expand(
            phash1_2_msg,
            cf_phash1_1_c_le.clone(),
            opad_le.clone(),
            phash1_2_filename.clone(),
            target_ip.clone()
        );

        let fs_phash1_2 = format!("{}{}", emp_path, phash1_2_filename.clone());
        let mut cf_phash1_2_c_le = fs::read_to_string(fs_phash1_2).expect("failed reading");
        println!("Client share: {:?}", cf_phash1_2_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let cf_phash1_2_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", cf_phash1_2_v_le);

        // let cf_phash1_2_c_be: String = cf_phash1_2_c_le.chars().rev().collect();
        // let cf_phash1_2_v_be: String = cf_phash1_2_v_le.chars().rev().collect();
        // let mut cf_phash_1_2_be = string_xor(cf_phash1_2_c_be.clone(), cf_phash1_2_v_be.clone());

        // let cf_phash_1_2_state: digest::State = be_bin_string_to_state(cf_phash_1_2_be);
        println!("====== End: 2PC-HMAC (P_hash[1]) ======");

        println!("====== Start: 2PC-HMAC (A2) ======");
        // message input of A2
        let cf_a1_c_be: String = cf_a1_c_le.chars().rev().collect();
        let mut padding = format!("{:b}", cf_a1_c_be.len()+512);
        println!("padding: {:?}", padding);
        let mut input_bin = format!("{}1", cf_a1_c_be.clone());
        while input_bin.len() < 512 - padding.len() {
            input_bin = format!("{}{}", input_bin, "0");
        }
        input_bin = format!("{}{}", input_bin, padding);
        println!("input_bin: {:?}", input_bin);
        input_bin = input_bin.chars().rev().collect();

        handle_emp_2pc_tls12_expand(
            input_bin,
            ipad_le.clone(),
            opad_le.clone(),
            a2_filename.clone(),
            target_ip.clone()
        );
        let fs_a2 = format!("{}{}", emp_path, a2_filename.clone());
        let mut cf_a2_c_le = fs::read_to_string(fs_a2).expect("failed reading");
        println!("Client share: {:?}", cf_a2_c_le);

        // let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        // let cf_a2_v_le = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", cf_a2_v_le);

        // let cf_a2_c_be: String = cf_a2_c_le.chars().rev().collect();
        // let cf_a2_v_be: String = cf_a2_v_le.chars().rev().collect();
        // let mut cf_a2_be = string_xor(cf_a2_c_be.clone(), cf_a2_v_be.clone());

        // let cf_a2_state: digest::State = be_bin_string_to_state(cf_a2_be);
        println!("====== End: 2PC-HMAC (A2) ======");

        let mut cf_phash1_2_c_be: String = cf_phash1_2_c_le.chars().rev().collect();
        cf_phash1_2_c_be = cf_phash1_2_c_be[0..96].to_string();

        let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        let cf_phash1_2_v_be = get_verifier_share(&stream);
        println!("cf_phash1_2_be Verifier share: {:?}", cf_phash1_2_v_be);
        
        let mut cf_phash1_2 = string_xor(cf_phash1_2_c_be.clone(), cf_phash1_2_v_be.clone());
        let cf_phash1_2_vec = be_bin_string_to_vec_u8(cf_phash1_2.clone());

        let mut output: [u8; 12] = [0; 12];
        for i in 0..12 {
            output[i] = cf_phash1_2_vec[i];
        }

        println!("out: {:?}", output);

        output
    }

    // [DECO]
    pub fn call_2pc_hmac_key_iopad_set_vc(
        algorithm: Algorithm, 
        fs_client_share_file_name: String, 
        ipad_output_file_name: String, 
        opad_output_file_name: String,
        target_ip_with_port: &str,
        target_ip: &str
    ) 
    -> Self {

        let digest_alg = algorithm.0;
        // println!("digest_alg: {:?}", digest_alg);
        let mut key = Self {
            inner: digest::BlockContext::new(digest_alg),
            outer: digest::BlockContext::new(digest_alg),
        };

        // Get the client share of 2PC-HMAC shared msg
        use std::env;
        use std::fs;
        // let fs_client_share = "./rustls/src/emp/emp-ag2pc/2pc_hmac/msg_client_share_le.txt";
        let mut client_share = fs::read_to_string(fs_client_share_file_name).expect("failed reading");
        println!("Client share: {:?}", client_share);

        let mut client_share_be: String = client_share.chars().rev().collect();
        for i in 0..256 {
            client_share_be = format!("{}{}", client_share_be, "0");
        }
        println!("client_share_be: {}", client_share_be);

        // Handle padding to 512 bits
        let ipad_one_byte = String::from("00110110"); // 0x36
        let opad_one_byte = String::from("01011100"); // 0x5C
        let mut ipad = String::new();
        let mut opad = String::new();
        for i in 0..64 {
            ipad = format!("{}{}", ipad, ipad_one_byte);
            opad = format!("{}{}", opad, opad_one_byte);
        }
        println!("ipad: {}", ipad);
        println!("opad: {}", opad);

        // HS client share XOR padding
        // let client_share_be: String = client_share.chars().rev().collect();
        let mut client_share_ipad_be = string_xor(client_share_be.clone(), ipad.clone());
        let mut client_share_opad_be = string_xor(client_share_be.clone(), opad.clone());

        let client_share_ipad_le: String = client_share_ipad_be.chars().rev().collect();
        let client_share_opad_le: String = client_share_opad_be.chars().rev().collect();
        println!("client_share_ipad_le: {}", client_share_ipad_le);
        println!("client_share_opad_le: {}", client_share_opad_le);
        
        // Run emp
        call_emp_2pc_hmac_key_iopad(client_share_ipad_le.clone(), ipad_output_file_name.clone(), target_ip.clone());

        // Get the HS with ipad
        // let fs = "./rustls/src/emp/emp-ag2pc/2pc_hmac/";
        let fs_key_ipad: String = format!("{}{}", emp_path, ipad_output_file_name);
        let key_ipad_le_c = fs::read_to_string(fs_key_ipad).expect("failed reading");

        // Get verifier shares
        let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        let key_ipad_le_v = get_verifier_share(&stream);
        println!("Verifier share: {:?}", key_ipad_le_v);

        // Run emp
        call_emp_2pc_hmac_key_iopad(client_share_opad_le.clone(), opad_output_file_name.clone(), target_ip.clone());

        // Get the HS with opad
        let fs_key_opad: String = format!("{}{}", emp_path, opad_output_file_name);
        let key_opad_le_c = fs::read_to_string(fs_key_opad).expect("failed reading");

        // Get verifier shares
        let mut stream = TcpStream::connect(target_ip_with_port).unwrap();
        let key_opad_le_v = get_verifier_share(&stream);
        println!("Verifier share: {:?}", key_opad_le_v);

        let key_ipad_le = string_xor(key_ipad_le_c, key_ipad_le_v);
        let key_opad_le = string_xor(key_opad_le_c, key_opad_le_v);

        let key_ipad_be: String = key_ipad_le.chars().rev().collect();
        let key_opad_be: String = key_opad_le.chars().rev().collect();

        let key_ipad_state: digest::State = be_bin_string_to_state(key_ipad_be);
        let key_opad_state: digest::State = be_bin_string_to_state(key_opad_be);

        key.inner.update_with_states(key_ipad_state);
        key.outer.update_with_states(key_opad_state);

        key
    }

    // [DECO]
    pub fn call_2pc_hmac_key_iopad_set_cv(
        algorithm: Algorithm, 
        fs_client_share_file_name: String, 
        ipad_output_file_name: String, 
        opad_output_file_name: String,
        my_ip_with_port: &str,
        target_ip: &str
    ) 
    -> Self {

        use std::net::TcpListener;
        let listener = TcpListener::bind(my_ip_with_port).unwrap();

        let digest_alg = algorithm.0;
        // println!("digest_alg: {:?}", digest_alg);
        let mut key = Self {
            inner: digest::BlockContext::new(digest_alg),
            outer: digest::BlockContext::new(digest_alg),
        };

        // Get the client share of 2PC-HMAC shared msg
        use std::env;
        use std::fs;
        // let fs_client_share = "./rustls/src/emp/emp-ag2pc/2pc_hmac/msg_client_share_le.txt";
        let mut client_share = fs::read_to_string(fs_client_share_file_name).expect("failed reading");
        println!("Client share: {:?}", client_share);

        let mut client_share_be: String = client_share.chars().rev().collect();
        for i in 0..256 {
            client_share_be = format!("{}{}", client_share_be, "0");
        }
        println!("client_share_be: {}", client_share_be);

        // Handle padding to 512 bits
        let ipad_one_byte = String::from("00110110"); // 0x36
        let opad_one_byte = String::from("01011100"); // 0x5C
        let mut ipad = String::new();
        let mut opad = String::new();
        for i in 0..64 {
            ipad = format!("{}{}", ipad, ipad_one_byte);
            opad = format!("{}{}", opad, opad_one_byte);
        }
        println!("ipad: {}", ipad);
        println!("opad: {}", opad);

        // HS client share XOR padding
        // let client_share_be: String = client_share.chars().rev().collect();
        let mut client_share_ipad_be = string_xor(client_share_be.clone(), ipad.clone());
        let mut client_share_opad_be = string_xor(client_share_be.clone(), opad.clone());

        let client_share_ipad_le: String = client_share_ipad_be.chars().rev().collect();
        let client_share_opad_le: String = client_share_opad_be.chars().rev().collect();
        println!("client_share_ipad_le: {}", client_share_ipad_le);
        println!("client_share_opad_le: {}", client_share_opad_le);
        
        // Run emp
        call_emp_2pc_hmac_key_iopad(client_share_ipad_le.clone(), ipad_output_file_name.clone(), target_ip.clone());

        // Get the HS with ipad
        // let fs = "./rustls/src/emp/emp-ag2pc/2pc_hmac/";
        let fs_key_ipad: String = format!("{}{}", emp_path, ipad_output_file_name);
        let key_ipad_le_c = fs::read_to_string(fs_key_ipad).expect("failed reading");

        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        stream.write(&key_ipad_le_c.as_bytes()).unwrap();
        // println!("CHECK key_ipad_le_c: {}", key_ipad_le_c);
        // Get verifier shares
        // let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();
        // let key_ipad_le_v = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", key_ipad_le_v);

        // Run emp
        call_emp_2pc_hmac_key_iopad(client_share_opad_le.clone(), opad_output_file_name.clone(), target_ip.clone());

        // Get the HS with opad
        let fs_key_opad: String = format!("{}{}", emp_path, opad_output_file_name);
        let key_opad_le_c = fs::read_to_string(fs_key_opad).expect("failed reading");

        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        stream.write(&key_opad_le_c.as_bytes()).unwrap();
        // println!("CHECK key_opad_le_c: {}", key_opad_le_c);
        // Get verifier shares
        // let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();
        // let key_opad_le_v = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", key_opad_le_v);

        // let key_ipad_le = string_xor(key_ipad_le_c, key_ipad_le_v);
        // let key_opad_le = string_xor(key_opad_le_c, key_opad_le_v);

        // let key_ipad_be: String = key_ipad_le.chars().rev().collect();
        // let key_opad_be: String = key_opad_le.chars().rev().collect();

        // let key_ipad_state: digest::State = be_bin_string_to_state(key_ipad_be);
        // let key_opad_state: digest::State = be_bin_string_to_state(key_opad_be);
        let dumpy_output_str = String::from("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let dumpy_output_state: digest::State = be_bin_string_to_state(dumpy_output_str);

        key.inner.update_with_states(dumpy_output_state);
        key.outer.update_with_states(dumpy_output_state);

        key
    }

    // [DECO]
    pub fn call_2pc_hmac_key_iopad_set_no_communication(
        algorithm: Algorithm, 
        fs_client_share_file_name: String, 
        ipad_output_file_name: String, 
        opad_output_file_name: String,
        target_ip: &str
    ) -> Self {

        let digest_alg = algorithm.0;
        // println!("digest_alg: {:?}", digest_alg);
        let mut key = Self {
            inner: digest::BlockContext::new(digest_alg),
            outer: digest::BlockContext::new(digest_alg),
        };

        // Get the client share of 2PC-HMAC shared msg
        use std::env;
        use std::fs;
        // let fs_client_share = "./rustls/src/emp/emp-ag2pc/2pc_hmac/msg_client_share_le.txt";
        let mut client_share = fs::read_to_string(fs_client_share_file_name).expect("failed reading");
        println!("Client share: {:?}", client_share);

        let mut client_share_be: String = client_share.chars().rev().collect();
        for i in 0..256 {
            client_share_be = format!("{}{}", client_share_be, "0");
        }
        println!("client_share_be: {}", client_share_be);

        // Handle padding to 512 bits
        let ipad_one_byte = String::from("00110110"); // 0x36
        let opad_one_byte = String::from("01011100"); // 0x5C
        let mut ipad = String::new();
        let mut opad = String::new();
        for i in 0..64 {
            ipad = format!("{}{}", ipad, ipad_one_byte);
            opad = format!("{}{}", opad, opad_one_byte);
        }
        println!("ipad: {}", ipad);
        println!("opad: {}", opad);

        // HS client share XOR padding
        // let client_share_be: String = client_share.chars().rev().collect();
        let mut client_share_ipad_be = string_xor(client_share_be.clone(), ipad.clone());
        let mut client_share_opad_be = string_xor(client_share_be.clone(), opad.clone());

        let client_share_ipad_le: String = client_share_ipad_be.chars().rev().collect();
        let client_share_opad_le: String = client_share_opad_be.chars().rev().collect();
        println!("client_share_ipad_le: {}", client_share_ipad_le);
        println!("client_share_opad_le: {}", client_share_opad_le);
        
        // Run emp
        call_emp_2pc_hmac_key_iopad(client_share_ipad_le.clone(), ipad_output_file_name.clone(), target_ip.clone());

        // Get the HS with ipad
        // let fs = "./rustls/src/emp/emp-ag2pc/2pc_hmac/";
        // let fs_key_ipad: String = format!("{}{}", fs, ipad_output_file_name);
        // let key_ipad_le_c = fs::read_to_string(fs_key_ipad).expect("failed reading");

        // Get verifier shares
        // let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();
        // let key_ipad_le_v = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", key_ipad_le_v);

        // Run emp
        call_emp_2pc_hmac_key_iopad(client_share_opad_le.clone(), opad_output_file_name.clone(), target_ip.clone());

        // Get the HS with opad
        // let fs_key_opad: String = format!("{}{}", fs, opad_output_file_name);
        // let key_opad_le_c = fs::read_to_string(fs_key_opad).expect("failed reading");

        // Get verifier shares
        // let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();
        // let key_opad_le_v = get_verifier_share(&stream);
        // println!("Verifier share: {:?}", key_opad_le_v);

        // let key_ipad_le = string_xor(key_ipad_le_c, key_ipad_le_v);
        // let key_opad_le = string_xor(key_opad_le_c, key_opad_le_v);

        // let key_ipad_be: String = key_ipad_le.chars().rev().collect();
        // let key_opad_be: String = key_opad_le.chars().rev().collect();

        // let key_ipad_state: digest::State = be_bin_string_to_state(key_ipad_be);
        // let key_opad_state: digest::State = be_bin_string_to_state(key_opad_be);

        // key.inner.update_with_states(key_ipad_state);
        // key.outer.update_with_states(key_opad_state);

        key
    }
}

// [DECO]
pub fn get_dumpy_key(
    algorithm: Algorithm, 
) -> Key {

    let digest_alg = algorithm.0;
    // println!("digest_alg: {:?}", digest_alg);
    let mut key = Key {
        inner: digest::BlockContext::new(digest_alg),
        outer: digest::BlockContext::new(digest_alg),
    };

    let dumpy_output_str = String::from("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    let dumpy_output_state: digest::State = be_bin_string_to_state(dumpy_output_str);

    key.inner.update_with_states(dumpy_output_state);
    key.outer.update_with_states(dumpy_output_state);

    key
}


// [DECO]
pub fn be_bin_to_key(
    be_bin_ipad: String,
    be_bin_opad: String,
    algorithm: Algorithm, 
) -> Key {
    
    let digest_alg = algorithm.0;
    // println!("digest_alg: {:?}", digest_alg);
    let mut key = Key {
        inner: digest::BlockContext::new(digest_alg),
        outer: digest::BlockContext::new(digest_alg),
    };

    let key_ipad_state: digest::State = be_bin_string_to_state(be_bin_ipad);
    let key_opad_state: digest::State = be_bin_string_to_state(be_bin_opad);

    key.inner.update_with_states(key_ipad_state);
    key.outer.update_with_states(key_opad_state);

    key
}

impl hkdf::KeyType for Algorithm {
    fn len(&self) -> usize {
        self.digest_algorithm().output_len
    }
}

impl From<hkdf::Okm<'_, Algorithm>> for Key {
    fn from(okm: hkdf::Okm<Algorithm>) -> Self {
        Key::construct(*okm.len(), |buf| okm.fill(buf)).unwrap()
    }
}

/// A context for multi-step (Init-Update-Finish) HMAC signing.
///
/// Use `sign` for single-step HMAC signing.
#[derive(Clone)]
pub struct Context {
    inner: digest::Context,
    outer: digest::BlockContext,
}

/// `hmac::SigningContext` was renamed to `hmac::Context`.
#[deprecated(note = "Renamed to `hmac::Context`.")]
pub type SigningContext = Context;

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("Context")
            .field("algorithm", self.inner.algorithm())
            .finish()
    }
}

impl Context {
    /// Constructs a new HMAC signing context using the given digest algorithm
    /// and key.
    pub fn with_key(signing_key: &Key) -> Self {
        Self {
            inner: digest::Context::clone_from(&signing_key.inner),
            outer: signing_key.outer.clone(),
        }
    }

    /// Updates the HMAC with all the data in `data`. `update` may be called
    /// zero or more times until `finish` is called.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes the HMAC calculation and returns the HMAC value. `sign`
    /// consumes the context so it cannot be (mis-)used after `sign` has been
    /// called.
    ///
    /// It is generally not safe to implement HMAC verification by comparing
    /// the return value of `sign` to a tag. Use `verify` for verification
    /// instead.
    pub fn sign(self) -> Tag {
        let algorithm = self.inner.algorithm();
        let mut pending = [0u8; digest::MAX_BLOCK_LEN];
        let pending = &mut pending[..algorithm.block_len];
        let num_pending = algorithm.output_len;
        pending[..num_pending].copy_from_slice(self.inner.finish().as_ref());
        Tag(self.outer.finish(pending, num_pending))
    }
}

/// Calculates the HMAC of `data` using the key `key` in one step.
///
/// Use `Context` to calculate HMACs where the input is in multiple parts.
///
/// It is generally not safe to implement HMAC verification by comparing the
/// return value of `sign` to a tag. Use `verify` for verification instead.
pub fn sign(key: &Key, data: &[u8]) -> Tag {
    let mut ctx = Context::with_key(key);
    ctx.update(data);
    ctx.sign()
}

/// Calculates the HMAC of `data` using the signing key `key`, and verifies
/// whether the resultant value equals `tag`, in one step.
///
/// This is logically equivalent to, but more efficient than, constructing a
/// `Key` with the same value as `key` and then using `verify`.
///
/// The verification will be done in constant time to prevent timing attacks.
pub fn verify(key: &Key, data: &[u8], tag: &[u8]) -> Result<(), error::Unspecified> {
    constant_time::verify_slices_are_equal(sign(key, data).as_ref(), tag)
}

// // [DECO] 
// pub fn handle_2pc_hmac_msg_client(input: String) -> Tag {

//     use std::net::TcpListener;
//     use std::net::TcpStream;
//     use std::thread;
//     use std::time;
//     use std::io::Read;

//     call_2pc_hmac_msg_client(input);

//     // For testing, get the verifier HS share immediately.

//     fn get_verifier_share(mut stream: &TcpStream) -> String {
//         let mut buf = [0; 256];
//         let read_bytes = stream.read(&mut buf).unwrap();
//         let vs_bit: Vec<u8> = buf[..read_bytes].to_vec();
//         let mut vs = String::new();
//         for i in 0..vs_bit.len() {
//             vs = format!("{}{}", vs, (vs_bit[i]-48).to_string());
//         }
//         vs
//     }

//     let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();
//     let verifier_share = get_verifier_share(&stream);
//     println!("Verifier share: {:?}", verifier_share);

//     use std::env;
//     use std::fs;
//     let fs_client_share = "./rustls/src/emp/emp-ag2pc/2pc_hmac/msg_client_share_le.txt";
//     let client_share = fs::read_to_string(fs_client_share).expect("failed reading");
//     println!("Client share: {:?}", client_share);
//     client_share

//     let mut after_xor = String::new();
//     for i in 0..client_share.len() {
//         if verifier_share.chars().nth(i).unwrap() == client_share.chars().nth(i).unwrap() {
//             after_xor = format!("{}{}", after_xor, "0");
//         }
//         else {
//             after_xor = format!("{}{}", after_xor, "1");
//         }
//     }   
//     println!("After XOR: {:?}", after_xor);
//     let after_xor_be: String = after_xor.chars().rev().collect();
//     println!("After XOR Big Endian: {:?}", after_xor_be);

//     let state: digest::State = be_bin_string_to_state(after_xor_be);

//     Tag(digest::new_digest(&digest::SHA256, state))
// }

#[cfg(test)]
mod tests {
    use crate::{hmac, rand};

    // Make sure that `Key::generate` and `verify_with_own_key` aren't
    // completely wacky.
    #[test]
    pub fn hmac_signing_key_coverage() {
        let rng = rand::SystemRandom::new();

        const HELLO_WORLD_GOOD: &[u8] = b"hello, world";
        const HELLO_WORLD_BAD: &[u8] = b"hello, worle";

        for algorithm in &[
            hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            hmac::HMAC_SHA256,
            hmac::HMAC_SHA384,
            hmac::HMAC_SHA512,
        ] {
            let key = hmac::Key::generate(*algorithm, &rng).unwrap();
            let tag = hmac::sign(&key, HELLO_WORLD_GOOD);
            assert!(hmac::verify(&key, HELLO_WORLD_GOOD, tag.as_ref()).is_ok());
            assert!(hmac::verify(&key, HELLO_WORLD_BAD, tag.as_ref()).is_err())
        }
    }
}

//[DECO]
pub fn call_emp_2pc_hmac_key_iopad(input: String,  output_file_name: String, target_ip: &str) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_hmac_key_iopad_client.sh")
                            .arg(input)
                            .arg(output_file_name)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("hello client, 2PC-HMAC for shared key! Set the key!");
}

//[DECO]
pub fn call_emp_2pc_hmac_expand(input: String, x_ipad: String, x_opad: String, output_file_name: String, target_ip: &str) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_hmac_expand_client.sh")
                            .arg(input)
                            .arg(x_ipad)
                            .arg(x_opad)
                            .arg(output_file_name)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("hello client, 2PC-HMAC for shared key! Expand!");
}

//[DECO]
fn handle_emp_2pc_tls12_expand(msg: String, ipad_state: String, opad_state: String, output: String, target_ip: &str) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_tls12_expand.sh")
                            .arg(msg)
                            .arg(ipad_state)
                            .arg(opad_state)
                            .arg(output)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("Make emp!");
}

//[DECO]
fn handle_emp_2pc_tls12_sha256(msg: String, state: String, output: String, target_ip: &str) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_tls12_sha256.sh")
                            .arg(msg)
                            .arg(state)
                            .arg(output)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("Make emp!");
}

// [DECO] 
pub fn call_emp_2pc_hmac_hs_msg_client(input: String, target_ip: &str) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_hmac_hs_msg_client.sh")
                            // .arg(ip)
                            .arg(input)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("hello client, 2PC-HMAC for shared message!");
}

// [DECO] 
pub fn call_emp_2pc_tls12_ems_s1s2sum(input: String, output_filename: String, target_ip: &str) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_tls12_ems_s1s2sum.sh")
                            // .arg(ip)
                            .arg(input)
                            .arg(output_filename)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("hello client, 2PC-HMAC for shared message!");
}

// [DECO] 
pub fn call_emp_2pc_tls12_ems_s1s2sum_secp256r1(input: String, output_filename: String, target_ip: &str) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_tls12_ems_s1s2sum_secp256r1.sh")
                            // .arg(ip)
                            .arg(input)
                            .arg(output_filename)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("hello client, 2PC-HMAC for shared message!");
}

// [DECO] 
pub fn call_emp_2pc_tls12_ems_s1s2sum_iopad(input: String, iopad: String, output_filename: String, target_ip: &str) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_tls12_ems_s1s2sum_iopad.sh")
                            // .arg(ip)
                            .arg(input)
                            .arg(iopad)
                            .arg(output_filename)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("hello client, 2PC-HMAC for shared message!");
}

// [DECO] 
pub fn handle_2pc_hmac_hs_msg_client(input: String, target_ip: &str) { // -> Tag {
    call_emp_2pc_hmac_hs_msg_client(input, target_ip);
}

// [DECO] helper
pub fn be_bin_string_to_vec_u8(input: String) -> Vec<u8> {

    // Truncate a string into 8-bit length each
    let mut input_vec: Vec<String> = Vec::new();
    let mut cur = input;
    while !cur.is_empty() {
        let (chunk, rest) = cur.split_at(8);
        input_vec.push(chunk.to_string());
        cur = rest.to_string();
    }
    println!("{:?}", input_vec);

    // binary -> u8
    let mut input_vec_u8: Vec<u8> = Vec::new();
    for i in 0..input_vec.len() {
        input_vec_u8.push(u8::from_str_radix(&input_vec[i], 2).unwrap());
    }
    println!("{:?}", input_vec_u8);

    input_vec_u8
}

// [DECO] helper
pub fn be_bin_string_to_state(input: String) -> digest::State {

    use core::num::Wrapping;

    // Truncate a string into 32-bit length each
    let mut input_vec: Vec<String> = Vec::new();
    let mut cur = input;
    while !cur.is_empty() {
        let (chunk, rest) = cur.split_at(32);
        input_vec.push(chunk.to_string());
        cur = rest.to_string();
    }
    println!("{:?}", input_vec);

    // binary -> u32
    let mut input_vec_u32: Vec<u32> = Vec::new();
    for i in 0..input_vec.len() {
        input_vec_u32.push(u32::from_str_radix(&input_vec[i], 2).unwrap());
    }
    println!("{:?}", input_vec_u32);

    let state = digest::State {
        as32: [
            Wrapping(input_vec_u32[0]),
            Wrapping(input_vec_u32[1]),
            Wrapping(input_vec_u32[2]),
            Wrapping(input_vec_u32[3]),
            Wrapping(input_vec_u32[4]),
            Wrapping(input_vec_u32[5]),
            Wrapping(input_vec_u32[6]),
            Wrapping(input_vec_u32[7]),
        ],
    };

    state

}

//[DECO] helper
pub fn string_xor(input1: String, input2: String) -> String {

    if input1.len() != input2.len() {
        println!("string_xor(): The length of input1 and input2 are not the same!");
    }
    let mut output = String::new();
    for i in 0..input1.len() {
        if input1.chars().nth(i).unwrap() == input2.chars().nth(i).unwrap() {
            output = format!("{}{}", output, "0");
        }
        else {
            output = format!("{}{}", output, "1");
        }
    }
    output
}

//[DECO] for testing
pub fn get_verifier_share(mut stream: &TcpStream) -> String {
    let mut buf = [0; 256];
    let read_bytes = stream.read(&mut buf).unwrap();
    let vs_bit: Vec<u8> = buf[..read_bytes].to_vec();
    let mut vs = String::new();
    for i in 0..vs_bit.len() {
        vs = format!("{}{}", vs, (vs_bit[i]-48).to_string());
    }
    vs
}