// Copyright 2015 Brian Smith.
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

//! HMAC-based Extract-and-Expand Key Derivation Function.
//!
//! HKDF is specified in [RFC 5869].
//!
//! [RFC 5869]: https://tools.ietf.org/html/rfc5869

use crate::{error, hmac};
use std::net::TcpListener;
use std::io::Write;
use std::io::Read;

const emp_path: &str = "./rustls/src/emp/emp-sh2pc/2pc_hmac/";

/// An HKDF algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Algorithm(hmac::Algorithm);

impl Algorithm {
    /// The underlying HMAC algorithm.
    #[inline]
    pub fn hmac_algorithm(&self) -> hmac::Algorithm {
        self.0
    }
}

/// HKDF using HMAC-SHA-1. Obsolete.
pub static HKDF_SHA1_FOR_LEGACY_USE_ONLY: Algorithm =
    Algorithm(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY);

/// HKDF using HMAC-SHA-256.
pub static HKDF_SHA256: Algorithm = Algorithm(hmac::HMAC_SHA256);

/// HKDF using HMAC-SHA-384.
pub static HKDF_SHA384: Algorithm = Algorithm(hmac::HMAC_SHA384);

/// HKDF using HMAC-SHA-512.
pub static HKDF_SHA512: Algorithm = Algorithm(hmac::HMAC_SHA512);

impl KeyType for Algorithm {
    fn len(&self) -> usize {
        self.0.digest_algorithm().output_len
    }
}

/// A salt for HKDF operations.
#[derive(Debug)]
pub struct Salt(hmac::Key);

impl Salt {
    /// Constructs a new `Salt` with the given value based on the given digest
    /// algorithm.
    ///
    /// Constructing a `Salt` is relatively expensive so it is good to reuse a
    /// `Salt` object instead of re-constructing `Salt`s with the same value.
    pub fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        Salt(hmac::Key::new(algorithm.0, value))
    }

    /// The [HKDF-Extract] operation.
    ///
    /// [HKDF-Extract]: https://tools.ietf.org/html/rfc5869#section-2.2
    pub fn extract(&self, secret: &[u8]) -> Prk {
        // The spec says that if no salt is provided then a key of
        // `digest_alg.output_len` bytes of zeros is used. But, HMAC keys are
        // already zero-padded to the block length, which is larger than the output
        // length of the extract step (the length of the digest). Consequently the
        // `Key` constructor will automatically do the right thing for a
        // zero-length string.
        let salt = &self.0;
        let prk = hmac::sign(salt, secret);
        Prk(hmac::Key::new(salt.algorithm(), prk.as_ref()))
    }

    // [DECO] 
    pub fn extract_2pc_hmac_hs_msg(
        &self, 
        input: String,
        target_ip: &str,
    ) //-> Prk 
    {
        
        let salt = &self.0;

        println!("====== Start: 2PC-HMAC ======");
        // let prk = 
        hmac::handle_2pc_hmac_hs_msg_client(input.clone(), target_ip.clone());
        println!("====== End: 2PC-HMAC ======");
        // println!("{:?}", prk);

        // println!("====== Start: normal HMAC ======");
        // let normal_prk = hmac::sign(salt, secret);
        // println!("====== End: normal HMAC ======");
        // println!("{:?}", normal_prk);

        println!("====== Start: HS Setting with ipad and opad ======");
        let fs_client_share: String = format!("{}{}", emp_path, "msg_client_share_le.txt"); // String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/msg_client_share_le.txt");
        let ipad_output: String = String::from("HS_ipad_le.txt");
        let opad_output: String = String::from("HS_opad_le.txt");
        // Prk(hmac::Key::call_2pc_hmac_key_iopad_set(
        //     salt.algorithm(),
        //     fs_client_share,
        //     ipad_output,
        //     opad_output
        // ))

        let _ = hmac::Key::call_2pc_hmac_key_iopad_set_no_communication(
            salt.algorithm(),
            fs_client_share,
            ipad_output,
            opad_output,
            target_ip.clone()
        );
        // hmac::Key::new_after_2pc_hmac(salt.algorithm());
        // Prk(hmac::Key::new(salt.algorithm(), prk.as_ref()))
    }

    /// The algorithm used to derive this salt.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        Algorithm(self.0.algorithm())
    }

    // [DECO]
    #[inline]
    pub fn prk_to_salt(
        input: Prk
    ) -> Self {
        let key = input.0;
        Salt(key)
    }
}

impl From<Okm<'_, Algorithm>> for Salt {
    fn from(okm: Okm<'_, Algorithm>) -> Self {
        Self(hmac::Key::from(Okm {
            prk: okm.prk,
            info: okm.info,
            len: okm.len().0,
            len_cached: okm.len_cached,
        }))
    }
}

/// The length of the OKM (Output Keying Material) for a `Prk::expand()` call.
pub trait KeyType {
    /// The length that `Prk::expand()` should expand its input to.
    fn len(&self) -> usize;
}

/// A HKDF PRK (pseudorandom key).
#[derive(Clone, Debug)]
pub struct Prk(hmac::Key);

impl Prk {

    // [DECO]
    pub fn hmac_key_to_prk(
        key: hmac::Key
    ) -> Self {

        Prk(key)
    }

    // [DECO]
    pub fn read(self) {
        println!("read: {:?}", self.0);
        hmac::Key::read(self.0);
    }

    /// Construct a new `Prk` directly with the given value.
    ///
    /// Usually one can avoid using this. It is useful when the application
    /// intentionally wants to leak the PRK secret, e.g. to implement
    /// `SSLKEYLOGFILE` functionality.
    pub fn new_less_safe(algorithm: Algorithm, value: &[u8]) -> Self {
        Self(hmac::Key::new(algorithm.hmac_algorithm(), value))
    }

    /// The [HKDF-Expand] operation.
    ///
    /// [HKDF-Expand]: https://tools.ietf.org/html/rfc5869#section-2.3
    ///
    /// Fails if (and only if) `len` is too large.
    #[inline]
    pub fn expand<'a, L: KeyType>(
        &'a self,
        info: &'a [&'a [u8]],
        len: L,
    ) -> Result<Okm<'a, L>, error::Unspecified> {
        println!("ring expand");
        let len_cached = len.len();
        if len_cached > 255 * self.0.algorithm().digest_algorithm().output_len {
            return Err(error::Unspecified);
        }
        println!("okm?");
        // println!("prk: {:?}", prk);
        println!("info: {:?}", info);
        // println!("len: {:?}", len);
        println!("len_cached: {:?}", len_cached);
        Ok(Okm {
            prk: self,
            info,
            len,
            len_cached,
        })
    }

    // [DECO]
    #[inline]
    pub fn expand_deco(
        msg: Vec<u8>,
        my_ip_with_port: &str,
        target_ip_with_port: &str,
        target_ip: &str
    ) -> Self {

        use std::env;
        use std::fs;

        println!("ring expand_deco");

        // for different keys.
        let mut output_file_name: String = String::new();
        let mut input_ipad_file_name: String = String::new();
        let mut input_opad_file_name: String = String::new();
        let mut output_ipad_file_name: String = String::new();
        let mut output_opad_file_name: String = String::new();
        if msg[9] == 99 && msg[11] == 104 { // CHTS
            output_file_name = String::from("CHTS_le.txt");
            input_ipad_file_name = format!("{}{}", emp_path, "HS_ipad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/HS_ipad_le.txt");
            input_opad_file_name = format!("{}{}", emp_path, "HS_opad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/HS_opad_le.txt");
            output_ipad_file_name = String::from("CHTS_ipad_le.txt");
            output_opad_file_name = String::from("CHTS_opad_le.txt");
        }
        else if msg[9] == 115 && msg[11] == 104 { // SHTS
            output_file_name = String::from("SHTS_le.txt");
            input_ipad_file_name = format!("{}{}", emp_path, "HS_ipad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/HS_ipad_le.txt");
            input_opad_file_name = format!("{}{}", emp_path, "HS_opad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/HS_opad_le.txt");
            output_ipad_file_name = String::from("SHTS_ipad_le.txt");
            output_opad_file_name = String::from("SHTS_opad_le.txt");
        }
        else if msg[9] == 100 { // dHS
            output_file_name = String::from("dHS_le.txt");
            input_ipad_file_name = format!("{}{}", emp_path, "HS_ipad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/HS_ipad_le.txt");
            input_opad_file_name = format!("{}{}", emp_path, "HS_opad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/HS_opad_le.txt");
            output_ipad_file_name = String::from("dHS_ipad_le.txt");
            output_opad_file_name = String::from("dHS_opad_le.txt");
        }
        else if msg[9] == 0 { // MS
            output_file_name = String::from("MS_le.txt");
            input_ipad_file_name = format!("{}{}", emp_path, "dHS_ipad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/dHS_ipad_le.txt");
            input_opad_file_name = format!("{}{}", emp_path, "dHS_opad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/dHS_opad_le.txt");
            output_ipad_file_name = String::from("MS_ipad_le.txt");
            output_opad_file_name = String::from("MS_opad_le.txt");
        }
        else if msg[9] == 99 && msg[11] == 97 { // CATS
            output_file_name = String::from("CATS_le.txt");
            input_ipad_file_name = format!("{}{}", emp_path, "MS_ipad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/MS_ipad_le.txt");
            input_opad_file_name = format!("{}{}", emp_path, "MS_opad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/MS_opad_le.txt");
            output_ipad_file_name = String::from("CATS_ipad_le.txt");
            output_opad_file_name = String::from("CATS_opad_le.txt");
        }
        else if msg[9] == 115 && msg[11] == 97 { // SATS
            output_file_name = String::from("SATS_le.txt");
            input_ipad_file_name = format!("{}{}", emp_path, "MS_ipad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/MS_ipad_le.txt");
            input_opad_file_name = format!("{}{}", emp_path, "MS_opad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/MS_opad_le.txt");
            output_ipad_file_name = String::from("SATS_ipad_le.txt");
            output_opad_file_name = String::from("SATS_opad_le.txt");
        }
        else { // if msg[9] == 101 { // EMS
            output_file_name = String::from("EMS_le.txt");
            input_ipad_file_name = format!("{}{}", emp_path, "MS_ipad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/MS_ipad_le.txt");
            input_opad_file_name = format!("{}{}", emp_path, "MS_opad_le.txt"); //String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/MS_opad_le.txt");
            output_ipad_file_name = String::from("EMS_ipad_le.txt");
            output_opad_file_name = String::from("EMS_opad_le.txt");
        }

        println!("output_file_name: {}", output_file_name);

        let mut msg_bin_be: String = String::new();
        for i in 0..msg.len() {
            let mut temp: String = String::new();
            temp = format!("{:b}", msg[i]);
            while temp.chars().count() < 8 {
                temp = format!("{}{}", "0", temp);
            }
            msg_bin_be = format!("{}{}", msg_bin_be, temp);
            println!("temp: {}  \t->\t{}", msg[i], temp);
        }
        println!("msg_bin_be: {}", msg_bin_be);

        let mut msg_bin_le: String = msg_bin_be.chars().rev().collect();
        println!("msg_bin_le: {}", msg_bin_le);

        // Get the key with ipad
        let key_ipad_le_c = fs::read_to_string(input_ipad_file_name).expect("failed reading");
        println!("key_ipad_le_c: {}", key_ipad_le_c);

        // Get the key with opad
        let key_opad_le_c = fs::read_to_string(input_opad_file_name).expect("failed reading");
        println!("key_opad_le_c: {}", key_opad_le_c);

        hmac::call_emp_2pc_hmac_expand(
            msg_bin_le,
            key_ipad_le_c,
            key_opad_le_c,
            output_file_name.clone(),
            target_ip.clone()
        );

        // Get the share of CHTS/SHTS/CATS/SATS/EMS
        let fs_key_le_c: String = format!("{}{}", emp_path, output_file_name);
        // let key_le_c = fs::read_to_string(fs_key_le_c).expect("failed reading");

        let mut key: hmac::Key;
        println!("========================================");
        if  msg[9] == 99 && msg[11] == 104 || // CHTS
            msg[9] == 115 && msg[11] == 104 || // SHTS
            msg[9] == 99 && msg[11] == 97 || // CATS
            msg[9] == 101 { // EMS

                key = hmac::Key::call_2pc_hmac_key_iopad_set_vc(
                    hmac::HMAC_SHA256,
                    fs_key_le_c,
                    output_ipad_file_name,
                    output_opad_file_name,
                    target_ip_with_port,
                    target_ip.clone()
                );
        }
        else if msg[9] == 115 && msg[11] == 97 { // SATS
            key = hmac::Key::call_2pc_hmac_key_iopad_set_cv(
                hmac::HMAC_SHA256,
                fs_key_le_c,
                output_ipad_file_name,
                output_opad_file_name,
                my_ip_with_port,
                target_ip.clone()
            );
        }
        else { // dHS or MS
            key = hmac::Key::call_2pc_hmac_key_iopad_set_no_communication(
            // key = hmac::Key::call_2pc_hmac_key_iopad_set_vc(
                hmac::HMAC_SHA256,
                fs_key_le_c,
                output_ipad_file_name,
                output_opad_file_name,
                target_ip.clone()
            );
        }

        Prk(key)
    }
}

// [DECO]
#[inline]
pub fn expand_deco_tksapp(
    msg: Vec<u8>
) {

    use std::env;
    use std::fs;

    println!("ring expand_deco_tksapp");

    let listener = TcpListener::bind("127.0.0.1:8081").unwrap();

    // for different keys.
    let mut output_file_name: String = String::new();
    let mut input_ipad_file_name: String = String::new();
    let mut input_opad_file_name: String = String::new();

    input_ipad_file_name = String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/SATS_ipad_le.txt");
    input_opad_file_name = String::from("./rustls/src/emp/emp-ag2pc/2pc_hmac/SATS_opad_le.txt");

    if msg[9] == 107 { // key
        output_file_name = String::from("tksapp_key_le.txt");
    }
    else { // iv
        output_file_name = String::from("tksapp_iv_le.txt");
    }

    println!("output_file_name: {}", output_file_name);

    let mut msg_bin_be: String = String::new();
    for i in 0..msg.len() {
        let mut temp: String = String::new();
        temp = format!("{:b}", msg[i]);
        while temp.chars().count() < 8 {
            temp = format!("{}{}", "0", temp);
        }
        msg_bin_be = format!("{}{}", msg_bin_be, temp);
        println!("temp: {}  \t->\t{}", msg[i], temp);
    }
    println!("msg_bin_be: {}", msg_bin_be);

    let mut msg_bin_le: String = msg_bin_be.chars().rev().collect();
    println!("msg_bin_le: {}", msg_bin_le);

    // Get the key with ipad
    let key_ipad_le_c = fs::read_to_string(input_ipad_file_name).expect("failed reading");
    println!("key_ipad_le_c: {}", key_ipad_le_c);

    // Get the key with opad
    let key_opad_le_c = fs::read_to_string(input_opad_file_name).expect("failed reading");
    println!("key_opad_le_c: {}", key_opad_le_c);

    hmac::call_emp_2pc_hmac_expand(
        msg_bin_le,
        key_ipad_le_c,
        key_opad_le_c,
        output_file_name.clone(),
        ""
    );

    // Send the share to the verifier
    let fs = "./rustls/src/emp/emp-ag2pc/2pc_hmac/";
    let fs_tksapp_iv_le_c: String = format!("{}{}", fs, output_file_name);
    let tksapp_iv_le_c = fs::read_to_string(fs_tksapp_iv_le_c).expect("failed reading");

    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    stream.write(&tksapp_iv_le_c.as_bytes()).unwrap();
}

impl From<Okm<'_, Algorithm>> for Prk {
    fn from(okm: Okm<Algorithm>) -> Self {
        Self(hmac::Key::from(Okm {
            prk: okm.prk,
            info: okm.info,
            len: okm.len().0,
            len_cached: okm.len_cached,
        }))
    }
}

/// An HKDF OKM (Output Keying Material)
///
/// Intentionally not `Clone` or `Copy` as an OKM is generally only safe to
/// use once.
#[derive(Debug)]
pub struct Okm<'a, L: KeyType> {
    prk: &'a Prk,
    info: &'a [&'a [u8]],
    len: L,
    len_cached: usize,
}

impl<L: KeyType> Okm<'_, L> {
    /// The `OkmLength` given to `Prk::expand()`.
    #[inline]
    pub fn len(&self) -> &L {
        &self.len
    }

    /// Fills `out` with the output of the HKDF-Expand operation for the given
    /// inputs.
    ///
    /// Fails if (and only if) the requested output length is larger than 255
    /// times the size of the digest algorithm's output. (This is the limit
    /// imposed by the HKDF specification due to the way HKDF's counter is
    /// constructed.)
    #[inline]
    pub fn fill(self, out: &mut [u8]) -> Result<(), error::Unspecified> {
        fill_okm(self.prk, self.info, out, self.len_cached)
    }
}

fn fill_okm(
    prk: &Prk,
    info: &[&[u8]],
    out: &mut [u8],
    len: usize,
) -> Result<(), error::Unspecified> {

    println!("In: fill_okm");

    if out.len() != len {
        return Err(error::Unspecified);
    }

    let digest_alg = prk.0.algorithm().digest_algorithm();
    assert!(digest_alg.block_len >= digest_alg.output_len);

    let mut ctx = hmac::Context::with_key(&prk.0);

    let mut n = 1u8;
    let mut out = out;
    loop {
        println!("Loop: fill_okm");
        for info in info {
            ctx.update(info);
        }
        ctx.update(&[n]);

        let t = ctx.sign();
        let t = t.as_ref();
        println!("t: {:?}", t);

        // Append `t` to the output.
        out = if out.len() < digest_alg.output_len {
            let len = out.len();
            out.copy_from_slice(&t[..len]);
            &mut []
        } else {
            let (this_chunk, rest) = out.split_at_mut(digest_alg.output_len);
            this_chunk.copy_from_slice(t);
            rest
        };

        if out.is_empty() {
            println!("prk: {:?}", prk);
            println!("info: {:?}", info);
            println!("out: {:?}", out);
            println!("len: {:?}", len);
            return Ok(());
        }

        ctx = hmac::Context::with_key(&prk.0);
        ctx.update(t);
        n = n.checked_add(1).unwrap();
    }
}
