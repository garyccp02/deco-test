use crate::cipher::{MessageDecrypter, MessageEncrypter};
use crate::conn::CommonState;
use crate::conn::ConnectionRandoms;
use crate::kx;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{AlertDescription, ContentType};
use crate::msgs::enums::{CipherSuite, SignatureScheme};
use crate::msgs::handshake::KeyExchangeAlgorithm;
use crate::suites::{BulkAlgorithm, CipherSuiteCommon, SupportedCipherSuite};
use crate::Error;

use ring::aead;
use ring::digest::Digest;

use std::{fmt, fs};
use std::io::{Read, Write};
use std::net::{TcpStream, TcpListener, Shutdown};

mod cipher;
pub(crate) use cipher::{AesGcm, ChaCha20Poly1305, Tls12AeadAlgorithm};

mod prf;

// /// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
// #[cfg(feature = "tls12")]
// pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
//     SupportedCipherSuite::Tls12(&Tls12CipherSuite {
//         common: CipherSuiteCommon {
//             suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
//             bulk: BulkAlgorithm::Chacha20Poly1305,
//             aead_algorithm: &ring::aead::CHACHA20_POLY1305,
//         },
//         kx: KeyExchangeAlgorithm::ECDHE,
//         sign: TLS12_ECDSA_SCHEMES,
//         fixed_iv_len: 12,
//         explicit_nonce_len: 0,
//         aead_alg: &ChaCha20Poly1305,
//         hmac_algorithm: ring::hmac::HMAC_SHA256,
//     });

// /// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
// #[cfg(feature = "tls12")]
// pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
//     SupportedCipherSuite::Tls12(&Tls12CipherSuite {
//         common: CipherSuiteCommon {
//             suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
//             bulk: BulkAlgorithm::Chacha20Poly1305,
//             aead_algorithm: &ring::aead::CHACHA20_POLY1305,
//         },
//         kx: KeyExchangeAlgorithm::ECDHE,
//         sign: TLS12_RSA_SCHEMES,
//         fixed_iv_len: 12,
//         explicit_nonce_len: 0,
//         aead_alg: &ChaCha20Poly1305,
//         hmac_algorithm: ring::hmac::HMAC_SHA256,
//     });

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
#[cfg(feature = "tls12")]
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            bulk: BulkAlgorithm::Aes128Gcm,
            aead_algorithm: &ring::aead::AES_128_GCM,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        fixed_iv_len: 4,
        explicit_nonce_len: 8,
        aead_alg: &AesGcm,
        hmac_algorithm: ring::hmac::HMAC_SHA256,
    });

// /// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
// #[cfg(feature = "tls12")]
// pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
//     SupportedCipherSuite::Tls12(&Tls12CipherSuite {
//         common: CipherSuiteCommon {
//             suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
//             bulk: BulkAlgorithm::Aes256Gcm,
//             aead_algorithm: &ring::aead::AES_256_GCM,
//         },
//         kx: KeyExchangeAlgorithm::ECDHE,
//         sign: TLS12_RSA_SCHEMES,
//         fixed_iv_len: 4,
//         explicit_nonce_len: 8,
//         aead_alg: &AesGcm,
//         hmac_algorithm: ring::hmac::HMAC_SHA384,
//     });

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
#[cfg(feature = "tls12")]
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            bulk: BulkAlgorithm::Aes128Gcm,
            aead_algorithm: &ring::aead::AES_128_GCM,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        fixed_iv_len: 4,
        explicit_nonce_len: 8,
        aead_alg: &AesGcm,
        hmac_algorithm: ring::hmac::HMAC_SHA256,
    });

// /// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
// #[cfg(feature = "tls12")]
// pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
//     SupportedCipherSuite::Tls12(&Tls12CipherSuite {
//         common: CipherSuiteCommon {
//             suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
//             bulk: BulkAlgorithm::Aes256Gcm,
//             aead_algorithm: &ring::aead::AES_256_GCM,
//         },
//         kx: KeyExchangeAlgorithm::ECDHE,
//         sign: TLS12_ECDSA_SCHEMES,
//         fixed_iv_len: 4,
//         explicit_nonce_len: 8,
//         aead_alg: &AesGcm,
//         hmac_algorithm: ring::hmac::HMAC_SHA384,
//     });

#[cfg(feature = "tls12")]
static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

#[cfg(feature = "tls12")]
static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// A TLS 1.2 cipher suite supported by rustls.
#[cfg(feature = "tls12")]
pub struct Tls12CipherSuite {
    /// Common cipher suite fields.
    pub common: CipherSuiteCommon,
    pub(crate) hmac_algorithm: ring::hmac::Algorithm,
    /// How to exchange/agree keys.
    pub kx: KeyExchangeAlgorithm,

    /// How to sign messages for authentication.
    pub sign: &'static [SignatureScheme],

    /// How long the fixed part of the 'IV' is.
    ///
    /// This isn't usually an IV, but we continue the
    /// terminology misuse to match the standard.
    pub fixed_iv_len: usize,

    /// This is a non-standard extension which extends the
    /// key block to provide an initial explicit nonce offset,
    /// in a deterministic and safe way.  GCM needs this,
    /// chacha20poly1305 works this way by design.
    pub explicit_nonce_len: usize,

    pub(crate) aead_alg: &'static dyn Tls12AeadAlgorithm,
}

#[cfg(feature = "tls12")]
impl Tls12CipherSuite {
    /// Resolve the set of supported `SignatureScheme`s from the
    /// offered `SupportedSignatureSchemes`.  If we return an empty
    /// set, the handshake terminates.
    pub fn resolve_sig_schemes(&self, offered: &[SignatureScheme]) -> Vec<SignatureScheme> {
        self.sign
            .iter()
            .filter(|pref| offered.contains(pref))
            .cloned()
            .collect()
    }

    /// Which hash function to use with this suite.
    pub fn hash_algorithm(&self) -> &'static ring::digest::Algorithm {
        self.hmac_algorithm.digest_algorithm()
    }
}

#[cfg(feature = "tls12")]
impl From<&'static Tls12CipherSuite> for SupportedCipherSuite {
    fn from(s: &'static Tls12CipherSuite) -> Self {
        Self::Tls12(s)
    }
}

#[cfg(feature = "tls12")]
impl PartialEq for Tls12CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.common.suite == other.common.suite
    }
}

#[cfg(feature = "tls12")]
impl fmt::Debug for Tls12CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls12CipherSuite")
            .field("suite", &self.common.suite)
            .field("bulk", &self.common.bulk)
            .finish()
    }
}

/// TLS1.2 per-connection keying material
#[derive(Debug)]
pub(crate) struct ConnectionSecrets {
    pub(crate) randoms: ConnectionRandoms,
    suite: &'static Tls12CipherSuite,
    pub(crate) master_secret: [u8; 48],
}

impl ConnectionSecrets {

    pub(crate) fn new(
        randoms: &ConnectionRandoms,
        suite: &'static Tls12CipherSuite,
        pms: &[u8],
    ) -> Self {
        let mut ret = Self {
            randoms: randoms.clone(),
            suite,
            master_secret: [0u8; 48],
        };

        let randoms = join_randoms(&ret.randoms.client, &ret.randoms.server);
        prf::prf(
            &mut ret.master_secret,
            suite.hmac_algorithm,
            pms,
            b"master secret",
            &randoms,
        );
        ret
    }

    // [DECO] TLS 1.2 2PC-HMAC
    pub(crate) fn new_deco_curve25519(
        randoms: &ConnectionRandoms,
        suite: &'static Tls12CipherSuite,
        pms: &[u8],
        s1_str: String
    ) -> Self {
        let mut ret = Self {
            randoms: randoms.clone(),
            suite,
            master_secret: [0u8; 48],
        };

        let randoms = join_randoms(&ret.randoms.client, &ret.randoms.server);
        prf::prf_deco_master_secret_curve25519(
            &mut ret.master_secret,
            suite.hmac_algorithm,
            pms,
            b"master secret",
            &randoms,
            s1_str
        );
        ret
    }

    // [DECO] TLS 1.2 2PC-HMAC
    pub(crate) fn new_deco_secp256r1(
        randoms: &ConnectionRandoms,
        suite: &'static Tls12CipherSuite,
        pms: &[u8],
        s1_str: String
    ) -> Self {
        let mut ret = Self {
            randoms: randoms.clone(),
            suite,
            master_secret: [0u8; 48],
        };

        let randoms = join_randoms(&ret.randoms.client, &ret.randoms.server);
        prf::prf_deco_master_secret_secp256r1(
            &mut ret.master_secret,
            suite.hmac_algorithm,
            pms,
            b"master secret",
            &randoms,
            s1_str
        );
        ret
    }

    pub(crate) fn new_ems(
        randoms: &ConnectionRandoms,
        hs_hash: &Digest,
        suite: &'static Tls12CipherSuite,
        pms: &[u8],
    ) -> Self {
        let mut ret = Self {
            randoms: randoms.clone(),
            master_secret: [0u8; 48],
            suite,
        };

        prf::prf(
            &mut ret.master_secret,
            suite.hmac_algorithm,
            pms,
            b"extended master secret",
            hs_hash.as_ref(),
        );
        ret
    }

    // [DECO] TLS 1.2 2PC-HMAC
    pub(crate) fn new_ems_deco_curve25519 (
        randoms: &ConnectionRandoms,
        hs_hash: &Digest,
        suite: &'static Tls12CipherSuite,
        pms: &[u8],
        s1_str: String
    ) -> Self {
        let mut ret = Self {
            randoms: randoms.clone(),
            master_secret: [0u8; 48],
            suite,
        };

        println!("ret.master_secret: {:?}", ret.master_secret);

        prf::prf_deco_extended_master_secret_curve25519(
            &mut ret.master_secret,
            suite.hmac_algorithm,
            pms,
            b"extended master secret",
            hs_hash.as_ref(),
            s1_str
        );
        ret
    }

    // [DECO] TLS 1.2 2PC-HMAC
    pub(crate) fn new_ems_deco_secp256r1 (
        randoms: &ConnectionRandoms,
        hs_hash: &Digest,
        suite: &'static Tls12CipherSuite,
        pms: &[u8],
        s1_str: String
    ) -> Self {
        let mut ret = Self {
            randoms: randoms.clone(),
            master_secret: [0u8; 48],
            suite,
        };

        println!("ret.master_secret: {:?}", ret.master_secret);

        prf::prf_deco_extended_master_secret_secp256r1(
            &mut ret.master_secret,
            suite.hmac_algorithm,
            pms,
            b"extended master secret",
            hs_hash.as_ref(),
            s1_str
        );
        ret
    }

    pub(crate) fn new_resume(
        randoms: &ConnectionRandoms,
        suite: &'static Tls12CipherSuite,
        master_secret: &[u8],
    ) -> Self {
        let mut ret = Self {
            randoms: randoms.clone(),
            suite,
            master_secret: [0u8; 48],
        };
        ret.master_secret
            .copy_from_slice(master_secret);
        ret
    }

    /// Make a `MessageCipherPair` based on the given supported ciphersuite `scs`,
    /// and the session's `secrets`.
    pub(crate) fn make_cipher_pair(&self) -> MessageCipherPair {
        fn split_key<'a>(
            key_block: &'a [u8],
            alg: &'static aead::Algorithm,
        ) -> (aead::LessSafeKey, &'a [u8]) {
            // Might panic if the key block is too small.
            let (key, rest) = key_block.split_at(alg.key_len());
            // Won't panic because its only prerequisite is that `key` is `alg.key_len()` bytes long.
            let key = aead::UnboundKey::new(alg, key).unwrap();
            (aead::LessSafeKey::new(key), rest)
        }

        // Make a key block, and chop it up.
        // nb. we don't implement any ciphersuites with nonzero mac_key_len.
        let key_block = self.make_key_block();

        let suite = self.suite;
        let scs = &suite.common;

        let (client_write_key, key_block) = split_key(&key_block, scs.aead_algorithm);
        let (server_write_key, key_block) = split_key(key_block, scs.aead_algorithm);
        let (client_write_iv, key_block) = key_block.split_at(suite.fixed_iv_len);
        let (server_write_iv, extra) = key_block.split_at(suite.fixed_iv_len);

        let (write_key, write_iv, read_key, read_iv) = if self.randoms.we_are_client {
            (
                client_write_key,
                client_write_iv,
                server_write_key,
                server_write_iv,
            )
        } else {
            (
                server_write_key,
                server_write_iv,
                client_write_key,
                client_write_iv,
            )
        };

        (
            suite
                .aead_alg
                .decrypter(read_key, read_iv),
            suite
                .aead_alg
                .encrypter(write_key, write_iv, extra),
        )
    }

    fn make_key_block(&self) -> Vec<u8> {

        let suite = &self.suite;
        let common = &self.suite.common;

        let len =
            (common.aead_algorithm.key_len() + suite.fixed_iv_len) * 2 + suite.explicit_nonce_len;

        let mut out = Vec::new();
        out.resize(len, 0u8);

        // NOTE: opposite order to above for no good reason.
        // Don't design security protocols on drugs, kids.
        let randoms = join_randoms(&self.randoms.server, &self.randoms.client);
        prf::prf(
            &mut out,
            self.suite.hmac_algorithm,
            &self.master_secret,
            b"key expansion",
            &randoms,
        );

        out
    }

    // [DECO] TLS 1.2 2PC-HMAC
    /// Make a `MessageCipherPair` based on the given supported ciphersuite `scs`,
    /// and the session's `secrets`.
    pub(crate) fn make_cipher_pair_deco(&self) -> MessageCipherPair {
        fn split_key<'a>(
            key_block: &'a [u8],
            alg: &'static aead::Algorithm,
        ) -> (aead::LessSafeKey, &'a [u8]) {

            println!("alg.key_len(): {:?}", alg.key_len());
            // Might panic if the key block is too small.
            let (key, rest) = key_block.split_at(alg.key_len());
            println!("key: {:?}",  key);
            // Won't panic because its only prerequisite is that `key` is `alg.key_len()` bytes long.
            let key = aead::UnboundKey::new(alg, key).unwrap();
            (aead::LessSafeKey::new(key), rest)
        }

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

        // Ready the listener
        let (my_ip_port, target_ip, target_ip_port) = crate::get_ip();
        let listener = TcpListener::bind(my_ip_port).unwrap();

        // Make a key block, and chop it up.
        // nb. we don't implement any ciphersuites with nonzero mac_key_len.
        println!("make_key_block");
        let key_block = self.make_key_block_deco();

        let suite = self.suite;
        let scs = &suite.common;
        println!("suite: {:?}", suite);

        // ======================= [Start] Get shares =======================
        // Truncate key
        let emp_path: &str = "./rustls/src/emp/emp-sh2pc/2pc_hmac/";
        let fs: String = String::from(emp_path);

        let fs_ke_phash1_2: String = format!("{}{}", fs, "tls12_ke_Phash1_2.txt");
        let mut ke_phash1_2_le: String = fs::read_to_string(fs_ke_phash1_2).expect("failed reading");

        let fs_ke_phash2_2: String = format!("{}{}", fs, "tls12_ke_Phash2_2.txt");
        let mut ke_phash2_2_le: String = fs::read_to_string(fs_ke_phash2_2).expect("failed reading");

        let ke_phash1_2_be: String = ke_phash1_2_le.chars().rev().collect();
        let ke_phash2_2_be: String = ke_phash2_2_le.chars().rev().collect();
        let ke_be: String = format!("{}{}", ke_phash1_2_be, ke_phash2_2_be);

        let client_write_key_c: String = ke_be.clone()[0..128].to_string();
        let server_write_key_c: String = ke_be.clone()[128..256].to_string();
        let client_write_iv_c: String = ke_be.clone()[256..288].to_string();
        let server_write_iv_c: String = ke_be.clone()[288..320].to_string();
        let extra_c: String = ke_be.clone()[320..384].to_string();

        println!("client_write_key_c: {:?}", client_write_key_c);
        println!("server_write_key_c: {:?}", server_write_key_c);
        println!("client_write_iv_c: {:?}", client_write_iv_c);
        println!("server_write_iv_c: {:?}", server_write_iv_c);
        println!("extra_c: {:?}", extra_c);

        // Get verifier shares, and send client shares
        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        stream.write(&server_write_key_c.as_bytes()).unwrap();
        println!("server_write_key_c.as_bytes(): {:?}", server_write_key_c.as_bytes());

        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        stream.write(&server_write_iv_c.as_bytes()).unwrap();
        println!("server_write_iv_c.as_bytes(): {:?}", server_write_iv_c.as_bytes());

        let stream = TcpStream::connect(&target_ip_port).unwrap();
        let client_write_key_v: String = get_verifier_share(&stream);

        let stream = TcpStream::connect(&target_ip_port).unwrap();
        let client_write_iv_v: String = get_verifier_share(&stream);

        let stream = TcpStream::connect(&target_ip_port).unwrap();
        let extra_v: String = get_verifier_share(&stream);

        // let stream = TcpStream::connect(&target_ip_port).unwrap();
        // let server_write_key_v: String = get_verifier_share(&stream);

        // let stream = TcpStream::connect(&target_ip_port).unwrap();
        // let server_write_iv_v: String = get_verifier_share(&stream);

        println!("client_write_key_v: {:?}", client_write_key_v);
        println!("client_write_iv_v: {:?}", client_write_iv_v);
        println!("extra_v: {:?}", extra_v);
        // println!("server_write_key_v: {:?}", server_write_key_v);
        // println!("server_write_iv_v: {:?}", server_write_iv_v);

        // Do XOR and get real keys.
        let client_write_key = string_xor(client_write_key_c, client_write_key_v);
        let client_write_iv = string_xor(client_write_iv_c, client_write_iv_v);
        let extra = string_xor(extra_c, extra_v);
        let client_write_key: Vec<u8> = be_bin_string_to_u8_vec(client_write_key.clone());
        let client_write_iv: &[u8] = &be_bin_string_to_u8_vec(client_write_iv.clone());
        let extra: &[u8] = &be_bin_string_to_u8_vec(extra.clone());
        println!("client_write_key: {:?}", client_write_key);
        println!("client_write_iv: {:?}", client_write_iv);
        println!("extra: {:?}", extra);

        // let server_write_key = string_xor(server_write_key_c, server_write_key_v);
        // let server_write_iv = string_xor(server_write_iv_c, server_write_iv_v);
        // let server_write_key: Vec<u8> = be_bin_string_to_u8_vec(server_write_key.clone());
        // let server_write_iv: &[u8] = &be_bin_string_to_u8_vec(server_write_iv.clone());
        let server_write_key: Vec<u8> = be_bin_string_to_u8_vec(server_write_key_c.clone());
        let server_write_iv: &[u8] = &be_bin_string_to_u8_vec(server_write_iv_c.clone());
        println!("server_write_key: {:?}", server_write_key);
        println!("server_write_iv: {:?}", server_write_iv);

        let client_write_key = aead::UnboundKey::new(
            &aead::AES_128_GCM, 
            &client_write_key
        ).unwrap();
        let client_write_key = aead::LessSafeKey::new(
            client_write_key
        );
        let server_write_key = aead::UnboundKey::new(
            &aead::AES_128_GCM, 
            &server_write_key
        ).unwrap();
        let server_write_key = aead::LessSafeKey::new(
            server_write_key
        );
        // ======================= [End] Get shares =======================

        // println!("scs.aead_algorithm: {:?}", scs.aead_algorithm);
        // let (client_write_key, key_block) = split_key(&key_block, scs.aead_algorithm);
        // println!("split_key: client_write_key: {:?}", client_write_key);
        // let (server_write_key, key_block) = split_key(key_block, scs.aead_algorithm);
        // println!("split_key: server_write_key: {:?}", server_write_key);
        // let (client_write_iv, key_block) = key_block.split_at(suite.fixed_iv_len);
        // println!("split_at: client_write_iv: {:?}", client_write_iv);
        // println!("suite.fixed_iv_len: {:?}", suite.fixed_iv_len);
        // let (server_write_iv, extra) = key_block.split_at(suite.fixed_iv_len);
        // println!("split_at: server_write_iv: {:?}", server_write_iv);
        // println!("split_at: extra: {:?}", extra);

        let (write_key, write_iv, read_key, read_iv) = if self.randoms.we_are_client {
            (
                client_write_key,
                client_write_iv,
                server_write_key,
                server_write_iv,
            )
        } else {
            (
                server_write_key,
                server_write_iv,
                client_write_key,
                client_write_iv,
            )
        };

        (
            suite
                .aead_alg
                .decrypter(read_key, read_iv),
            suite
                .aead_alg
                .encrypter(write_key, write_iv, extra),
        )
    }

    // [DECO] TLS 1.2 2PC-HMAC
    fn make_key_block_deco(&self) -> Vec<u8> {

        println!("self.master_secret: {:?}", self.master_secret);
        let suite = &self.suite;
        let common = &self.suite.common;

        let len =
            (common.aead_algorithm.key_len() + suite.fixed_iv_len) * 2 + suite.explicit_nonce_len;

        let mut out = Vec::new();
        out.resize(len, 0u8);

        // NOTE: opposite order to above for no good reason.
        // Don't design security protocols on drugs, kids.
        let randoms = join_randoms(&self.randoms.server, &self.randoms.client);
        println!("randoms: {:?}", randoms);
        println!("randoms len: {:?}", randoms.len());
        prf::prf_deco_key_expansion(
            &mut out,
            self.suite.hmac_algorithm,
            &self.master_secret,
            b"key expansion",
            &randoms,
        );

        println!("Second part out: {:?}", out);
        println!("Second part out len: {:?}", out.len());

        out
    }

    pub(crate) fn suite(&self) -> &'static Tls12CipherSuite {
        self.suite
    }

    pub(crate) fn get_master_secret(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        ret.extend_from_slice(&self.master_secret);
        ret
    }

    fn make_verify_data(&self, handshake_hash: &Digest, label: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.resize(12, 0u8);

        println!("handshake_hash.as_ref(): {:?}", handshake_hash.as_ref());
        println!("handshake_hash.as_ref() len: {:?}", handshake_hash.as_ref().len());

        prf::prf(
            &mut out,
            self.suite.hmac_algorithm,
            &self.master_secret,
            label,
            handshake_hash.as_ref(),
        );
        out
    }

    pub(crate) fn client_verify_data(&self, handshake_hash: &Digest) -> Vec<u8> {
        self.make_verify_data(handshake_hash, b"client finished")
    }

    pub(crate) fn server_verify_data(&self, handshake_hash: &Digest) -> Vec<u8> {
        self.make_verify_data(handshake_hash, b"server finished")
    }

    fn make_verify_data_cf_deco(&self, handshake_hash: &Digest, label: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.resize(12, 0u8);

        println!("handshake_hash.as_ref(): {:?}", handshake_hash.as_ref());
        println!("handshake_hash.as_ref() len: {:?}", handshake_hash.as_ref().len());

        prf::prf_deco_client_finish(
            &mut out,
            self.suite.hmac_algorithm,
            &self.master_secret,
            label,
            handshake_hash.as_ref(),
        );
        out
    }

    pub(crate) fn client_verify_data_deco(&self, handshake_hash: &Digest) -> Vec<u8> {
        self.make_verify_data_cf_deco(handshake_hash, b"client finished")
    }

    fn make_verify_data_sf_deco(&self, handshake_hash: &Digest, label: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.resize(12, 0u8);

        println!("handshake_hash.as_ref(): {:?}", handshake_hash.as_ref());
        println!("handshake_hash.as_ref() len: {:?}", handshake_hash.as_ref().len());

        prf::prf_deco_server_finish(
            &mut out,
            self.suite.hmac_algorithm,
            &self.master_secret,
            label,
            handshake_hash.as_ref(),
        );
        out
    }

    pub(crate) fn server_verify_data_deco(&self, handshake_hash: &Digest) -> Vec<u8> {
        self.make_verify_data_sf_deco(handshake_hash, b"server finished")
    }

    pub(crate) fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) {
        let mut randoms = Vec::new();
        randoms.extend_from_slice(&self.randoms.client);
        randoms.extend_from_slice(&self.randoms.server);
        if let Some(context) = context {
            assert!(context.len() <= 0xffff);
            (context.len() as u16).encode(&mut randoms);
            randoms.extend_from_slice(context);
        }

        prf::prf(
            output,
            self.suite.hmac_algorithm,
            &self.master_secret,
            label,
            &randoms,
        )
    }
}

fn join_randoms(first: &[u8; 32], second: &[u8; 32]) -> [u8; 64] {
    let mut randoms = [0u8; 64];
    randoms[..32].copy_from_slice(first);
    randoms[32..].copy_from_slice(second);
    randoms
}

type MessageCipherPair = (Box<dyn MessageDecrypter>, Box<dyn MessageEncrypter>);

pub(crate) fn decode_ecdh_params<T: Codec>(
    common: &mut CommonState,
    kx_params: &[u8],
) -> Result<T, Error> {
    decode_ecdh_params_::<T>(kx_params).ok_or_else(|| {
        common.send_fatal_alert(AlertDescription::DecodeError);
        Error::CorruptMessagePayload(ContentType::Handshake)
    })
}

fn decode_ecdh_params_<T: Codec>(kx_params: &[u8]) -> Option<T> {
    let mut rd = Reader::init(kx_params);
    let ecdh_params = T::read(&mut rd)?;
    match rd.any_left() {
        false => Some(ecdh_params),
        true => None,
    }
}

pub(crate) fn complete_ecdh(
    mine: kx::KeyExchange,
    peer_pub_key: &[u8],
) -> Result<kx::KeyExchangeResult, Error> {
    mine.complete(peer_pub_key)
        .ok_or_else(|| Error::PeerMisbehavedError("key agreement failed".to_string()))
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
pub fn be_bin_string_to_u8_vec(input: String) -> Vec<u8> {

    use core::num::Wrapping;

    // Truncate a string into 32-bit length each
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::handshake::{ClientECDHParams, ServerECDHParams};

    #[test]
    fn server_ecdhe_remaining_bytes() {
        let key = kx::KeyExchange::start(&kx::X25519).unwrap();
        let server_params = ServerECDHParams::new(key.group(), key.pubkey.as_ref());
        let mut server_buf = Vec::new();
        server_params.encode(&mut server_buf);
        server_buf.push(34);
        assert!(decode_ecdh_params_::<ServerECDHParams>(&server_buf).is_none());
    }

    #[test]
    fn client_ecdhe_invalid() {
        assert!(decode_ecdh_params_::<ClientECDHParams>(&[34]).is_none());
    }
}
