use crate::msgs::enums::NamedGroup;
use serde::{Serialize, Deserialize};
/// The result of a key exchange.  This has our public key,
/// and the agreed shared secret (also known as the "premaster secret"
/// in TLS1.0-era protocols, and "Z" in TLS1.3).
#[derive(Clone, Debug)]
pub struct KeyExchangeResult {
    pub(crate) pubkey: ring::agreement::PublicKey,
    pub(crate) shared_secret: Vec<u8>,
}

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
#[derive(Clone, Debug)] // ADDED
pub struct KeyExchange {
    pub(crate) skxg: &'static SupportedKxGroup,
    pub(crate) privkey: ring::agreement::EphemeralPrivateKey,
    pub(crate) pubkey: ring::agreement::PublicKey,
}

impl KeyExchange {
    /// Choose a SupportedKxGroup by name, from a list of supported groups.
    pub(crate) fn choose(
        name: NamedGroup,
        supported: &[&'static SupportedKxGroup],
    ) -> Option<&'static SupportedKxGroup> {
        supported
            .iter()
            .find(|skxg| skxg.name == name)
            .cloned()
    }

    /// Start a key exchange, using the given SupportedKxGroup.
    ///
    /// This generates an ephemeral key pair and stores it in the returned KeyExchange object.
    pub(crate) fn start(skxg: &'static SupportedKxGroup) -> Option<Self> {
        let rng = ring::rand::SystemRandom::new();
        let ours =
            ring::agreement::EphemeralPrivateKey::generate(skxg.agreement_algorithm, &rng).ok()?;

        let pubkey = ours.compute_public_key().ok()?;

        Some(Self {
            skxg,
            privkey: ours,
            pubkey,
        })
    }

    /// Return the group being used.
    pub(crate) fn group(&self) -> NamedGroup {
        self.skxg.name
    }

    /// Completes the key exchange, given the peer's public key.  The shared
    /// secret is returned as a KeyExchangeResult.
    pub(crate) fn complete(self, peer: &[u8]) -> Option<KeyExchangeResult> {
        let peer_key = ring::agreement::UnparsedPublicKey::new(self.skxg.agreement_algorithm, peer);
        // println!("\n*********** peer {:?}", &peer);
        // println!("\n*********** peer_key {:?}", &peer_key);
        // println!("\n*********** peer_key.bytes.as_ref() {:?}",&peer_key.bytes().as_ref());
        // println!("\n*********** peer_key {:?}\n", &untrusted::Input::from(peer_key.bytes().as_ref()).as_slice_less_safe());

        let pubkey = self.pubkey;
        ring::agreement::agree_ephemeral(self.privkey, &peer_key, (), move |v| {
            Ok(KeyExchangeResult {
                pubkey,
                shared_secret: Vec::from(v),
            })
        })
        .ok()
    }
}

/// A key-exchange group supported by rustls.
///
/// All possible instances of this class are provided by the library in
/// the `ALL_KX_GROUPS` array.
#[derive(Debug)]
pub struct SupportedKxGroup {
    /// The IANA "TLS Supported Groups" name of the group
    pub name: NamedGroup,

    /// The corresponding ring agreement::Algorithm
    agreement_algorithm: &'static ring::agreement::Algorithm,
}

/// Ephemeral ECDH on curve25519 (see RFC7748)
pub static X25519: SupportedKxGroup = SupportedKxGroup {
    name: NamedGroup::X25519,
    agreement_algorithm: &ring::agreement::X25519,
};

/// Ephemeral ECDH on secp256r1 (aka NIST-P256)
pub static SECP256R1: SupportedKxGroup = SupportedKxGroup {
    name: NamedGroup::secp256r1,
    agreement_algorithm: &ring::agreement::ECDH_P256,
};

// /// Ephemeral ECDH on secp384r1 (aka NIST-P384)
// pub static SECP384R1: SupportedKxGroup = SupportedKxGroup {
//     name: NamedGroup::secp384r1,
//     agreement_algorithm: &ring::agreement::ECDH_P384,
// };

/// A list of all the key exchange groups supported by rustls.
// pub static ALL_KX_GROUPS: [&SupportedKxGroup; 3] = [&X25519, &SECP256R1, &SECP384R1];
pub static ALL_KX_GROUPS: [&SupportedKxGroup; 2] = [&X25519, &SECP256R1];
