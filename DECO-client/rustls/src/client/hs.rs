#[cfg(feature = "logging")]
use crate::bs_debug;
use crate::check::check_message;
use crate::conn::{CommonState, ConnectionRandoms, State};
use crate::error::Error;
use crate::hash_hs::HandshakeHashBuffer;
use crate::kx;
#[cfg(feature = "logging")]
use crate::log::{debug, trace};
use crate::msgs::base::Payload;
#[cfg(feature = "quic")]
use crate::msgs::base::PayloadU16;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{AlertDescription, CipherSuite, Compression, ProtocolVersion};
use crate::msgs::enums::{ContentType, ExtensionType, HandshakeType};
use crate::msgs::enums::{ECPointFormat, PSKKeyExchangeMode};
use crate::msgs::handshake::{CertificateStatusRequest, ClientSessionTicket, SCTList};
use crate::msgs::handshake::{ClientExtension, HasServerExtensions};
use crate::msgs::handshake::{ClientHelloPayload, HandshakeMessagePayload, HandshakePayload};
use crate::msgs::handshake::{ConvertProtocolNameList, ProtocolNameList};
use crate::msgs::handshake::{ECPointFormatList, SupportedPointFormats};
use crate::msgs::handshake::{HelloRetryRequest, KeyShareEntry};
use crate::msgs::handshake::{Random, SessionID};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::ticketer::TimeBase;
use crate::tls13::key_schedule::KeyScheduleEarly;
use crate::SupportedCipherSuite;
use crate::msgs::base::PayloadU8;

use crate::{uint_to_yint, yint_to_uint};

#[cfg(feature = "tls12")]
use super::tls12;
use crate::client::client_conn::ClientConnectionData;
use crate::client::common::ClientHelloDetails;
use crate::client::{tls13, ClientConfig, ServerName};
use std::sync::Arc;

pub(super) type NextState = Box<dyn State<ClientConnectionData>>;
pub(super) type NextStateOrError = Result<NextState, Error>;
pub(super) type ClientContext<'a> = crate::conn::Context<'a, ClientConnectionData>;

// use ring::ec::curve25519::x25519::x25519_public_from_private;
use ring::ec::curve25519::scalar::{Scalar, SCALAR_LEN};
use ring::ec::curve25519::ops;

// pub const SCALAR_LEN: usize = 32;
// #[repr(transparent)]
// pub struct MaskedScalar([u8; SCALAR_LEN]);

// impl MaskedScalar {
//     pub fn from_bytes_masked(bytes: [u8; SCALAR_LEN]) -> Self {
//         extern "C" {
//             fn GFp_x25519_sc_mask(a: &mut [u8; SCALAR_LEN]);
//         }
//         let mut r = Self(bytes);
//         unsafe { GFp_x25519_sc_mask(&mut r.0) };
//         r
//     }
// }

// impl From<MaskedScalar> for Scalar {
//     fn from(MaskedScalar(scalar): MaskedScalar) -> Self {
//         Self(scalar)
//     }
// }


fn find_session(
    server_name: &ServerName,
    config: &ClientConfig,
    #[cfg(feature = "quic")] cx: &mut ClientContext<'_>,
) -> Option<persist::Retrieved<persist::ClientSessionValue>> {
    let key = persist::ClientSessionKey::session_for_server_name(server_name);
    let key_buf = key.get_encoding();

    let value = config
        .session_storage
        .get(&key_buf)
        .or_else(|| {
            debug!("No cached session for {:?}", server_name);
            None
        })?;

    let mut reader = Reader::init(&value[..]);
    CipherSuite::read_bytes(&value[..2])
        .and_then(|suite| {
            config
                .cipher_suites
                .iter()
                .find(|s| s.suite() == suite)
        })
        .and_then(|suite| match suite {
            SupportedCipherSuite::Tls13(_) => persist::Tls13ClientSessionValue::read(&mut reader)
                .map(persist::ClientSessionValue::from),
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(_) => persist::Tls12ClientSessionValue::read(&mut reader)
                .map(persist::ClientSessionValue::from),
        })
        .and_then(|resuming| {
            let retrieved = persist::Retrieved::new(resuming, TimeBase::now().ok()?);
            match retrieved.has_expired() {
                false => Some(retrieved),
                true => None,
            }
        })
        .and_then(|resuming| {
            #[cfg(feature = "quic")]
            if cx.common.is_quic() {
                let params = PayloadU16::read(&mut reader)?;
                cx.common.quic.params = Some(params.0);
            }
            Some(resuming)
        })
}

pub(super) fn start_handshake(
    server_name: ServerName,
    extra_exts: Vec<ClientExtension>,
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
) -> NextStateOrError { // add verifier key share
    let mut transcript_buffer = HandshakeHashBuffer::new();
    if config
        .client_auth_cert_resolver
        .has_certs()
    {
        transcript_buffer.set_client_auth_enabled();
    }

    let support_tls12 = config.supports_version(ProtocolVersion::TLSv1_2);
    let support_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);

    let mut session_id: Option<SessionID> = None;
    let mut resuming_session = find_session(
        &server_name,
        &config,
        #[cfg(feature = "quic")]
        cx,
    );

    let mut key_share = if support_tls13 {
        Some(tls13::initial_key_share(&config, &server_name)?)
    } else {
        None
    };

//====================== INSERT ==========================
    if support_tls13 { 
        println!("support_tls13 Hi");
        use ring::ec::curve25519::ed25519::verification::{GFp_x25519_ge_add, GFp_x25519_extpoint_from_private_generic_masked, GFp_x25519_ge_double_scalarmult_vartime};
        use ring::ec::curve25519::ed25519::signing::GFp_x25519_ge_scalarmult_base;
        use ring::ec::curve25519::scalar::{Scalar, MaskedScalar};
        use ring::ec::curve25519::ops::{ExtPoint,Point};
        use ring::ec::keys;
        use ring::agreement;
        use ring::digest;
        use std::convert::TryInto;
        use curv::BigInt;
        use curv::arithmetic::Converter;
        use curv::arithmetic::traits::*;

        fn uint_to_extpoint(u_int: &BigInt) -> ExtPoint {
            let y_int = uint_to_yint(u_int);
            let mut bytes_y = y_int.to_bytes(); // big endian
            bytes_y.reverse(); // little endian

            let num_of_zero_bytes = 32 - bytes_y.len();
            if num_of_zero_bytes > 0 {
                for _ in 0..num_of_zero_bytes {
                    bytes_y.push(0);
                    println!("final byte is 0: {:?}", &bytes_y);
                }
            }

            let bytes_y: [u8; 32] = pop(&bytes_y);
            ExtPoint::from_encoded_point_vartime(&bytes_y).unwrap()
        }

        fn extpoint_to_uint(extpoint: ExtPoint) -> BigInt {
            let mut bytes_y = extpoint.into_encoded_point(); // little endian
            bytes_y.reverse(); // BIg endian
            let mut y_int = BigInt::from_bytes(&bytes_y);
            let two_pow_255: BigInt = BigInt::from_str_radix(
                "57896044618658097711785492504343953926634992332820282019728792003956564819968",
                10
            ).unwrap();
            let p: BigInt = BigInt::from_str_radix(
                // "115792089237316195423570985008687907853269984665640564039457584007908834671663",
                "57896044618658097711785492504343953926634992332820282019728792003956564819949", 
                10
            ).unwrap();
            if y_int >= two_pow_255 {
                y_int = y_int - 19;
                y_int = y_int.mod_floor(&p);
            }
            yint_to_uint(&y_int)
        }


        fn point_to_uint(extpoint: Point) -> BigInt {
            // Curve 25519 only
            let mut bytes_y = extpoint.into_encoded_point(); // little endian
            bytes_y.reverse(); // BIg endian
            let mut y_int = BigInt::from_bytes(&bytes_y);
            let p: BigInt = BigInt::from_str_radix(
                // "115792089237316195423570985008687907853269984665640564039457584007908834671663",
                "57896044618658097711785492504343953926634992332820282019728792003956564819949", 
                10
            ).unwrap();
            let two_pow_255: BigInt = BigInt::from_str_radix(
                "57896044618658097711785492504343953926634992332820282019728792003956564819968",
                10
            ).unwrap();
            if y_int >= two_pow_255 {
                y_int = y_int - 19;
                y_int = y_int.mod_floor(&p);
            }
            yint_to_uint(&y_int)
        }


        // prime order of 25519 = 2^255 - 19
        let p: BigInt = BigInt::from_str_radix(
            // "115792089237316195423570985008687907853269984665640564039457584007908834671663",
            "57896044618658097711785492504343953926634992332820282019728792003956564819949", 
            10
        ).unwrap();

        fn pop(barry: &[u8]) -> [u8; 32] {
            barry.try_into().expect("slice with incorrect length")
        }
        
    /********   Initialize client's coordinates and extended edwards point  ******/
        let client_keypair: kx::KeyExchange = key_share.clone().unwrap();
        // debug_assert!(support_tls13);
        // let key_share = KeyShareEntry::new(key_share.group(), key_share.pubkey.as_ref());
        let bytes_print = &client_keypair.pubkey.bytes.bytes;// u-coor in little endian
        // println!("\n[client hs.rs] initial client pubkey.bytes.bytes: {:?}", bytes_print);
        let client_pubkey_bytes = &client_keypair.pubkey.bytes.bytes[0..32];// u-coor in little endian
        let client_pubkey_bytes: [u8; 32] = pop(&client_pubkey_bytes);
        println!("\n[client hs.rs] initial client pubkey.bytes.bytes 【u8;32】: {:?}", &client_pubkey_bytes);


        let mut client_pubkey_bytes_u_big_endian = client_pubkey_bytes;  
        client_pubkey_bytes_u_big_endian.reverse(); // u-coor in big endian
        let u_int = BigInt::from_bytes(&client_pubkey_bytes_u_big_endian); // to decimal
        // println!("u_int client ######### {}", u_int);
        let client_pubkey_extpoint = uint_to_extpoint(&u_int);
        let client_pubkey_extpoint_11 = uint_to_extpoint(&u_int);
        let u_after = extpoint_to_uint(client_pubkey_extpoint_11);
        // println!("u_int after client ######### {}", u_after);


        let mut u_by_pub_from_priv = client_keypair.privkey.private_key.compute_public_key().unwrap().bytes;
        u_by_pub_from_priv.reverse();
        let u_int_client = BigInt::from_bytes(&u_by_pub_from_priv); // to decimal
        // println!("u_int after client ######### {}", u_int_client);




    /********   Initialize verifier's coordinates and extended edwards point  ******/
        use std::io::{self, prelude::*, BufReader, Write};
        use std::net::TcpStream;
        use std::str;

        // let mut stream = TcpStream::connect(crate::TARGET_IP_WITH_PORT).unwrap();
        let (my_ip_port, target_ip, target_ip_port) = crate::get_ip();
        let mut stream = TcpStream::connect(&target_ip_port.as_str()).unwrap();
        let mut buf = [0; 256];
        let read_bytes = stream.read(&mut buf).unwrap();
        let bytes_verifier: [u8; 32] = pop(&buf[..read_bytes]);
        println!("g^v received from verifier: {:?}", bytes_verifier);

        // let mut reader = BufReader::new(&stream);
        // let mut buffer: Vec<u8> = Vec::new();
        // reader.read_until(b'\n', &mut buffer).expect("Failed to read into buffer");
        // println!("g^v received from verifier: {:?}", buffer);
        // let bytes_verifier: [u8; 32] = pop(&buffer.as_slice());

        let verifier_extpoint = ExtPoint::from_encoded_point_vartime(&bytes_verifier).unwrap();

        // transform from client's seed to its ext_point
        let mut client_extpoint = ExtPoint::new_at_infinity(); 
        let privkey_client: &[u8; SCALAR_LEN]  = client_keypair.privkey.private_key.bytes_less_safe().try_into().unwrap();
        let privkey_client = MaskedScalar::from_bytes_masked(*privkey_client);
        unsafe { 
            GFp_x25519_extpoint_from_private_generic_masked(
                &mut client_extpoint, 
                &privkey_client,
            )
        };
        let mut r1 = Point::new_at_infinity(); 
        unsafe { GFp_x25519_ge_add(&mut r1, &verifier_extpoint, &client_extpoint) };

        // Transform r1 to keyshare: Option<kx::KeyExchange>
        let len: usize = 32;
        let algorithm = client_keypair.pubkey.algorithm;
        let right: [u8; 65] = [0; 65];
        let u_int = point_to_uint(r1);
        let mut u_bytes = u_int.to_bytes(); // big endian
        u_bytes.reverse(); // little endian

        let num_of_zero_bytes = 32 - u_bytes.len();
        if num_of_zero_bytes > 0 {
            for _ in 0..num_of_zero_bytes {
                u_bytes.push(0);
            }
        }

        let left: [u8; 32] = pop(&u_bytes);
        let bytes: [u8; 97] = {
            let mut whole: [u8; 97] = [0; 97];
            let (one, two) = whole.split_at_mut(left.len());
            one.copy_from_slice(&left);
            two.copy_from_slice(&right);
            whole
        };
        // println!("\n[client hs.rs] rephrased client key share g^(x+v){:?}", &bytes);

        let bytes = keys::PublicKey {bytes,len};
        let pubkey = agreement::PublicKey {algorithm,bytes};
        let skxg = client_keypair.skxg;
        let privkey = client_keypair.privkey;
        let key_share_update = kx::KeyExchange {skxg,privkey,pubkey};

        //(x, g^(x+v))
        // let key_share: Option<kx::KeyExchange> = Some(key_share_update);
        key_share = Some(key_share_update);


        // println!("inserted code in hs.rs is executed.");
    }
//============================ INSERT ENDING ============================


    if let Some(resuming) = &mut resuming_session {
        #[cfg(feature = "tls12")]
        if let persist::ClientSessionValue::Tls12(inner) = &mut resuming.value {
            // If we have a ticket, we use the sessionid as a signal that
            // we're  doing an abbreviated handshake.  See section 3.4 in
            // RFC5077.
            if !inner.ticket().is_empty() {
                inner.session_id = SessionID::random()?;
            }
            session_id = Some(inner.session_id);
        }

        debug!("Resuming session");
    } else {
        debug!("Not resuming any session");
    }

    // https://tools.ietf.org/html/rfc8446#appendix-D.4
    // https://tools.ietf.org/html/draft-ietf-quic-tls-34#section-8.4
    if session_id.is_none() && !cx.common.is_quic() {
        session_id = Some(SessionID::random()?);
    }

    let random = Random::new()?;
    let hello_details = ClientHelloDetails::new();
    let sent_tls13_fake_ccs = false;
    let may_send_sct_list = config.verifier.request_scts();
    Ok(emit_client_hello_for_retry(
        config,
        cx,
        resuming_session,
        random,
        false,
        transcript_buffer,
        sent_tls13_fake_ccs,
        hello_details,
        session_id,
        None,
        server_name,
        key_share,
        extra_exts,
        may_send_sct_list,
        None,
    ))
}

struct ExpectServerHello {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Retrieved<persist::ClientSessionValue>>,
    server_name: ServerName,
    random: Random,
    using_ems: bool,
    transcript_buffer: HandshakeHashBuffer,
    early_key_schedule: Option<KeyScheduleEarly>,
    hello: ClientHelloDetails,
    offered_key_share: Option<kx::KeyExchange>,
    session_id: SessionID,
    sent_tls13_fake_ccs: bool,
    suite: Option<SupportedCipherSuite>,
}

struct ExpectServerHelloOrHelloRetryRequest {
    next: ExpectServerHello,
    extra_exts: Vec<ClientExtension>,
}

fn emit_client_hello_for_retry(
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
    resuming_session: Option<persist::Retrieved<persist::ClientSessionValue>>,
    random: Random,
    using_ems: bool,
    mut transcript_buffer: HandshakeHashBuffer,
    mut sent_tls13_fake_ccs: bool,
    mut hello: ClientHelloDetails,
    session_id: Option<SessionID>,
    retryreq: Option<&HelloRetryRequest>,
    server_name: ServerName,
    key_share: Option<kx::KeyExchange>,
    extra_exts: Vec<ClientExtension>,
    may_send_sct_list: bool,
    suite: Option<SupportedCipherSuite>,
) -> NextState {
    // Do we have a SessionID or ticket cached for this host?
    let (ticket, resume_version) = if let Some(resuming) = &resuming_session {
        match &resuming.value {
            persist::ClientSessionValue::Tls13(inner) => {
                (inner.ticket().to_vec(), ProtocolVersion::TLSv1_3)
            }
            #[cfg(feature = "tls12")]
            persist::ClientSessionValue::Tls12(inner) => {
                (inner.ticket().to_vec(), ProtocolVersion::TLSv1_2)
            }
        }
    } else {
        (Vec::new(), ProtocolVersion::Unknown(0))
    };

    let support_tls12 = config.supports_version(ProtocolVersion::TLSv1_2) && !cx.common.is_quic();
    let support_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);

    let mut supported_versions = Vec::new();
    if support_tls13 {
        supported_versions.push(ProtocolVersion::TLSv1_3);
    }

    if support_tls12 {
        supported_versions.push(ProtocolVersion::TLSv1_2);
    }

    let mut exts = Vec::new();
    if !supported_versions.is_empty() {
        exts.push(ClientExtension::SupportedVersions(supported_versions));
    }
    if let (Some(sni_name), true) = (server_name.for_sni(), config.enable_sni) {
        exts.push(ClientExtension::make_sni(sni_name));
    }
    exts.push(ClientExtension::ECPointFormats(
        ECPointFormatList::supported(),
    ));
    exts.push(ClientExtension::NamedGroups(
        config
            .kx_groups
            .iter()
            .map(|skxg| skxg.name)
            .collect(),
    ));
    exts.push(ClientExtension::SignatureAlgorithms(
        config
            .verifier
            .supported_verify_schemes(),
    ));
    exts.push(ClientExtension::ExtendedMasterSecretRequest);
    exts.push(ClientExtension::CertificateStatusRequest(
        CertificateStatusRequest::build_ocsp(),
    ));

    if may_send_sct_list {
        exts.push(ClientExtension::SignedCertificateTimestampRequest);
    }

    if let Some(key_share) = &key_share {
        debug_assert!(support_tls13);
        let key_share = KeyShareEntry::new(key_share.group(), key_share.pubkey.as_ref());
        exts.push(ClientExtension::KeyShare(vec![key_share]));
    }

    if let Some(cookie) = retryreq.and_then(HelloRetryRequest::get_cookie) {
        exts.push(ClientExtension::Cookie(cookie.clone()));
    }

    if support_tls13 && config.enable_tickets {
        // We could support PSK_KE here too. Such connections don't
        // have forward secrecy, and are similar to TLS1.2 resumption.
        let psk_modes = vec![PSKKeyExchangeMode::PSK_DHE_KE];
        exts.push(ClientExtension::PresharedKeyModes(psk_modes));
    }

    if !config.alpn_protocols.is_empty() {
        exts.push(ClientExtension::Protocols(ProtocolNameList::from_slices(
            &config
                .alpn_protocols
                .iter()
                .map(|proto| &proto[..])
                .collect::<Vec<_>>(),
        )));
    }

    // Extra extensions must be placed before the PSK extension
    exts.extend(extra_exts.iter().cloned());

    let fill_in_binder = if support_tls13
        && config.enable_tickets
        && resume_version == ProtocolVersion::TLSv1_3
        && !ticket.is_empty()
    {
        resuming_session
            .as_ref()
            .and_then(|resuming| match (suite, resuming.tls13()) {
                (Some(suite), Some(resuming)) => {
                    suite
                        .tls13()?
                        .can_resume_from(resuming.suite())?;
                    Some(resuming)
                }
                (None, Some(resuming)) => Some(resuming),
                _ => None,
            })
            .map(|resuming| {
                tls13::prepare_resumption(
                    &config,
                    cx,
                    ticket,
                    &resuming,
                    &mut exts,
                    retryreq.is_some(),
                );
                resuming
            })
    } else if config.enable_tickets {
        // If we have a ticket, include it.  Otherwise, request one.
        if ticket.is_empty() {
            exts.push(ClientExtension::SessionTicket(ClientSessionTicket::Request));
        } else {
            exts.push(ClientExtension::SessionTicket(ClientSessionTicket::Offer(
                Payload::new(ticket),
            )));
        }
        None
    } else {
        None
    };

    // Note what extensions we sent.
    hello.sent_extensions = exts
        .iter()
        .map(ClientExtension::get_type)
        .collect();

    let session_id = session_id.unwrap_or_else(SessionID::empty);
    let mut cipher_suites: Vec<_> = config
        .cipher_suites
        .iter()
        .map(|cs| cs.suite())
        .collect();
    // We don't do renegotiation at all, in fact.
    cipher_suites.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

    let mut chp = HandshakeMessagePayload {
        typ: HandshakeType::ClientHello,
        payload: HandshakePayload::ClientHello(ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random,
            session_id,
            cipher_suites,
            compression_methods: vec![Compression::Null],
            extensions: exts,
        }),
    };

    let early_key_schedule = if let Some(resuming) = fill_in_binder {
        let schedule = tls13::fill_in_psk_binder(&resuming, &transcript_buffer, &mut chp);
        Some((resuming.suite(), schedule))
    } else {
        None
    };

    let ch = Message {
        // "This value MUST be set to 0x0303 for all records generated
        //  by a TLS 1.3 implementation other than an initial ClientHello
        //  (i.e., one not generated after a HelloRetryRequest)"
        version: if retryreq.is_some() {
            ProtocolVersion::TLSv1_2
        } else {
            ProtocolVersion::TLSv1_0
        },
        payload: MessagePayload::Handshake(chp),
    };

    if retryreq.is_some() {
        // send dummy CCS to fool middleboxes prior
        // to second client hello
        tls13::emit_fake_ccs(&mut sent_tls13_fake_ccs, cx.common);
    }

    trace!("Sending ClientHello {:#?}", ch);

    transcript_buffer.add_message(&ch);
    cx.common.send_msg(ch, false);

    // Calculate the hash of ClientHello and use it to derive EarlyTrafficSecret
    let early_key_schedule = early_key_schedule.map(|(resuming_suite, schedule)| {
        if !cx.data.early_data.is_enabled() {
            return schedule;
        }

        tls13::derive_early_traffic_secret(
            &*config.key_log,
            cx,
            resuming_suite,
            &schedule,
            &mut sent_tls13_fake_ccs,
            &transcript_buffer,
            &random.0,
        );
        schedule
    });

    let next = ExpectServerHello {
        config,
        resuming_session,
        server_name,
        random,
        using_ems,
        transcript_buffer,
        early_key_schedule,
        hello,
        offered_key_share: key_share,
        session_id,
        sent_tls13_fake_ccs,
        suite,
    };

    if support_tls13 && retryreq.is_none() {
        Box::new(ExpectServerHelloOrHelloRetryRequest { next, extra_exts })
    } else {
        Box::new(next)
    }
}

pub(super) fn process_alpn_protocol(
    cx: &mut ClientContext<'_>,
    config: &ClientConfig,
    proto: Option<&[u8]>,
) -> Result<(), Error> {
    cx.common.alpn_protocol = proto.map(ToOwned::to_owned);

    if let Some(alpn_protocol) = &cx.common.alpn_protocol {
        if !config
            .alpn_protocols
            .contains(alpn_protocol)
        {
            return Err(cx
                .common
                .illegal_param("server sent non-offered ALPN protocol"));
        }
    }

    debug!(
        "ALPN protocol is {:?}",
        cx.common
            .alpn_protocol
            .as_ref()
            .map(|v| bs_debug::BsDebug(v))
    );
    Ok(())
}

pub(super) fn sct_list_is_invalid(scts: &SCTList) -> bool {
    scts.is_empty() || scts.iter().any(|sct| sct.0.is_empty())
}

impl State<ClientConnectionData> for ExpectServerHello {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> NextStateOrError {

        println!("state.handle");
        let server_hello =
            require_handshake_msg!(m, HandshakeType::ServerHello, HandshakePayload::ServerHello)?;
        trace!("We got ServerHello {:#?}", server_hello);

        use crate::ProtocolVersion::{TLSv1_2, TLSv1_3};
        let tls13_supported = self.config.supports_version(TLSv1_3);

        let server_version = if server_hello.legacy_version == TLSv1_2 {
            server_hello
                .get_supported_versions()
                .unwrap_or(server_hello.legacy_version)
        } else {
            server_hello.legacy_version
        };

        let version = match server_version {
            TLSv1_3 if tls13_supported => TLSv1_3,
            TLSv1_2 if self.config.supports_version(TLSv1_2) => {
                if cx.data.early_data.is_enabled() && cx.common.early_traffic {
                    // The client must fail with a dedicated error code if the server
                    // responds with TLS 1.2 when offering 0-RTT.
                    return Err(Error::PeerMisbehavedError(
                        "server chose v1.2 when offering 0-rtt".to_string(),
                    ));
                }

                if server_hello
                    .get_supported_versions()
                    .is_some()
                {
                    return Err(cx
                        .common
                        .illegal_param("server chose v1.2 using v1.3 extension"));
                }

                TLSv1_2
            }
            _ => {
                cx.common
                    .send_fatal_alert(AlertDescription::ProtocolVersion);
                let msg = match server_version {
                    TLSv1_2 | TLSv1_3 => "server's TLS version is disabled in client",
                    _ => "server does not support TLS v1.2/v1.3",
                };
                return Err(Error::PeerIncompatibleError(msg.to_string()));
            }
        };

        if server_hello.compression_method != Compression::Null {
            return Err(cx
                .common
                .illegal_param("server chose non-Null compression"));
        }

        if server_hello.has_duplicate_extension() {
            cx.common
                .send_fatal_alert(AlertDescription::DecodeError);
            return Err(Error::PeerMisbehavedError(
                "server sent duplicate extensions".to_string(),
            ));
        }

        let allowed_unsolicited = [ExtensionType::RenegotiationInfo];
        if self
            .hello
            .server_sent_unsolicited_extensions(&server_hello.extensions, &allowed_unsolicited)
        {
            cx.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(Error::PeerMisbehavedError(
                "server sent unsolicited extension".to_string(),
            ));
        }

        cx.common.negotiated_version = Some(version);

        // Extract ALPN protocol
        if !cx.common.is_tls13() {
            process_alpn_protocol(cx, &self.config, server_hello.get_alpn_protocol())?;
        }

        println!("hs.rs HandshakeFailure");

        // If ECPointFormats extension is supplied by the server, it must contain
        // Uncompressed.  But it's allowed to be omitted.
        if let Some(point_fmts) = server_hello.get_ecpoints_extension() {
            if !point_fmts.contains(&ECPointFormat::Uncompressed) {
                cx.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure);
                return Err(Error::PeerMisbehavedError(
                    "server does not support uncompressed points".to_string(),
                ));
            }
        }

        let suite = self
            .config
            .find_cipher_suite(server_hello.cipher_suite)
            .ok_or_else(|| {
                cx.common
                    .send_fatal_alert(AlertDescription::HandshakeFailure);
                Error::PeerMisbehavedError("server chose non-offered ciphersuite".to_string())
            })?;

        if version != suite.version().version {
            return Err(cx
                .common
                .illegal_param("server chose unusable ciphersuite for version"));
        }

        match self.suite {
            Some(prev_suite) if prev_suite != suite => {
                return Err(cx
                    .common
                    .illegal_param("server varied selected ciphersuite"));
            }
            _ => {
                debug!("Using ciphersuite {:?}", suite);
                self.suite = Some(suite);
                cx.common.suite = Some(suite);
            }
        }

        // Start our handshake hash, and input the server-hello.
        let mut transcript = self
            .transcript_buffer
            .start_hash(suite.hash_algorithm());
        transcript.add_message(&m);

        let randoms = ConnectionRandoms::new(self.random, server_hello.random, true);
        // For TLS1.3, start message encryption using
        // handshake_traffic_secret.
        match suite {
            SupportedCipherSuite::Tls13(suite) => {
                let resuming_session = self
                    .resuming_session
                    .and_then(|resuming| match resuming.value {
                        persist::ClientSessionValue::Tls13(inner) => Some(inner),
                        #[cfg(feature = "tls12")]
                        persist::ClientSessionValue::Tls12(_) => None,
                    });

                tls13::handle_server_hello(
                    self.config,
                    cx,
                    server_hello,
                    resuming_session,
                    self.server_name,
                    randoms,
                    suite,
                    transcript,
                    self.early_key_schedule,
                    self.hello,
                    // We always send a key share when TLS 1.3 is enabled.
                    self.offered_key_share.unwrap(),
                    self.sent_tls13_fake_ccs,
                )
            }
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(suite) => {
                let resuming_session = self
                    .resuming_session
                    .and_then(|resuming| match resuming.value {
                        persist::ClientSessionValue::Tls12(inner) => Some(inner),
                        persist::ClientSessionValue::Tls13(_) => None,
                    });

                tls12::CompleteServerHelloHandling {
                    config: self.config,
                    resuming_session,
                    server_name: self.server_name,
                    randoms,
                    using_ems: self.using_ems,
                    transcript,
                }
                .handle_server_hello(cx, suite, server_hello, tls13_supported)
            }
        }
    }
}

impl ExpectServerHelloOrHelloRetryRequest {
    fn into_expect_server_hello(self) -> NextState {
        Box::new(self.next)
    }

    fn handle_hello_retry_request(
        self,
        cx: &mut ClientContext<'_>,
        m: Message,
    ) -> NextStateOrError {
        let hrr = require_handshake_msg!(
            m,
            HandshakeType::HelloRetryRequest,
            HandshakePayload::HelloRetryRequest
        )?;
        trace!("Got HRR {:?}", hrr);

        cx.common.check_aligned_handshake()?;

        let cookie = hrr.get_cookie();
        let req_group = hrr.get_requested_key_share_group();

        // We always send a key share when TLS 1.3 is enabled.
        let offered_key_share = self.next.offered_key_share.unwrap();

        // A retry request is illegal if it contains no cookie and asks for
        // retry of a group we already sent.
        if cookie.is_none() && req_group == Some(offered_key_share.group()) {
            return Err(cx
                .common
                .illegal_param("server requested hrr with our group"));
        }

        // Or has an empty cookie.
        if let Some(cookie) = cookie {
            if cookie.0.is_empty() {
                return Err(cx
                    .common
                    .illegal_param("server requested hrr with empty cookie"));
            }
        }

        // Or has something unrecognised
        if hrr.has_unknown_extension() {
            cx.common
                .send_fatal_alert(AlertDescription::UnsupportedExtension);
            return Err(Error::PeerIncompatibleError(
                "server sent hrr with unhandled extension".to_string(),
            ));
        }

        // Or has the same extensions more than once
        if hrr.has_duplicate_extension() {
            return Err(cx
                .common
                .illegal_param("server send duplicate hrr extensions"));
        }

        // Or asks us to change nothing.
        if cookie.is_none() && req_group.is_none() {
            return Err(cx
                .common
                .illegal_param("server requested hrr with no changes"));
        }

        // Or asks us to talk a protocol we didn't offer, or doesn't support HRR at all.
        match hrr.get_supported_versions() {
            Some(ProtocolVersion::TLSv1_3) => {
                cx.common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
            }
            _ => {
                return Err(cx
                    .common
                    .illegal_param("server requested unsupported version in hrr"));
            }
        }

        // Or asks us to use a ciphersuite we didn't offer.
        let maybe_cs = self
            .next
            .config
            .find_cipher_suite(hrr.cipher_suite);
        let cs = match maybe_cs {
            Some(cs) => cs,
            None => {
                return Err(cx
                    .common
                    .illegal_param("server requested unsupported cs in hrr"));
            }
        };

        // HRR selects the ciphersuite.
        cx.common.suite = Some(cs);

        // This is the draft19 change where the transcript became a tree
        let transcript = self
            .next
            .transcript_buffer
            .start_hash(cs.hash_algorithm());
        let mut transcript_buffer = transcript.into_hrr_buffer();
        transcript_buffer.add_message(&m);

        // Early data is not allowed after HelloRetryrequest
        if cx.data.early_data.is_enabled() {
            cx.data.early_data.rejected();
        }

        let may_send_sct_list = self
            .next
            .hello
            .server_may_send_sct_list();

        let key_share = match req_group {
            Some(group) if group != offered_key_share.group() => {
                let group = kx::KeyExchange::choose(group, &self.next.config.kx_groups)
                    .ok_or_else(|| {
                        cx.common
                            .illegal_param("server requested hrr with bad group")
                    })?;
                kx::KeyExchange::start(group).ok_or(Error::FailedToGetRandomBytes)?
            }
            _ => offered_key_share,
        };

        Ok(emit_client_hello_for_retry(
            self.next.config,
            cx,
            self.next.resuming_session,
            self.next.random,
            self.next.using_ems,
            transcript_buffer,
            self.next.sent_tls13_fake_ccs,
            self.next.hello,
            Some(self.next.session_id),
            Some(hrr),
            self.next.server_name,
            Some(key_share),
            self.extra_exts,
            may_send_sct_list,
            Some(cs),
        ))
    }
}

impl State<ClientConnectionData> for ExpectServerHelloOrHelloRetryRequest {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message) -> NextStateOrError {
        check_message(
            &m,
            &[ContentType::Handshake],
            &[HandshakeType::ServerHello, HandshakeType::HelloRetryRequest],
        )?;
        if m.is_handshake_type(HandshakeType::ServerHello) {
            self.into_expect_server_hello()
                .handle(cx, m)
        } else {
            self.handle_hello_retry_request(cx, m)
        }
    }
}

pub(super) fn send_cert_error_alert(common: &mut CommonState, err: Error) -> Error {
    match err {
        Error::InvalidCertificateEncoding => {
            common.send_fatal_alert(AlertDescription::DecodeError);
        }
        Error::PeerMisbehavedError(_) => {
            common.send_fatal_alert(AlertDescription::IllegalParameter);
        }
        _ => {
            common.send_fatal_alert(AlertDescription::BadCertificate);
        }
    };

    err
}
