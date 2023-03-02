use std::net::TcpStream;
use std::io::Write;
use std::io::Read;
use curv::BigInt;
use curv::arithmetic::Converter;
use curv::arithmetic::Integer;
use curv::arithmetic::Modulo;
use std::convert::TryInto;
use ring::ec::suite_b::ops::Point;
use ring::ec::suite_b::ops::p256;
use untrusted::Input;

use crate::SupportedKxGroup;
use crate::kx::KeyExchange;
use crate::kx::KeyExchangeResult;
use crate::msgs::handshake::ServerECDHParams;
use crate::kx;

use ring::ec::curve25519::scalar::{Scalar, SCALAR_LEN};
use ring::ec::curve25519::ops::ExtPoint;
use ring::ec::curve25519::ops::Point as Point25519;
use crate::error::Error;

pub fn handle_point_addition_curve25519_step_one (
    ecdh_params: ServerECDHParams,
    group: &SupportedKxGroup,
    kx: KeyExchange
) -> kx::KeyExchange {

    println!("handle_point_addition_curve25519_step_one Hi");
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
        let y_int = crate::uint_to_yint(u_int);
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
        crate::yint_to_uint(&y_int)
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
        crate::yint_to_uint(&y_int)
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
    
    // send server pk g^y to verifier, so that verifier can compute ecdh (g^v)y = g^vy, 
    // as one of the two inputs of ECTF.
    let (my_ip_port, target_ip, target_ip_port) = crate::get_ip();
    let mut stream = TcpStream::connect(&target_ip_port.as_str()).unwrap();
    stream.write(&ecdh_params.public.0).unwrap();

    println!("ecdh_params.public.0: {:?}", ecdh_params.public.0);
    println!("ecdh_params: {:?}", ecdh_params);
    println!("group: {:?}", group);
    println!("kx: {:?}", kx);

/********   Initialize client's coordinates and extended edwards point  ******/
    let client_keypair: kx::KeyExchange = kx.clone();
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

    key_share_update
}

pub fn handle_point_addition_curve25519_step_two(
    their_key_share: ServerECDHParams,
    our_key_share: KeyExchange,
    kxd: KeyExchangeResult
) -> (kx::KeyExchangeResult, String) {

    use crate::client::ectf::*;

    fn get_bytes(mut stream: &TcpStream) -> BigInt {
        let mut buf = [0; 256]; 
        let read_bytes = stream.read(&mut buf).unwrap(); // read g^v
        let incoming = &buf[..read_bytes].to_vec();
        BigInt::from_bytes(&incoming)
    }
    
    fn pop(barry: &[u8]) -> [u8; 32] {
        barry.try_into().expect("slice with incorrect length")
    }

    fn uint_to_extpoint(u_int: &BigInt) -> ExtPoint {
        let y_int = crate::uint_to_yint(u_int);
        let mut bytes_y = y_int.to_bytes(); // big endian
        bytes_y.reverse(); // little endian

        let num_of_zero_bytes = 32 - bytes_y.len();
        if num_of_zero_bytes > 0 {
            for _ in 0..num_of_zero_bytes {
                bytes_y.push(0);
                // println!("final byte is 0: {:?}", &bytes_y);

            }
        }

        // println!("======= y bytes len: {}", bytes_y.len());
        let bytes_y: [u8; 32] = pop(&bytes_y);
        ExtPoint::from_encoded_point_vartime(&bytes_y).unwrap()
    }

    fn point_to_uint(extpoint: Point25519) -> BigInt {
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
        crate::yint_to_uint(&y_int)
    }


    // prime order of 25519 = 2^255 - 19
    let p: BigInt = BigInt::from_str_radix(
        // "115792089237316195423570985008687907853269984665640564039457584007908834671663",
        "57896044618658097711785492504343953926634992332820282019728792003956564819949", 
        10
    ).unwrap();
    
    // is still g^{xy}. we need to use this to do ECTF with verifier's g^{vy} \
    // share = ( client_pubkey: g^{x+v}, key_exchange (shared_secret): g^{xy} )
    // shared_pre = g^{xy}
    // our_key_share (x, g^(x+v))
    // their_key_share (y, g^y)
    // Diffie-Hellman: use x and y.
    let shared_pre = our_key_share.clone() 
        .complete(&their_key_share.public.0)
        .ok_or_else(|| Error::PeerMisbehavedError("key exchange failed".to_string())).unwrap();

    // println!("\n[client side: server's key share (payload.0)] {:?}", &their_key_share.payload.0);
    // println!("====== shared_pre.shared_secret: {:?} ======", shared_pre.shared_secret.clone());

    let mut U_xy_bytes = shared_pre.shared_secret.clone(); // little endian
    // println!("U_xy little endian = {:?}", U_xy_bytes);
    U_xy_bytes.reverse();  // big endian

    fn send_g_y_to_verifier(mut stream: &TcpStream, u_coor_server: &Vec<u8>) {
        let mut buf = [0; 256];
        stream.write(u_coor_server).unwrap();
    }

    let (my_ip_port, target_ip, target_ip_port) = crate::get_ip();
    // let mut stream = TcpStream::connect(crate::TARGET_IP_WITH_PORT).unwrap();
    // let mut stream = TcpStream::connect(&target_ip_port.as_str()).unwrap();
    // send_g_y_to_verifier(&stream, &their_key_share.public.0);
    // println!("g^y has been sent to verifier: {:?}", &their_key_share.public.0);

    // ===================  ECTF starts  ======================
    let a2 = BigInt::from(486662);
    let x1 = BigInt::from_bytes(&U_xy_bytes);
    let y1 = get_v_coordinate(x1.clone());
    let s1 = ectf(p.clone(), a2.clone(), x1.clone(), y1.clone());
    // ===================  ECTF ends  ======================

    // let stream = TcpStream::connect(&target_ip_port.as_str()).unwrap();
    // let s2 = get_bytes(&stream);
    // let s_sum = BigInt::mod_add(&s1, &s2, &p.clone());
    // println!("s_sum: {:?}", s_sum);

    let s1_str: String = s1.to_hex().to_string();
    println!("s1: {}", s1_str);
    let mut u_bytes = s1.to_bytes();

    u_bytes.reverse(); // little endian
    println!("u_bytes: {:?}", u_bytes);

    let num_of_zero_bytes = 32 - u_bytes.len();
    if num_of_zero_bytes > 0 {
        for _ in 0..num_of_zero_bytes {
            u_bytes.push(0);
        }
    }
    // println!("after reverse: {:?}", u_bytes);
    // ECTF end   

    // update share -> ( client_pubkey: g^{x+v}, key_exchange: g^{(x+v)y} )
    let shared = kx::KeyExchangeResult{
        pubkey: shared_pre.pubkey,
        shared_secret: u_bytes.clone(),
    };

    (shared, s1_str)
}

pub fn handle_point_addition_p256_step_one (
    ecdh_params: ServerECDHParams,
    group: &SupportedKxGroup,
    kx: KeyExchange
) -> kx::KeyExchange {
    
    // [Aim] We need to modify kx to (x, g^(x+v)) by point addition, 
    // refer to how it is done in hs.rs, "GFp_x25519_ge_add"

    fn get_payload(mut stream: &TcpStream) -> Vec<u8> {
        let mut buf = [0; 8000000]; 
        let read_bytes = stream.read(&mut buf).unwrap(); 
        buf[..read_bytes].to_vec()
    }

    fn point_add(output_x: &mut [u8], output_y: &mut [u8], client_key: &[u8], verifier_key: &[u8]) {

        let (client_px, client_py) = ring::ec::suite_b::public_key::parse_uncompressed_point(
            &p256::PUBLIC_KEY_OPS,
            Input::from(client_key)
        ).unwrap();
        let (verifier_px, verifier_py) = ring::ec::suite_b::public_key::parse_uncompressed_point(
            &p256::PUBLIC_KEY_OPS,
            Input::from(verifier_key)
        ).unwrap();

        println!("client_px: {:?}", client_px.limbs);
        println!("client_py: {:?}", client_py.limbs);
        println!("verifier_px: {:?}", verifier_px.limbs);
        println!("verifier_py: {:?}", verifier_py.limbs);

        let mut client_point = Point::new_at_infinity();
        unsafe {
            ring::ec::suite_b::ops::p256::Convert_px_py_to_Point(
                client_point.xyz.as_mut_ptr(),
                client_px.limbs.as_ptr(),
                client_py.limbs.as_ptr()
            );
        }
        let mut verifier_point = Point::new_at_infinity();
        unsafe {
            ring::ec::suite_b::ops::p256::Convert_px_py_to_Point(
                verifier_point.xyz.as_mut_ptr(),
                verifier_px.limbs.as_ptr(),
                verifier_py.limbs.as_ptr()
            );
        }

        // The result of point addition
        let mut r = Point::new_at_infinity();

        // Call the function in p256.rs
        // pub fn GFp_nistz256_point_add(
        //     r: *mut Limb,   // [3][COMMON_OPS.num_limbs]
        //     a: *const Limb, // [3][COMMON_OPS.num_limbs]
        //     b: *const Limb, // [3][COMMON_OPS.num_limbs]
        // );
        unsafe {
            ring::ec::suite_b::ops::p256::GFp_nistz256_point_add(
                r.xyz.as_mut_ptr(),
                client_point.xyz.as_ptr(),
                verifier_point.xyz.as_ptr(),
            );
        }

        // let r_x = p256::PUBLIC_KEY_OPS.common.point_x(&r);
        println!("r.xyz: {:?}", r.xyz);

        ring::ec::suite_b::private_key::big_endian_affine_from_jacobian(
            &p256::PRIVATE_KEY_OPS, 
            Some(output_x), 
            Some(output_y),  
            &r
        ).unwrap();

        println!("output_x: {:?}", output_x);
        println!("output_x len: {:?}", output_x.len());
        println!("output_x BigInt: {:?}", BigInt::from_bytes(&output_x));
        println!("output_y: {:?}", output_y);
        println!("output_y len: {:?}", output_y.len());
        println!("output_y BigInt: {:?}", BigInt::from_bytes(&output_y));
    }

    fn point_double(output: &mut [u8], client_key: &[u8])  {
        
        let (client_px, client_py) = ring::ec::suite_b::public_key::parse_uncompressed_point(
            &p256::PUBLIC_KEY_OPS,
            Input::from(client_key)
        ).unwrap();

        let mut client_point = Point::new_at_infinity();
        unsafe {
            ring::ec::suite_b::ops::p256::Convert_px_py_to_Point(
                client_point.xyz.as_mut_ptr(),
                client_px.limbs.as_ptr(),
                client_py.limbs.as_ptr()
            );
        }

        // The result of point doubling
        let mut r = Point::new_at_infinity();
        unsafe {
            ring::ec::suite_b::ops::p256::GFp_nistz256_point_double(
                r.xyz.as_mut_ptr(),
                client_point.xyz.as_ptr()
            );
        }

        ring::ec::suite_b::private_key::big_endian_affine_from_jacobian(
            &p256::PRIVATE_KEY_OPS, 
            Some(output), 
            None, 
            &r
        ).unwrap();

        println!("output: {:?}", output);
        println!("output BigInt: {:?}", BigInt::from_bytes(&output));
    }

    fn pop(barry: &[u8]) -> [u8; 32] {
        use std::convert::TryInto;
        barry.try_into().expect("slice with incorrect length")
    }

    // send server pk g^y to verifier, so that verifier can compute ecdh (g^v)y = g^vy, 
    // as one of the two inputs of ECTF.
    let (my_ip_port, target_ip, target_ip_port) = crate::get_ip();
    let mut stream = TcpStream::connect(&target_ip_port.as_str()).unwrap();
    stream.write(&ecdh_params.public.0).unwrap();

    println!("ecdh_params.public.0: {:?}", ecdh_params.public.0);
    println!("ecdh_params: {:?}", ecdh_params);
    println!("group: {:?}", group);
    println!("kx: {:?}", kx);

    // Get verifier_key = g^v
    let mut stream = TcpStream::connect(&target_ip_port.as_str()).unwrap();
    let verifier_key = get_payload(&stream); // g^v

    // Client key g^x
    let client_key = kx.pubkey.bytes.as_ref(); // [u8]

    // Modify key: g^x -> g^(x+v)
    // Result stores in client_verifier_key
    // Point addition 
    // darren: g^x, kx.pubkey.bytes.as_ref() ; g^v verifier_key
    let mut client_verifier_key: [u8; 33] = [0u8; 33];
    let client_verifier_key = &mut client_verifier_key[..32];
    let mut client_verifier_key_y: [u8; 33] = [0u8; 33];
    let client_verifier_key_y = &mut client_verifier_key_y[..32];
    point_add(client_verifier_key,  client_verifier_key_y, &client_key, &verifier_key);
    println!("client_verifier_key: {:?}", client_verifier_key);
    println!("client_verifier_key bigint: {:?}", BigInt::from_bytes(&client_verifier_key));
    println!("len: {:?}", client_verifier_key.len());

    // // Test
    // println!("Test point addition");
    // println!("point_add");
    // let mut test: [u8; 33] = [0u8; 33];
    // let test = &mut test[..32];
    // point_add(test, &client_key, &client_key);
    // println!("output: {:?}", test);
    // println!("output BigInt: {:?}", BigInt::from_bytes(&test));

    // println!("point_double");
    // let mut test2: [u8; 33] = [0u8; 33];
    // let test2 = &mut test2[..32];
    // point_double(test2, &client_key);
    // println!("output: {:?}", test2);
    // println!("output BigInt: {:?}", BigInt::from_bytes(&test2));

    // client_verifier_key.reverse();

    // Construct the format of pubkey
    // [4, <x_coord>, <y_coord>]
    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(4);
    let mut client_verifier_key = client_verifier_key.to_vec();
    let mut client_verifier_key_y = client_verifier_key_y.to_vec();
    for i in 0..client_verifier_key.len() {
        bytes.push(client_verifier_key[i]);
    }
    for i in 0..client_verifier_key_y.len() {
        bytes.push(client_verifier_key_y[i]);
    }

    for _ in 0..97-bytes.len() {
        bytes.push(0);
    }
    println!("bytes len: {:?}", bytes.len());
    println!("client_verifier_key: {:?}", client_verifier_key);
    println!("bytes: {:?}", bytes);
    
    // Switch kx from g^x -> g^(x+v)
    let len: usize = 65;
    let algorithm = kx.pubkey.algorithm;
    let bytes = ring::ec::keys::PublicKey {bytes: bytes.try_into().unwrap(), len};
    let pubkey = ring::agreement::PublicKey {algorithm, bytes};
    let kx_xv = kx::KeyExchange {
        skxg: kx.skxg,
        privkey: kx.privkey,
        pubkey: pubkey
    };

    kx_xv
}

pub fn handle_point_addition_p256_step_two(
    kxd: KeyExchangeResult
) -> (kx::KeyExchangeResult, String) {

    let (my_ip_port, target_ip, target_ip_port) = crate::get_ip();

    // ===================  ECTF starts  ======================
    use curv::arithmetic::Modulo;

    // g^xy
    let mut client_shared_secret = kxd.shared_secret.clone();  // little endian
    // client_shared_secret.reverse(); // big endian

    // p for secp256r1
    let p: BigInt = BigInt::from_str_radix(
        "115792089210356248762697446949407573530086143415290314195533631308867097853951",
        10
    ).unwrap();
    let a2 = BigInt::from(0);
    let x1 = BigInt::from_bytes(&client_shared_secret); // big endian 
    let y1 = crate::client::ectf::get_secp256r1_v_coordinate(x1.clone(), p.clone());
    let s1 = crate::client::ectf::ectf(p.clone(), a2.clone(), x1.clone(), y1.clone());

    fn get_bytes(mut stream: &TcpStream) -> BigInt {
        let mut buf = [0; 256]; 
        let read_bytes = stream.read(&mut buf).unwrap(); // read g^v
        let incoming = &buf[..read_bytes].to_vec();
        BigInt::from_bytes(&incoming)
    }

    // // Get verifier share
    // let stream = TcpStream::connect(&target_ip_port.as_str()).unwrap();
    // let s2 = get_bytes(&stream);
    // let s_sum = BigInt::mod_add(&s1, &s2, &p.clone());

    // darren: how to validate ectf and point add? 
    // send h = g^(x+v), which is in kx, to server.
    // then in server side, it computes the result h1 = h^y using its server sk = y.
    // now it turns to verifier/client side, after ectf, obtain s1 + s2 = x_coor of g^(x+v)y
    // check if x_coor of h1 is equal to x_coor of (s1+s2)
    println!("s1: {:?}", s1);
    // println!("s2: {:?}", s2);
    // println!("s_sum: {:?}", s_sum);

    // let kxd = kx::KeyExchangeResult{pubkey: kxd.pubkey, shared_secret: new_x_bytes.clone()};
    // println!("kxd: {:?}", kxd);
    // ===================  ECTF ends  ======================

    let s1_str: String = s1.to_hex().to_string();
    let mut u_bytes = s1.to_bytes();
    // let mut u_bytes = s_sum.to_bytes();
    // println!("u_bytes: {:?}", u_bytes);
    // u_bytes.reverse(); // little endian
    let num_of_zero_bytes = 32 - u_bytes.len();
    if num_of_zero_bytes > 0 {
        for _ in 0..num_of_zero_bytes {
            u_bytes.push(0);
        }
    }

    // update share -> ( client_pubkey: g^{x+v}, key_exchange: g^{(x+v)y} )
    // client share, not the whole
    let kxd = kx::KeyExchangeResult{
        pubkey: kxd.pubkey,
        shared_secret: u_bytes.clone(),
    };
    // println!("[by ectf] g^(x+v)y in client: {:?}", &u_bytes);

    (kxd, s1_str)
}