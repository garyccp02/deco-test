/*
    ECtF for DECO
    Chan Kwan Yin

    kychancf.github.io
*/

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

use crate::client::client_conn::ClientConnectionData;
use crate::client::common::ClientHelloDetails;
use crate::client::{tls13, ClientConfig, ServerName};

use std::sync::Arc;

pub(super) type NextState = Box<dyn State<ClientConnectionData>>;
pub(super) type NextStateOrError = Result<NextState, Error>;
pub(super) type ClientContext<'a> = crate::conn::Context<'a, ClientConnectionData>;

use paillier::traits::EncryptWithChosenRandomness;
use paillier::{
    Encrypt, Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext, RawPlaintext, Mul, Add
};

use curv::arithmetic::traits::Samplable;
// use curv::elliptic::curves::traits::*;
use curv::BigInt;
use curv::arithmetic::traits::*;
use class_group::primitives::cl_dl_lcm::*;
use std::net::TcpListener;
use std::time::Duration;
use std::time::Instant;

fn cal_25519_rhs(
    u: BigInt
) -> BigInt {

    // p for 25519
    let p: BigInt = BigInt::from_str_radix(
        // "115792089237316195423570985008687907853269984665640564039457584007908834671663",
        "57896044618658097711785492504343953926634992332820282019728792003956564819949",
        10
    ).unwrap();

    // Some constants
    let two = BigInt::from(2);
    let three = BigInt::from(3);

    // ========== Part 1 ==========
    // Equation of Curve 25519.
    // v^2 = u^3 + 486662 u^2 + u

    // Calculate the RHS
    let x3_term = BigInt::mod_pow(&u, &three, &p);
    let x2_term_temp = BigInt::mod_pow(&u, &two, &p);
    let x2_term = BigInt::mod_mul(&x2_term_temp, &BigInt::from(486662), &p);

    let sum_temp = BigInt::mod_add(&x3_term, &x2_term, &p);
    let sum = BigInt::mod_add(&sum_temp, &u, &p);
    
    sum
}

fn tonelli_shanks(
    n: BigInt,
    p: BigInt
) -> BigInt {

    // Some constants
    let zero = BigInt::from(0);
    let one = BigInt::from(1);
    let two = BigInt::from(2);
    let three = BigInt::from(3);
    let four = BigInt::from(4);

    // Tonelli-Shanks algorithm

    // Check if any square root exist using Jacobi symbol.
    if jacobi(&n, &p).unwrap() == 1 {}
    else {
        assert!(0 == 1, "Jacobi failed.");
    }

    // Step 1: Factor out powers two.
    let mut q = &p - &one;
    let mut s = zero.clone();
    while q.modulus(&two) == zero {
        s += &one;
        q >>= 1;
    }
    // println!("Step 1a done");

    // Step 1: Direct solution
    if s == one {
        let r1 = BigInt::mod_pow(&n, &((&p + &one).div_floor(&four)), &p);
        if BigInt::mod_pow(&r1, &r1, &p) == n {
            return r1;
        }
        // println!("No solution: return 0.");
        // return zero;
    }
    // println!("Step 1b done");

    // Step 2: Select z, assign c
    let mut z = one.clone();
    while BigInt::mod_pow(&z, &((&p - &one).div_floor(&two)), &p) != &p - &one {
        z += &one; 
    }
    let mut c = BigInt::mod_pow(&z, &q, &p);

    // Step 3: Assign R, t, M
    let mut r = BigInt::mod_pow(&n, &((&q + &one).div_floor(&two)), &p);
    let mut t = BigInt::mod_pow(&n, &q, &p);
    let mut m = s.clone();

    // Step 4: loop
    while t != one {
        
        // Find lowest i...
        let mut i = zero.clone();
        let mut tt = t.clone();
        while tt != one {
            tt = BigInt::mod_mul(&tt, &tt, &p);
            i += &one;
            if i == m { return zero; }
        }
        let b = BigInt::mod_pow(&c, &BigInt::mod_pow(&two, &(&m-&i-&one), &(&p-&one)), &p);
        let b2 = BigInt::mod_mul(&b, &b, &p);

        r = BigInt::mod_mul(&r, &b, &p);
        c = b2.clone();
        t = BigInt::mod_mul(&t, &c, &p);
        m = i.clone();
    }

    if BigInt::mod_mul(&r, &r, &p) == n {
        return r;
    }

    assert!(0 == 1, "No solution.");
    return zero;
}

// get_v_coordinate(u: BigInt)
// To calculate v-coordinate by square root modulo
pub fn get_v_coordinate(
    u: BigInt
) -> BigInt {

    // p for 25519
    let p: BigInt = BigInt::from_str_radix(
        // "115792089237316195423570985008687907853269984665640564039457584007908834671663",
        "57896044618658097711785492504343953926634992332820282019728792003956564819949",
        10
    ).unwrap();


    // 1. Calculate the v^2 using the equation of Curve 25519.
    let n = cal_25519_rhs(
        u.clone()
    );

    // 2. Run Tonelli-Shanks algorithm for square root modolo p.
    let v = tonelli_shanks(
        n.clone(),
        p.clone()
    );

    v
}

pub fn ECtF_Paillier(
    x1: BigInt,
    y1: BigInt,
    x2: BigInt,
    y2: BigInt
) -> (BigInt, BigInt) {

    // 3 rounds

    // ========== Inputs ==========
    // p for 25519
    let p: BigInt = BigInt::from_str_radix(
        // "115792089237316195423570985008687907853269984665640564039457584007908834671663",
        "57896044618658097711785492504343953926634992332820282019728792003956564819949",
        10
    ).unwrap();
    let a2 = BigInt::from(486662);

    // println!("{}", BigInt::from(2).pow(255) - BigInt::from(19));
    // println!("{}", BigInt::modulus(&p, &BigInt::from(4)));

    let (mut ek, mut dk) = Paillier::keypair_with_modulus_size(3072).keys();

    let minus_one = BigInt::from(-1);

    // ==================== Step 1 ==================== 
    // Prover

    let Cx = Paillier::encrypt(
        &ek,
        RawPlaintext::from(&x1)
    );

    let Cy = Paillier::encrypt(
        &ek,
        RawPlaintext::from(&y1)
    );

    let r1 = BigInt::sample_below(&p); 
    let Cr = Paillier::encrypt(
        &ek,
        RawPlaintext::from(&r1)
    );

    let y1r1 = BigInt::mod_mul(&y1, &r1, &p);
    let Cry = Paillier::encrypt(
        &ek,
        RawPlaintext::from(&y1r1)
    );

    // ==================== Step 2 ==================== 
    // Verifier

    let r2 = BigInt::sample_below(&p); 
    let beta2 = BigInt::sample_below(&p); 
    let gamma2 = BigInt::sample_below(&p); 
    let alpha2 = BigInt::sample_below(&p); 

    // Compute C_beta
    let Cx_r2 = Paillier::mul(
        &ek,
        RawCiphertext::from(Cx.clone()),
        RawPlaintext::from(&r2)
    );

    let neg_x2 = BigInt::mod_mul(&x2, &minus_one, &p);
    let Cr_neg_x2 = Paillier::mul(
        &ek,
        RawCiphertext::from(Cr.clone()),
        RawPlaintext::from(&neg_x2)
    );

    let neg_beta2 = BigInt::mod_mul(&beta2, &minus_one, &p);
    let enc_neg_beta2 = Paillier::encrypt(
        &ek,
        RawPlaintext::from(&neg_beta2)
    );

    let C_beta_temp = Paillier::add(
        &ek,
        Cx_r2.clone(),
        Cr_neg_x2.clone()
    );

    let C_beta = Paillier::add(
        &ek,
        C_beta_temp.clone(),
        enc_neg_beta2.clone()
    );

    // Compute C_gamma
    let Cy_r2 = Paillier::mul(
        &ek,
        RawCiphertext::from(Cy.clone()),
        RawPlaintext::from(&r2)
    );

    let neg_y2 = BigInt::mod_mul(&y2, &minus_one, &p);
    let Cr_neg_y2 = Paillier::mul(
        &ek,
        RawCiphertext::from(Cr.clone()),
        RawPlaintext::from(&neg_y2)
    );

    let neg_gamma2 = BigInt::mod_mul(&gamma2, &minus_one, &p);
    let enc_neg_gamma2 = Paillier::encrypt(
        &ek,
        RawPlaintext::from(&neg_gamma2)
    );

    let C_gamma_temp = Paillier::add(
        &ek,
        Cy_r2.clone(),
        Cr_neg_y2.clone()
    );

    let C_gamma = Paillier::add(
        &ek,
        C_gamma_temp.clone(),
        enc_neg_gamma2.clone()
    );

    // Compute delta2
    let x2r2 = BigInt::mod_mul(&x2, &r2, &p);
    let delta2 = BigInt::mod_sub(&beta2, &x2r2, &p);

    // Compute omega2
    let y2r2 = BigInt::mod_mul(&y2, &r2, &p);
    let omega2 = BigInt::mod_sub(&gamma2, &y2r2, &p);

    // Compute C_alpha
    let C_gamma_C_ry = Paillier::add(
        &ek,
        C_gamma.clone(),
        Cry.clone()
    );

    let C_gamma_C_ry_omega2 = Paillier::mul(
        &ek,
        RawCiphertext::from(C_gamma_C_ry.clone()),
        RawPlaintext::from(&omega2)
    );

    let neg_alpha2 = BigInt::mod_mul(&alpha2, &minus_one, &p);
    let enc_neg_alpha2 = Paillier::encrypt(
        &ek,
        RawPlaintext::from(&neg_alpha2)
    );

    let C_alpha = Paillier::add(
        &ek,
        RawCiphertext::from(C_gamma_C_ry_omega2.clone()),
        RawCiphertext::from(enc_neg_alpha2.clone())
    );

    // ==================== Step 3 ==================== 
    // Prover

    // Compute beta1
    let beta1 = Paillier::decrypt(
        &dk,
        RawCiphertext::from(C_beta.clone())
    ).0
    .clone()
    .into_owned();

    // // Check
    // let beta1_plus_beta2 = BigInt::mod_add(&beta1, &beta2, &p);
    // let x1r2 = BigInt::mod_mul(&x1, &r2, &p);
    // let x2r1 = BigInt::mod_mul(&x2, &r1, &p);
    // let x1r2_sub_x2r1 = BigInt::mod_sub(&x1r2, &x2r1, &p);
    // assert!(beta1_plus_beta2 == x1r2_sub_x2r1);

    // Compute delta1
    let x1r1 = BigInt::mod_mul(&x1, &r1, &p);
    let delta1 = BigInt::mod_add(&beta1, &x1r1, &p);

    // Compute gamma1
    let gamma1 = Paillier::decrypt(
        &dk,
        RawCiphertext::from(C_gamma.clone())
    ).0
    .clone()
    .into_owned();

    // // Check
    // let gamma1_plus_gamma2 = BigInt::mod_add(&gamma1, &gamma2, &p);
    // let y1r2 = BigInt::mod_mul(&y1, &r2, &p);
    // let y2r1 = BigInt::mod_mul(&y2, &r1, &p);
    // let y1r2_sub_y2r1 = BigInt::mod_sub(&y1r2, &y2r1, &p);
    // assert!(gamma1_plus_gamma2 == y1r2_sub_y2r1);

    // Compute delta
    let delta = BigInt::mod_add(&delta1, &delta2, &p);

    // Copmute omega1
    let omega1 = BigInt::mod_add(&gamma1, &y1r1, &p);

    // Copmute alpha1
    let alpha1 = Paillier::decrypt(
        &dk,
        RawCiphertext::from(C_alpha.clone())
    ).0
    .clone()
    .into_owned();

    // println!("{}", delta);

    // Copmute s1
    let omega1_square = BigInt::mod_mul(&omega1, &omega1, &p);
    let two_alpha1 = BigInt::mod_add(&alpha1, &alpha1, &p);
    let delta_inv = BigInt::mod_inv(&delta, &p).unwrap();
    let delta_inv_square = BigInt::mod_mul(&delta_inv, &delta_inv, &p);
    let temp = BigInt::mod_add(&omega1_square, &two_alpha1, &p);
    let tempp = BigInt::mod_mul(&temp, &delta_inv_square, &p);
    let temppp = BigInt::mod_sub(&tempp, &a2, &p);
    let s1 = BigInt::mod_sub(&temppp, &x1, &p);

    // // Check omega1 + omega2 = delta * lambda
    // let y2_minus_y1 = BigInt::mod_sub(&y2, &y1, &p);
    // let x2_minus_x1 = BigInt::mod_sub(&x2, &x1, &p);
    // let lambda = BigInt::mod_mul(&y2_minus_y1, &BigInt::mod_inv(&x2_minus_x1, &p), &p);
    // let omega1_plua_omega2 = BigInt::mod_add(&omega1, &omega2, &p);
    // let delta_mul_lambda = BigInt::mod_mul(&delta, &lambda, &p);
    // assert!(omega1_plua_omega2 == delta_mul_lambda);

    // // Check alpha1 + alpha2 = omega1 * omega2
    // let alpha1_plua_alpha2 = BigInt::mod_add(&alpha1, &alpha2, &p);
    // let omega1_mul_omega2 = BigInt::mod_mul(&omega1, &omega2, &p);
    // assert!(alpha1_plua_alpha2 == omega1_mul_omega2);

    // ==================== Step 4 ==================== 
    // Verifier

    // Compute delta
    let delta = BigInt::mod_add(&delta1, &delta2, &p);

    // Copmute s2
    let omega2_square = BigInt::mod_mul(&omega2, &omega2, &p);
    let two_alpha2 = BigInt::mod_add(&alpha2, &alpha2, &p);
    let delta_inv = BigInt::mod_inv(&delta, &p).unwrap();
    let delta_inv_square = BigInt::mod_mul(&delta_inv, &delta_inv, &p);
    let temp = BigInt::mod_add(&omega2_square, &two_alpha2, &p);
    let tempp = BigInt::mod_mul(&temp, &delta_inv_square, &p);
    let s2 = BigInt::mod_sub(&tempp, &x2, &p);

    // Check (step 4)   
    let y2_minus_y1 = BigInt::mod_sub(&y2, &y1, &p);
    let x2_minus_x1 = BigInt::mod_sub(&x2, &x1, &p);
    let lambda = BigInt::mod_mul(&y2_minus_y1, &BigInt::mod_inv(&x2_minus_x1, &p).unwrap(), &p);
    let lhs = BigInt::mod_add(&s1, &s2, &p); 
    let lambda_square = BigInt::mod_mul(&lambda, &lambda, &p);
    let lambda_square_sub_a2 = BigInt::mod_sub(&lambda_square, &a2, &p);
    let lambda_square_sub_a2_sub_x1 = BigInt::mod_sub(&lambda_square_sub_a2, &x1, &p);
    let rhs = BigInt::mod_sub(&lambda_square_sub_a2_sub_x1, &x2, &p);
    assert!(lhs == rhs);

    (s1, s2)

}

pub fn ECtF_CL(
    x1: BigInt,
    y1: BigInt,
    x2: BigInt,
    y2: BigInt
) -> (BigInt, BigInt) {

    // 3 rounds

    // ========== Inputs ==========
    // p for 25519
    let p: BigInt = BigInt::from_str_radix(
        // "115792089237316195423570985008687907853269984665640564039457584007908834671663",
        "57896044618658097711785492504343953926634992332820282019728792003956564819949",
        10
    ).unwrap();
    let a2 = BigInt::from(486662);

    let hsmcl = HSMCL::keygen(&p, &1827);
    let ek = hsmcl.pk.clone();
    let minus_one = BigInt::from(-1);

    // ==================== Step 1 ==================== 
    // Prover

    let Cx = HSMCL::encrypt(
        &ek,
        &x1
    );

    let Cy = HSMCL::encrypt(
        &ek,
        &y1
    );

    let r1 = BigInt::sample_below(&p); 
    let Cr = HSMCL::encrypt(
        &ek,
        &r1
    );

    let y1r1 = BigInt::mod_mul(&y1, &r1, &p);
    let Cry = HSMCL::encrypt(
        &ek,
        &y1r1
    );

    // ==================== Step 2 ==================== 
    // Verifier

    let r2 = BigInt::sample_below(&p); 
    let beta2 = BigInt::sample_below(&p); 
    let gamma2 = BigInt::sample_below(&p); 
    let alpha2 = BigInt::sample_below(&p); 

    // Compute C_beta
    let Cx_r2 = HSMCL::eval_scal(
        &Cx,
        &r2
    );

    let neg_x2 = BigInt::mod_mul(&x2, &minus_one, &p);
    let Cr_neg_x2 = HSMCL::eval_scal(
        &Cr,
        &neg_x2
    );

    let neg_beta2 = BigInt::mod_mul(&beta2, &minus_one, &p);
    let enc_neg_beta2 = HSMCL::encrypt(
        &ek,
        &neg_beta2
    );

    let C_beta_temp = HSMCL::eval_sum(
        &Cx_r2,
        &Cr_neg_x2
    );

    let C_beta = HSMCL::eval_sum(
        &C_beta_temp,
        &enc_neg_beta2
    );

    // Compute C_gamma
    let Cy_r2 = HSMCL::eval_scal(
        &Cy,
        &r2
    );

    let neg_y2 = BigInt::mod_mul(&y2, &minus_one, &p);
    let Cr_neg_y2 = HSMCL::eval_scal(
        &Cr,
        &neg_y2
    );

    let neg_gamma2 = BigInt::mod_mul(&gamma2, &minus_one, &p);
    let enc_neg_gamma2 = HSMCL::encrypt(
        &ek,
        &neg_gamma2
    );

    let C_gamma_temp = HSMCL::eval_sum(
        &Cy_r2,
        &Cr_neg_y2
    );

    let C_gamma = HSMCL::eval_sum(
        &C_gamma_temp,
        &enc_neg_gamma2
    );

    // Compute delta2
    let x2r2 = BigInt::mod_mul(&x2, &r2, &p);
    let delta2 = BigInt::mod_sub(&beta2, &x2r2, &p);

    // Compute omega2
    let y2r2 = BigInt::mod_mul(&y2, &r2, &p);
    let omega2 = BigInt::mod_sub(&gamma2, &y2r2, &p);

    // Compute C_alpha
    let C_gamma_C_ry = HSMCL::eval_sum(
        &C_gamma,
        &Cry
    );

    let C_gamma_C_ry_omega2 = HSMCL::eval_scal(
        &C_gamma_C_ry,
        &omega2
    );

    let neg_alpha2 = BigInt::mod_mul(&alpha2, &minus_one, &p);
    let enc_neg_alpha2 = HSMCL::encrypt(
        &ek,
        &neg_alpha2
    );

    let C_alpha = HSMCL::eval_sum(
        &C_gamma_C_ry_omega2,
        &enc_neg_alpha2
    );

    // ==================== Step 3 ==================== 
    // Prover

    // Compute beta1
    let beta1 = HSMCL::decrypt(
        &hsmcl,
        &C_beta
    );

    // // Check
    // let beta1_plus_beta2 = BigInt::mod_add(&beta1, &beta2, &p);
    // let x1r2 = BigInt::mod_mul(&x1, &r2, &p);
    // let x2r1 = BigInt::mod_mul(&x2, &r1, &p);
    // let x1r2_sub_x2r1 = BigInt::mod_sub(&x1r2, &x2r1, &p);
    // assert!(beta1_plus_beta2 == x1r2_sub_x2r1);

    // Compute delta1
    let x1r1 = BigInt::mod_mul(&x1, &r1, &p);
    let delta1 = BigInt::mod_add(&beta1, &x1r1, &p);

    // Compute gamma1
    let gamma1 = HSMCL::decrypt(
        &hsmcl,
        &C_gamma
    );

    // // Check
    // let gamma1_plus_gamma2 = BigInt::mod_add(&gamma1, &gamma2, &p);
    // let y1r2 = BigInt::mod_mul(&y1, &r2, &p);
    // let y2r1 = BigInt::mod_mul(&y2, &r1, &p);
    // let y1r2_sub_y2r1 = BigInt::mod_sub(&y1r2, &y2r1, &p);
    // assert!(gamma1_plus_gamma2 == y1r2_sub_y2r1);

    // Compute delta
    let delta = BigInt::mod_add(&delta1, &delta2, &p);

    // Copmute omega1
    let omega1 = BigInt::mod_add(&gamma1, &y1r1, &p);

    // Copmute alpha1
    let alpha1 = HSMCL::decrypt(
        &hsmcl,
        &C_alpha
    );

    // Copmute s1
    let omega1_square = BigInt::mod_mul(&omega1, &omega1, &p);
    let two_alpha1 = BigInt::mod_add(&alpha1, &alpha1, &p);
    let delta_inv = BigInt::mod_inv(&delta, &p).unwrap();
    let delta_inv_square = BigInt::mod_mul(&delta_inv, &delta_inv, &p);
    let temp = BigInt::mod_add(&omega1_square, &two_alpha1, &p);
    let tempp = BigInt::mod_mul(&temp, &delta_inv_square, &p);
    let temppp = BigInt::mod_sub(&tempp, &a2, &p);
    let s1 = BigInt::mod_sub(&temppp, &x1, &p);

    // // Check omega1 + omega2 = delta * lambda
    // let y2_minus_y1 = BigInt::mod_sub(&y2, &y1, &p);
    // let x2_minus_x1 = BigInt::mod_sub(&x2, &x1, &p);
    // let lambda = BigInt::mod_mul(&y2_minus_y1, &BigInt::mod_inv(&x2_minus_x1, &p), &p);
    // let omega1_plua_omega2 = BigInt::mod_add(&omega1, &omega2, &p);
    // let delta_mul_lambda = BigInt::mod_mul(&delta, &lambda, &p);
    // assert!(omega1_plua_omega2 == delta_mul_lambda);

    // // Check alpha1 + alpha2 = omega1 * omega2
    // let alpha1_plua_alpha2 = BigInt::mod_add(&alpha1, &alpha2, &p);
    // let omega1_mul_omega2 = BigInt::mod_mul(&omega1, &omega2, &p);
    // assert!(alpha1_plua_alpha2 == omega1_mul_omega2);

    // ==================== Step 4 ==================== 
    // Verifier

    // Compute delta
    let delta = BigInt::mod_add(&delta1, &delta2, &p);

    // Copmute s2
    let omega2_square = BigInt::mod_mul(&omega2, &omega2, &p);
    let two_alpha2 = BigInt::mod_add(&alpha2, &alpha2, &p);
    let delta_inv = BigInt::mod_inv(&delta, &p).unwrap();
    let delta_inv_square = BigInt::mod_mul(&delta_inv, &delta_inv, &p);
    let temp = BigInt::mod_add(&omega2_square, &two_alpha2, &p);
    let tempp = BigInt::mod_mul(&temp, &delta_inv_square, &p);
    let s2 = BigInt::mod_sub(&tempp, &x2, &p);

    // Check (step 4)
    let y2_minus_y1 = BigInt::mod_sub(&y2, &y1, &p);
    let x2_minus_x1 = BigInt::mod_sub(&x2, &x1, &p);
    let lambda = BigInt::mod_mul(&y2_minus_y1, &BigInt::mod_inv(&x2_minus_x1, &p).unwrap(), &p);
    let lhs = BigInt::mod_add(&s1, &s2, &p); 
    let lambda_square = BigInt::mod_mul(&lambda, &lambda, &p);
    let lambda_square_sub_a2 = BigInt::mod_sub(&lambda_square, &a2, &p);
    let lambda_square_sub_a2_sub_x1 = BigInt::mod_sub(&lambda_square_sub_a2, &x1, &p);
    let rhs = BigInt::mod_sub(&lambda_square_sub_a2_sub_x1, &x2, &p);
    assert!(lhs == rhs);

    (s1, s2)
}

fn cal_secp256r1_rhs(
    u: BigInt,
    p: BigInt
) -> BigInt {

    // Some constants
    let three = BigInt::from(3);

    // https://www.johndcook.com/blog/2018/08/21/a-tale-of-two-elliptic-curves/
    // let a1 = BigInt::from_str_radix(
    //     "115792089210356248762697446949407573530086143415290314195533631308867097853948",
    //     10
    // ).unwrap();
    let a1 = BigInt::from(-3);

    let a0 = BigInt::from_str_radix(
        "41058363725152142129326129780047268409114441015993725554835256314039467401291",
        10
    ).unwrap();

    // ========== Part 1 ==========
    // Equation of secp256r1.
    // v^2 = u^3 + a_1 u + a_0

    // Calculate the RHS
    let u3_term = BigInt::mod_pow(&u, &three, &p);
    let u1_term = BigInt::mod_mul(&a1, &u, &p);

    let sum_temp = BigInt::mod_add(&u3_term, &u1_term, &p);
    let sum = BigInt::mod_add(&sum_temp, &a0, &p);

    sum
}

pub fn get_secp256r1_v_coordinate(
    u: BigInt,
    p: BigInt
) -> BigInt {

    // 1. Calculate the v^2 using the equation.
    let n = cal_secp256r1_rhs(
        u.clone(),
        p.clone()
    );

    // 2. Run Tonelli-Shanks algorithm for square root modolo p.
    let v = tonelli_shanks(
        n.clone(),
        p.clone()
    );

    v
}

pub fn ectf(
    listener: &TcpListener, 
    p: BigInt, 
    a2: BigInt, 
    x2: BigInt, 
    y2: BigInt
) -> (BigInt, Duration){

    use std::net::TcpStream;
    use std::io::Read;
    use std::io::Write;

    fn get_ciphertext_i(mut stream: &TcpStream) -> RawCiphertext {
        let mut buf = [0; 6144]; // 3072 * 2
        let read_bytes = stream.read(&mut buf).unwrap(); // read g^v
        let cipher = &buf[..read_bytes].to_vec();
        RawCiphertext::from(BigInt::from_bytes(&cipher))
    }

    fn get_ek_n(mut stream: &TcpStream) ->  BigInt {
        let mut buf = [0; 3072]; 
        let read_bytes = stream.read(&mut buf).unwrap(); // read g^v
        let cipher = &buf[..read_bytes].to_vec();
        BigInt::from_bytes(&cipher)
    }

    fn get_delta1(mut stream: &TcpStream) ->  BigInt {
        let mut buf = [0; 256]; 
        let read_bytes = stream.read(&mut buf).unwrap(); // read g^v
        let cipher = &buf[..read_bytes].to_vec();
        BigInt::from_bytes(&cipher)
    }

    fn get_ek_nn(mut stream: &TcpStream) -> BigInt {
        let mut buf = [0; 6144]; 
        let read_bytes = stream.read(&mut buf).unwrap(); // read g^v
        let cipher = &buf[..read_bytes].to_vec();
        BigInt::from_bytes(&cipher)
    }

    //===================  ECTF starts  ======================
    let start_hs = Instant::now();

    let minus_one = BigInt::from(-1);

    // get ek from client
    let stream = listener.incoming().next().unwrap().expect("failed"); 
    let ek_n = get_ek_n(&stream);
    println!("ek_n: {:?}", ek_n);

    let stream = listener.incoming().next().unwrap().expect("failed"); 
    let ek_nn = get_ek_nn(&stream);
    println!("ek_nn: {:?}", ek_nn);

    let ek = EncryptionKey {
        n: ek_n,
        nn: ek_nn,
    };

// ==================== Step 2 ==================== 
    // receive Cx Cy Cr Cry from client
    println!("check point");

    let stream = listener.incoming().next().unwrap().expect("failed"); 
    let Cx = get_ciphertext_i(&stream);
    let stream = listener.incoming().next().unwrap().expect("failed"); 
    let Cy = get_ciphertext_i(&stream);
    let stream = listener.incoming().next().unwrap().expect("failed"); 
    let Cr = get_ciphertext_i(&stream);
    let stream = listener.incoming().next().unwrap().expect("failed"); 
    let Cry = get_ciphertext_i(&stream);

    println!("\nCx: {:?}", &Cx);
    println!("\nCy: {:?}", &Cy);
    println!("\nCr: {:?}", &Cr);
    println!("\nCry: {:?}", &Cry);

    // Verifier
    let r2 = BigInt::sample_below(&p); 
    let beta2 = BigInt::sample_below(&p); 
    let gamma2 = BigInt::sample_below(&p); 
    let alpha2 = BigInt::sample_below(&p); 

    // Compute C_beta
    let Cx_r2 = Paillier::mul(
        &ek,
        RawCiphertext::from(Cx.clone()),
        RawPlaintext::from(&r2)
    );

    let neg_x2 = BigInt::mod_mul(&x2, &minus_one, &p);
    let Cr_neg_x2 = Paillier::mul(
        &ek,
        RawCiphertext::from(Cr.clone()),
        RawPlaintext::from(&neg_x2)
    );

    let neg_beta2 = BigInt::mod_mul(&beta2, &minus_one, &p);
    let enc_neg_beta2 = Paillier::encrypt(
        &ek,
        RawPlaintext::from(&neg_beta2)
    );

    let C_beta_temp = Paillier::add(
        &ek,
        Cx_r2.clone(),
        Cr_neg_x2.clone()
    );

    let C_beta = Paillier::add(
        &ek,
        C_beta_temp.clone(),
        enc_neg_beta2.clone()
    );

    // Compute C_gamma
    let Cy_r2 = Paillier::mul(
        &ek,
        RawCiphertext::from(Cy.clone()),
        RawPlaintext::from(&r2)
    );

    let neg_y2 = BigInt::mod_mul(&y2, &minus_one, &p);
    let Cr_neg_y2 = Paillier::mul(
        &ek,
        RawCiphertext::from(Cr.clone()),
        RawPlaintext::from(&neg_y2)
    );

    let neg_gamma2 = BigInt::mod_mul(&gamma2, &minus_one, &p);
    let enc_neg_gamma2 = Paillier::encrypt(
        &ek,
        RawPlaintext::from(&neg_gamma2)
    );

    let C_gamma_temp = Paillier::add(
        &ek,
        Cy_r2.clone(),
        Cr_neg_y2.clone()
    );

    let C_gamma = Paillier::add(
        &ek,
        C_gamma_temp.clone(),
        enc_neg_gamma2.clone()
    );

    // Compute delta2
    let x2r2 = BigInt::mod_mul(&x2, &r2, &p);
    let delta2 = BigInt::mod_sub(&beta2, &x2r2, &p);

    // Compute omega2
    let y2r2 = BigInt::mod_mul(&y2, &r2, &p);
    let omega2 = BigInt::mod_sub(&gamma2, &y2r2, &p);

    // Compute C_alpha
    let C_gamma_C_ry = Paillier::add(
        &ek,
        C_gamma.clone(),
        Cry.clone()
    );

    let C_gamma_C_ry_omega2 = Paillier::mul(
        &ek,
        RawCiphertext::from(C_gamma_C_ry.clone()),
        RawPlaintext::from(&omega2)
    );

    let neg_alpha2 = BigInt::mod_mul(&alpha2, &minus_one, &p);
    let enc_neg_alpha2 = Paillier::encrypt(
        &ek,
        RawPlaintext::from(&neg_alpha2)
    );

    let C_alpha = Paillier::add(
        &ek,
        RawCiphertext::from(C_gamma_C_ry_omega2.clone()),
        RawCiphertext::from(enc_neg_alpha2.clone())
    );

    // send C_beta, C_gamma, C_alpha, delta2 to verifier
    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    stream.write(&C_beta.0.to_bytes()).unwrap();

    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    stream.write(&C_gamma.0.to_bytes()).unwrap();

    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    stream.write(&C_alpha.0.to_bytes()).unwrap();

    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    stream.write(&delta2.to_bytes()).unwrap();

    println!("\ngenerate C_beta: {:?}", &C_beta);
    println!("\ngenerate C_gamma: {:?}", &C_gamma);
    println!("\ngenerate C_alpha: {:?}", &C_alpha);
    println!("\ngenerate delta2: {:?}", &delta2);

    // ==================== Step 4 ==================== 
    // Verifier
    let stream = listener.incoming().next().unwrap().expect("failed"); 
    let delta1 = get_delta1(&stream);
    println!("\nreceive delta1: {:?}", &delta1);



    // Compute delta
    let delta = BigInt::mod_add(&delta1, &delta2, &p);

    // Copmute s2
    let omega2_square = BigInt::mod_mul(&omega2, &omega2, &p);
    let two_alpha2 = BigInt::mod_add(&alpha2, &alpha2, &p);
    let delta_inv = BigInt::mod_inv(&delta, &p).unwrap();
    let delta_inv_square = BigInt::mod_mul(&delta_inv, &delta_inv, &p);
    let temp = BigInt::mod_add(&omega2_square, &two_alpha2, &p);
    let tempp = BigInt::mod_mul(&temp, &delta_inv_square, &p);
    let s2 = BigInt::mod_sub(&tempp, &x2, &p);

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&s2.to_bytes()).unwrap();

    let duration_hs = start_hs.elapsed();

    println!("check point 2 => client side");

    (s2, duration_hs)
}