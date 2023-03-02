use ring::hmac;

fn concat_sign(key: &hmac::Key, a: &[u8], b: &[u8]) -> hmac::Tag {
    let mut ctx = hmac::Context::with_key(key);
    ctx.update(a);
    ctx.update(b);
    ctx.sign()
}

fn p(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], seed: &[u8]) {
    println!("alg: {:?}", alg);
    let hmac_key = hmac::Key::new(alg, secret);
    println!("after test");
    // A(1)
    let mut current_a = hmac::sign(&hmac_key, seed);
    let chunk_size = alg.digest_algorithm().output_len;
    println!("chunk_size: {:?}", chunk_size);
    for chunk in out.chunks_mut(chunk_size) {
        // P_hash[i] = HMAC_hash(secret, A(i) + seed)
        let p_term = concat_sign(&hmac_key, current_a.as_ref(), seed);
        chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

        // A(i+1) = HMAC_hash(secret, A(i))
        current_a = hmac::sign(&hmac_key, current_a.as_ref());
    }
}

// [DECO] TLS 1.2 2PC-HMAC
fn p_deco_extended_master_secret_curve25519(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], seed: &[u8], s1_str: String) {
    
    use curv::BigInt;
    use curv::arithmetic::Converter;

    let (my_ip_port, target_ip, target_ip_port) = crate::get_ip();
    println!("alg: {:?}", alg);
    // let hmac_key = hmac::Key::new(alg, secret);

    // The Key of extended master secret
    let key_ipad_filename = String::from("tls12_ems_s1s2sum_ipad.txt");
    let key_opad_filename = String::from("tls12_ems_s1s2sum_opad.txt");
    // let hmac_key = 
    hmac::Key::deco_tls12_extended_master_secret_key_curve25519(
        alg, 
        s1_str, 
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone()
    );
    println!("after hmac::Key::new");
    
    // The recursive 2PC-HMAC
    let a1_filename = String::from("tls12_ems_A1.txt");
    let a2_filename = String::from("tls12_ems_A2.txt");
    let a3_filename = String::from("tls12_ems_A3.txt");
    let phash1_1_filename = String::from("tls12_ems_Phash1_1.txt");
    let phash1_2_filename = String::from("tls12_ems_Phash1_2.txt");
    let phash2_1_filename = String::from("tls12_ems_Phash2_1.txt");
    let phash2_2_filename = String::from("tls12_ems_Phash2_2.txt");

    let output: [u8; 48] = hmac::Key::deco_tls12_ems_recursive_hmac(
        alg, 
        seed,
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone(),
        a1_filename.clone(),
        a2_filename.clone(),
        a3_filename.clone(),
        phash1_1_filename.clone(),
        phash1_2_filename.clone(),
        phash2_1_filename.clone(),
        phash2_2_filename.clone()
    );

    for i in 0..out.len() { 
        out[i] = output[i];
    }

    // // A(1)
    // println!("seed: {:?}", seed);
    // println!("seed len: {:?}", seed.len());
    // let mut current_a = hmac::sign(&hmac_key, seed);
    // println!("after hmac::sign");

    // let chunk_size = alg.digest_algorithm().output_len;
    // println!("Iteration: {:?}", out.chunks_mut(chunk_size));
    
    // let mut i = 0;

    // for chunk in out.chunks_mut(chunk_size) {

    //     // Iterate for 2 times, for 32 + 16 bytes message
    //     i += 1;
    //     println!("chunk: {:?}", chunk);

    //     println!("chunk interation in prf.rs");

    //     // P_hash[i] = HMAC_hash(secret, A(i) + seed)
    //     println!("P_hash[{:?}]", i);
    //     let p_term = concat_sign(&hmac_key, current_a.as_ref(), seed);
    //     chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

    //     // A(i+1) = HMAC_hash(secret, A(i))
    //     println!("A({:?})", i+1);
    //     println!("current_a.as_ref(): {:?}", current_a.as_ref());
    //     println!("current_a.as_ref() len: {:?}", current_a.as_ref().len());
    //     current_a = hmac::sign(&hmac_key, current_a.as_ref());
    //     println!("current_a.as_ref(): {:?}", current_a.as_ref());
    //     println!("current_a.as_ref() len: {:?}", current_a.as_ref().len());
    // }

    println!("out: {:?}", out);
    println!("out.len(): {:?}", out.len());
    // println!("total iterations: {:?}", i);
    // println!("chunk_size: {:?}", chunk_size);
}

// [DECO] TLS 1.2 2PC-HMAC
fn p_deco_extended_master_secret_secp256r1(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], seed: &[u8], s1_str: String) {
    
    use curv::BigInt;
    use curv::arithmetic::Converter;

    let (my_ip_port, target_ip, target_ip_port) = crate::get_ip();
    println!("alg: {:?}", alg);
    // let hmac_key = hmac::Key::new(alg, secret);

    // The Key of extended master secret
    let key_ipad_filename = String::from("tls12_ems_s1s2sum_ipad.txt");
    let key_opad_filename = String::from("tls12_ems_s1s2sum_opad.txt");
    // let hmac_key = 
    hmac::Key::deco_tls12_extended_master_secret_key_secp256r1(
        alg, 
        s1_str, 
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone()
    );
    println!("after hmac::Key::new");
    
    // The recursive 2PC-HMAC
    let a1_filename = String::from("tls12_ems_A1.txt");
    let a2_filename = String::from("tls12_ems_A2.txt");
    let a3_filename = String::from("tls12_ems_A3.txt");
    let phash1_1_filename = String::from("tls12_ems_Phash1_1.txt");
    let phash1_2_filename = String::from("tls12_ems_Phash1_2.txt");
    let phash2_1_filename = String::from("tls12_ems_Phash2_1.txt");
    let phash2_2_filename = String::from("tls12_ems_Phash2_2.txt");

    let output: [u8; 48] = hmac::Key::deco_tls12_ems_recursive_hmac(
        alg, 
        seed,
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone(),
        a1_filename.clone(),
        a2_filename.clone(),
        a3_filename.clone(),
        phash1_1_filename.clone(),
        phash1_2_filename.clone(),
        phash2_1_filename.clone(),
        phash2_2_filename.clone()
    );

    for i in 0..out.len() { 
        out[i] = output[i];
    }

    // // A(1)
    // println!("seed: {:?}", seed);
    // println!("seed len: {:?}", seed.len());
    // let mut current_a = hmac::sign(&hmac_key, seed);
    // println!("after hmac::sign");

    // let chunk_size = alg.digest_algorithm().output_len;
    // println!("Iteration: {:?}", out.chunks_mut(chunk_size));
    
    // let mut i = 0;

    // for chunk in out.chunks_mut(chunk_size) {

    //     // Iterate for 2 times, for 32 + 16 bytes message
    //     i += 1;
    //     println!("chunk: {:?}", chunk);

    //     println!("chunk interation in prf.rs");

    //     // P_hash[i] = HMAC_hash(secret, A(i) + seed)
    //     println!("P_hash[{:?}]", i);
    //     let p_term = concat_sign(&hmac_key, current_a.as_ref(), seed);
    //     chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

    //     // A(i+1) = HMAC_hash(secret, A(i))
    //     println!("A({:?})", i+1);
    //     println!("current_a.as_ref(): {:?}", current_a.as_ref());
    //     println!("current_a.as_ref() len: {:?}", current_a.as_ref().len());
    //     current_a = hmac::sign(&hmac_key, current_a.as_ref());
    //     println!("current_a.as_ref(): {:?}", current_a.as_ref());
    //     println!("current_a.as_ref() len: {:?}", current_a.as_ref().len());
    // }

    println!("out: {:?}", out);
    println!("out.len(): {:?}", out.len());
    // println!("total iterations: {:?}", i);
    // println!("chunk_size: {:?}", chunk_size);
}

// [DECO] TLS 1.2 2PC-HMAC
fn p_deco_master_secret_curve25519(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], seed: &[u8], s1_str: String) {
    
    use curv::BigInt;
    use curv::arithmetic::Converter;

    let (my_ip_port, target_ip, target_ip_port) = crate::get_ip();
    println!("alg: {:?}", alg);
    // let hmac_key = hmac::Key::new(alg, secret);

    // The Key of extended master secret
    let key_ipad_filename = String::from("tls12_ems_s1s2sum_ipad.txt");
    let key_opad_filename = String::from("tls12_ems_s1s2sum_opad.txt");
    // let hmac_key = 
    hmac::Key::deco_tls12_extended_master_secret_key_curve25519(
        alg, 
        s1_str, 
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone()
    );
    println!("after hmac::Key::new");
    
    // The recursive 2PC-HMAC
    let a1_1_filename = String::from("tls12_ems_A1_1.txt");
    let a1_2_filename = String::from("tls12_ems_A1_2.txt");
    let a2_filename = String::from("tls12_ems_A2.txt");
    let a3_filename = String::from("tls12_ems_A3.txt");
    let phash1_1_filename = String::from("tls12_ems_Phash1_1.txt");
    let phash1_2_filename = String::from("tls12_ems_Phash1_2.txt");
    let phash2_1_filename = String::from("tls12_ems_Phash2_1.txt");
    let phash2_2_filename = String::from("tls12_ems_Phash2_2.txt");

    let output: [u8; 48] = hmac::Key::deco_tls12_ms_recursive_hmac(
        alg, 
        seed,
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone(),
        a1_1_filename.clone(),
        a1_2_filename.clone(),
        a2_filename.clone(),
        a3_filename.clone(),
        phash1_1_filename.clone(),
        phash1_2_filename.clone(),
        phash2_1_filename.clone(),
        phash2_2_filename.clone()
    );

    for i in 0..out.len() { 
        out[i] = output[i];
    }

    // // A(1)
    // println!("seed: {:?}", seed);
    // println!("seed len: {:?}", seed.len());
    // let mut current_a = hmac::sign(&hmac_key, seed);
    // println!("after hmac::sign");

    // let chunk_size = alg.digest_algorithm().output_len;
    // println!("Iteration: {:?}", out.chunks_mut(chunk_size));
    
    // let mut i = 0;

    // for chunk in out.chunks_mut(chunk_size) {

    //     // Iterate for 2 times, for 32 + 16 bytes message
    //     i += 1;
    //     println!("chunk: {:?}", chunk);

    //     println!("chunk interation in prf.rs");

    //     // P_hash[i] = HMAC_hash(secret, A(i) + seed)
    //     println!("P_hash[{:?}]", i);
    //     let p_term = concat_sign(&hmac_key, current_a.as_ref(), seed);
    //     chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

    //     // A(i+1) = HMAC_hash(secret, A(i))
    //     println!("A({:?})", i+1);
    //     println!("current_a.as_ref(): {:?}", current_a.as_ref());
    //     println!("current_a.as_ref() len: {:?}", current_a.as_ref().len());
    //     current_a = hmac::sign(&hmac_key, current_a.as_ref());
    //     println!("current_a.as_ref(): {:?}", current_a.as_ref());
    //     println!("current_a.as_ref() len: {:?}", current_a.as_ref().len());
    // }

    println!("out: {:?}", out);
    println!("out.len(): {:?}", out.len());
    // println!("total iterations: {:?}", i);
    // println!("chunk_size: {:?}", chunk_size);
}

// [DECO] TLS 1.2 2PC-HMAC
fn p_deco_master_secret_secp256r1(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], seed: &[u8], s1_str: String) {
    
    use curv::BigInt;
    use curv::arithmetic::Converter;

    let (my_ip_port, target_ip, target_ip_port) = crate::get_ip();
    println!("alg: {:?}", alg);
    // let hmac_key = hmac::Key::new(alg, secret);

    // The Key of extended master secret
    let key_ipad_filename = String::from("tls12_ems_s1s2sum_ipad.txt");
    let key_opad_filename = String::from("tls12_ems_s1s2sum_opad.txt");
    // let hmac_key = 
    hmac::Key::deco_tls12_extended_master_secret_key_secp256r1(
        alg, 
        s1_str, 
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone()
    );
    println!("after hmac::Key::new");
    
    // The recursive 2PC-HMAC
    let a1_1_filename = String::from("tls12_ems_A1_1.txt");
    let a1_2_filename = String::from("tls12_ems_A1_2.txt");
    let a2_filename = String::from("tls12_ems_A2.txt");
    let a3_filename = String::from("tls12_ems_A3.txt");
    let phash1_1_filename = String::from("tls12_ems_Phash1_1.txt");
    let phash1_2_filename = String::from("tls12_ems_Phash1_2.txt");
    let phash2_1_filename = String::from("tls12_ems_Phash2_1.txt");
    let phash2_2_filename = String::from("tls12_ems_Phash2_2.txt");

    let output: [u8; 48] = hmac::Key::deco_tls12_ms_recursive_hmac(
        alg, 
        seed,
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone(),
        a1_1_filename.clone(),
        a1_2_filename.clone(),
        a2_filename.clone(),
        a3_filename.clone(),
        phash1_1_filename.clone(),
        phash1_2_filename.clone(),
        phash2_1_filename.clone(),
        phash2_2_filename.clone()
    );

    for i in 0..out.len() { 
        out[i] = output[i];
    }

    // // A(1)
    // println!("seed: {:?}", seed);
    // println!("seed len: {:?}", seed.len());
    // let mut current_a = hmac::sign(&hmac_key, seed);
    // println!("after hmac::sign");

    // let chunk_size = alg.digest_algorithm().output_len;
    // println!("Iteration: {:?}", out.chunks_mut(chunk_size));
    
    // let mut i = 0;

    // for chunk in out.chunks_mut(chunk_size) {

    //     // Iterate for 2 times, for 32 + 16 bytes message
    //     i += 1;
    //     println!("chunk: {:?}", chunk);

    //     println!("chunk interation in prf.rs");

    //     // P_hash[i] = HMAC_hash(secret, A(i) + seed)
    //     println!("P_hash[{:?}]", i);
    //     let p_term = concat_sign(&hmac_key, current_a.as_ref(), seed);
    //     chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

    //     // A(i+1) = HMAC_hash(secret, A(i))
    //     println!("A({:?})", i+1);
    //     println!("current_a.as_ref(): {:?}", current_a.as_ref());
    //     println!("current_a.as_ref() len: {:?}", current_a.as_ref().len());
    //     current_a = hmac::sign(&hmac_key, current_a.as_ref());
    //     println!("current_a.as_ref(): {:?}", current_a.as_ref());
    //     println!("current_a.as_ref() len: {:?}", current_a.as_ref().len());
    // }

    println!("out: {:?}", out);
    println!("out.len(): {:?}", out.len());
    // println!("total iterations: {:?}", i);
    // println!("chunk_size: {:?}", chunk_size);
}

// [DECO] TLS 1.2 2PC-HMAC
fn p_deco_key_expansion(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], seed: &[u8]) {

    let (my_ip_port, target_ip, target_ip_port) = crate::get_ip();
    println!("alg: {:?}", alg);
    // let hmac_key = hmac::Key::new(alg, secret);

    // The Key of extended master secret
    let ems_phash1_2_filename = String::from("tls12_ems_Phash1_2.txt");
    let ems_phash2_2_filename = String::from("tls12_ems_Phash2_2.txt");
    let key_ipad_filename = String::from("tls12_ke_key_ipad.txt");
    let key_opad_filename = String::from("tls12_ke_key_opad.txt");
    // let input = BigInt::from_bytes(&secret).to_hex().to_string();
    let hmac_key = 
    hmac::Key::deco_tls12_key_expansion_key(
        alg, 
        ems_phash1_2_filename.clone(), 
        ems_phash2_2_filename.clone(),
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone()
    );
    println!("after hmac::Key::new");
    
    // The recursive 2PC-HMAC
    let a1_1_filename = String::from("tls12_ke_A1_1.txt");
    let a1_2_filename = String::from("tls12_ke_A1_2.txt");
    let a2_filename = String::from("tls12_ke_A2.txt");
    let a3_filename = String::from("tls12_ke_A3.txt");
    let phash1_1_filename = String::from("tls12_ke_Phash1_1.txt");
    let phash1_2_filename = String::from("tls12_ke_Phash1_2.txt");
    let phash2_1_filename = String::from("tls12_ke_Phash2_1.txt");
    let phash2_2_filename = String::from("tls12_ke_Phash2_2.txt");

    let output: [u8; 48] = 
    hmac::Key::deco_tls12_ke_recursive_hmac(
        alg, 
        seed,
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone(),
        a1_1_filename.clone(),
        a1_2_filename.clone(),
        a2_filename.clone(),
        a3_filename.clone(),
        phash1_1_filename.clone(),
        phash1_2_filename.clone(),
        phash2_1_filename.clone(),
        phash2_2_filename.clone()
    );
    
    for i in 0..48 { 
        out[i] = output[i];
    }

    // // A(1)
    // println!("seed: {:?}", seed);
    // println!("seed len: {:?}", seed.len());
    // let mut current_a = hmac::sign(&hmac_key, seed);
    // println!("after hmac::sign");

    // let chunk_size = alg.digest_algorithm().output_len;
    // println!("Iteration: {:?}", out.chunks_mut(chunk_size));
    
    // let mut i = 0;

    // for chunk in out.chunks_mut(chunk_size) {

    //     // Iterate for 2 times, for 32 + 16 bytes message
    //     i += 1;
    //     println!("chunk: {:?}", chunk);

    //     println!("chunk interation in prf.rs");

    //     // P_hash[i] = HMAC_hash(secret, A(i) + seed)
    //     println!("P_hash[{:?}]", i);
    //     let p_term = concat_sign(&hmac_key, current_a.as_ref(), seed);
    //     chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

    //     // A(i+1) = HMAC_hash(secret, A(i))
    //     println!("A({:?})", i+1);
    //     println!("current_a.as_ref(): {:?}", current_a.as_ref());
    //     println!("current_a.as_ref() len: {:?}", current_a.as_ref().len());
    //     current_a = hmac::sign(&hmac_key, current_a.as_ref());
    //     println!("current_a.as_ref(): {:?}", current_a.as_ref());
    //     println!("current_a.as_ref() len: {:?}", current_a.as_ref().len());
    // }

    println!("out: {:?}", out);
    println!("out.len(): {:?}", out.len());
    // println!("total iterations: {:?}", i);
    // println!("chunk_size: {:?}", chunk_size);
}

fn p_deco_client_finish(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], seed: &[u8]) {
    println!("alg: {:?}", alg);
    // let hmac_key = hmac::Key::new(alg, secret);

    let (my_ip_port, target_ip, target_ip_port) = crate::get_ip();
    // The Key of extended master secret
    let ems_phash1_2_filename = String::from("tls12_ems_Phash1_2.txt");
    let ems_phash2_2_filename = String::from("tls12_ems_Phash2_2.txt");
    let key_ipad_filename = String::from("tls12_cf_key_ipad.txt");
    let key_opad_filename = String::from("tls12_cf_key_opad.txt");
    // let input = BigInt::from_bytes(&secret).to_hex().to_string();
    // let hmac_key = 
    hmac::Key::deco_tls12_key_expansion_key(
        alg, 
        ems_phash1_2_filename.clone(), 
        ems_phash2_2_filename.clone(),
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone()
    );
    println!("after hmac::Key::new");
    println!("after test");

    // The recursive 2PC-HMAC
    let a1_filename = String::from("tls12_cf_A1.txt");
    let a2_filename = String::from("tls12_cf_A2.txt");
    let phash1_1_filename = String::from("tls12_cf_Phash1_1.txt");
    let phash1_2_filename = String::from("tls12_cf_Phash1_2.txt");

    let output: [u8; 12] = 
    hmac::Key::deco_tls12_cf_sf_recursive_hmac(
        alg, 
        seed,
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone(),
        a1_filename.clone(),
        a2_filename.clone(),
        phash1_1_filename.clone(),
        phash1_2_filename.clone(),
    );

    for i in 0..12 { 
        out[i] = output[i];
    }
    println!("output: {:?}", output);

    // // A(1)
    // let mut current_a = hmac::sign(&hmac_key, seed);
    // let chunk_size = alg.digest_algorithm().output_len;
    // println!("chunk_size: {:?}", chunk_size);
    // for chunk in out.chunks_mut(chunk_size) {
    //     // P_hash[i] = HMAC_hash(secret, A(i) + seed)
    //     let p_term = concat_sign(&hmac_key, current_a.as_ref(), seed);
    //     chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

    //     // A(i+1) = HMAC_hash(secret, A(i))
    //     current_a = hmac::sign(&hmac_key, current_a.as_ref());
    // }

    println!("out: {:?}", out);
    println!("out.len(): {:?}", out.len());
    println!("[DONE] p_deco_client_finish");
}

fn p_deco_server_finish(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], seed: &[u8]) {
    println!("alg: {:?}", alg);
    // let hmac_key = hmac::Key::new(alg, secret);

    let (my_ip_port, target_ip, target_ip_port) = crate::get_ip();
    // The Key of extended master secret
    let ems_phash1_2_filename = String::from("tls12_ems_Phash1_2.txt");
    let ems_phash2_2_filename = String::from("tls12_ems_Phash2_2.txt");
    let key_ipad_filename = String::from("tls12_sf_key_ipad.txt");
    let key_opad_filename = String::from("tls12_sf_key_opad.txt");
    // let input = BigInt::from_bytes(&secret).to_hex().to_string();
    // let hmac_key = 
    hmac::Key::deco_tls12_key_expansion_key(
        alg, 
        ems_phash1_2_filename.clone(), 
        ems_phash2_2_filename.clone(),
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone()
    );
    println!("after hmac::Key::new");
    println!("after test");

    // The recursive 2PC-HMAC
    let a1_filename = String::from("tls12_sf_A1.txt");
    let a2_filename = String::from("tls12_sf_A2.txt");
    let phash1_1_filename = String::from("tls12_sf_Phash1_1.txt");
    let phash1_2_filename = String::from("tls12_sf_Phash1_2.txt");

    let output: [u8; 12] = 
    hmac::Key::deco_tls12_cf_sf_recursive_hmac(
        alg, 
        seed,
        &target_ip_port.as_str(), 
        &target_ip.as_str(),
        key_ipad_filename.clone(),
        key_opad_filename.clone(),
        a1_filename.clone(),
        a2_filename.clone(),
        phash1_1_filename.clone(),
        phash1_2_filename.clone(),
    );

    for i in 0..12 { 
        out[i] = output[i];
    }
    println!("output: {:?}", output);

    // // A(1)
    // let mut current_a = hmac::sign(&hmac_key, seed);
    // let chunk_size = alg.digest_algorithm().output_len;
    // println!("chunk_size: {:?}", chunk_size);
    // for chunk in out.chunks_mut(chunk_size) {
    //     // P_hash[i] = HMAC_hash(secret, A(i) + seed)
    //     let p_term = concat_sign(&hmac_key, current_a.as_ref(), seed);
    //     chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

    //     // A(i+1) = HMAC_hash(secret, A(i))
    //     current_a = hmac::sign(&hmac_key, current_a.as_ref());
    // }

    println!("out: {:?}", out);
    println!("out.len(): {:?}", out.len());
    println!("[DONE] p_deco_server_finish");
}

fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    println!("test concat");
    let mut ret = Vec::new();
    ret.extend_from_slice(a);
    ret.extend_from_slice(b);
    ret
}

pub(crate) fn prf(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], label: &[u8], seed: &[u8]) {
    let joined_seed = concat(label, seed);
    p(out, alg, secret, &joined_seed);
}

// [DECO] TLS 1.2 2PC-HMAC
pub(crate) fn prf_deco_extended_master_secret_curve25519(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], label: &[u8], seed: &[u8], s1_str: String) {
    let joined_seed = concat(label, seed);
    p_deco_extended_master_secret_curve25519(out, alg, secret, &joined_seed, s1_str);
}

// [DECO] TLS 1.2 2PC-HMAC
pub(crate) fn prf_deco_extended_master_secret_secp256r1(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], label: &[u8], seed: &[u8], s1_str: String) {
    let joined_seed = concat(label, seed);
    p_deco_extended_master_secret_secp256r1(out, alg, secret, &joined_seed, s1_str);
}

// [DECO] TLS 1.2 2PC-HMAC
pub(crate) fn prf_deco_master_secret_curve25519(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], label: &[u8], seed: &[u8], s1_str: String) {
    let joined_seed = concat(label, seed);
    p_deco_master_secret_curve25519(out, alg, secret, &joined_seed, s1_str);
}

// [DECO] TLS 1.2 2PC-HMAC
pub(crate) fn prf_deco_master_secret_secp256r1(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], label: &[u8], seed: &[u8], s1_str: String) {
    let joined_seed = concat(label, seed);
    p_deco_master_secret_secp256r1(out, alg, secret, &joined_seed, s1_str);
}

// [DECO] TLS 1.2 2PC-HMAC
pub(crate) fn prf_deco_key_expansion(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], label: &[u8], seed: &[u8]) {
    let joined_seed = concat(label, seed);
    p_deco_key_expansion(out, alg, secret, &joined_seed);
}

// [DECO] TLS 1.2 2PC-HMAC
pub(crate) fn prf_deco_client_finish(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], label: &[u8], seed: &[u8]) {
    let joined_seed = concat(label, seed);
    p_deco_client_finish(out, alg, secret, &joined_seed);
}

// [DECO] TLS 1.2 2PC-HMAC
pub(crate) fn prf_deco_server_finish(out: &mut [u8], alg: hmac::Algorithm, secret: &[u8], label: &[u8], seed: &[u8]) {
    let joined_seed = concat(label, seed);
    p_deco_server_finish(out, alg, secret, &joined_seed);
}

#[cfg(test)]
mod tests {
    use ring::hmac::{HMAC_SHA256, HMAC_SHA512};

    #[test]
    fn check_sha256() {
        let secret = b"\x9b\xbe\x43\x6b\xa9\x40\xf0\x17\xb1\x76\x52\x84\x9a\x71\xdb\x35";
        let seed = b"\xa0\xba\x9f\x93\x6c\xda\x31\x18\x27\xa6\xf7\x96\xff\xd5\x19\x8c";
        let label = b"test label";
        let expect = include_bytes!("../testdata/prf-result.1.bin");
        let mut output = [0u8; 100];

        super::prf(&mut output, HMAC_SHA256, secret, label, seed);
        assert_eq!(expect.len(), output.len());
        assert_eq!(expect.to_vec(), output.to_vec());
    }

    #[test]
    fn check_sha512() {
        let secret = b"\xb0\x32\x35\x23\xc1\x85\x35\x99\x58\x4d\x88\x56\x8b\xbb\x05\xeb";
        let seed = b"\xd4\x64\x0e\x12\xe4\xbc\xdb\xfb\x43\x7f\x03\xe6\xae\x41\x8e\xe5";
        let label = b"test label";
        let expect = include_bytes!("../testdata/prf-result.2.bin");
        let mut output = [0u8; 196];

        super::prf(&mut output, HMAC_SHA512, secret, label, seed);
        assert_eq!(expect.len(), output.len());
        assert_eq!(expect.to_vec(), output.to_vec());
    }
}
