use std::process;
use std::sync::{Arc, Mutex};

use mio;
use mio::net::TcpStream;
use ring::aead;

use std::collections;
use std::convert::TryInto;
use std::fs::{self, File};
use std::io;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, Shutdown};
use std::str;
use std::env;

use std::net::TcpListener;
use std::net::TcpStream as TcpStreamNet;
use std::thread;
use std::time;
use rustls::internal::msgs::base::Payload;

use serde::{Serialize, Deserialize};
use serde_json;

use env_logger;

#[macro_use]
extern crate serde_derive;

use docopt::Docopt;

use rustls::{self, Tls12CipherSuite};
use webpki_roots;
use rustls::internal::msgs::message::{Message, PlainMessage, OpaqueMessage};
use rustls::internal::msgs::enums::{AlertDescription, AlertLevel, ContentType, ProtocolVersion};
use rustls::{OwnedTrustAnchor, RootCertStore};
use rustls::record_layer::RecordLayer;

const CLIENT: mio::Token = mio::Token(0);
use std::time::{Duration, Instant};

const emp_path: &str = "./rustls/src/emp/emp-sh2pc/2pc_hmac/";

// pub const CLIENT_IP: &str = "127.0.0.1";
// pub const CLIENT_IP_WITH_PORT: &str = "127.0.0.1:8080";
// pub const CLIENT_IP_WITH_PORT_2: &str = "127.0.0.1:8081";

// // The IP with port number of verifier for "client -> verifier" communication.
// pub const MY_IP_ADDRESS_WITH_PORT: &str = "223.16.150.138:8080";
// // The IP of client for emp (default port: 12345)
// pub const TARGET_IP_ADDRESS: &str = "223.16.150.138";
// // The IP with port number of client for "verifier -> client" communication.
// pub const TARGET_IP_ADDRESS_WITH_PORT: &str = "223.16.150.138:8081";

// // The IP with port number of verifier for "client -> verifier" communication.
// pub const MY_IP_ADDRESS_WITH_PORT: &str = "127.0.0.1:8080";
// // The IP of client for emp (default port: 12345)
// pub const TARGET_IP_ADDRESS: &str = "127.0.0.1";
// // The IP with port number of client for "verifier -> client" communication.
// pub const TARGET_IP_ADDRESS_WITH_PORT: &str = "127.0.0.1:8081";

// // The IP with port number of verifier for "client -> verifier" communication.
// pub const MY_IP_ADDRESS_WITH_PORT: &str = "192.168.0.103:8080";
// // The IP of client for emp (default port: 12345)
// pub const TARGET_IP_ADDRESS: &str = "192.168.0.113";
// // The IP with port number of client for "verifier -> client" communication.
// pub const TARGET_IP_ADDRESS_WITH_PORT: &str = "192.168.0.113:8081";

/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
struct TlsClient {
    socket: TcpStream,
    closing: bool,
    clean_closure: bool,
    tls_conn: rustls::ClientConnection,
}

impl TlsClient {
    fn new(
        sock: TcpStream,
        server_name: rustls::ServerName,
        cfg: Arc<rustls::ClientConfig>,
    ) -> TlsClient {
        TlsClient {
            socket: sock,
            closing: false,
            clean_closure: false,
            tls_conn: rustls::ClientConnection::new(cfg, server_name).unwrap(),
        }
    }

    /// Handles events sent to the TlsClient by mio::Poll
    fn ready(&mut self, ev: &mio::event::Event) {
        assert_eq!(ev.token(), CLIENT);

        if ev.is_readable() {
            self.do_read();
        }

        if ev.is_writable() {
            self.do_write();
        }

        if self.is_closed() {
            println!("Connection closed");
            process::exit(if self.clean_closure { 0 } else { 1 });
        }
    }

    fn read_source_to_end(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        let mut buf = Vec::new();
        let len = rd.read_to_end(&mut buf)?;
        self.tls_conn
            .writer()
            .write_all(&buf)
            .unwrap();
        Ok(len)
    }

    /// We're ready to do a read.
    fn do_read(&mut self) {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        match self.tls_conn.read_tls(&mut self.socket) {
            Err(error) => {
                if error.kind() == io::ErrorKind::WouldBlock {
                    return;
                }
                println!("TLS read error: {:?}", error);
                self.closing = true;
                return;
            }

            // If we're ready but there's no data: EOF.
            Ok(0) => {
                println!("EOF");
                self.closing = true;
                self.clean_closure = true;
                return;
            }

            Ok(_) => {}
        };

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let io_state = match self.tls_conn.process_new_packets() {
            Ok(io_state) => io_state,
            Err(err) => {
                println!("TLS error: {:?}", err);
                self.closing = true;
                return;
            }
        };

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        if io_state.plaintext_bytes_to_read() > 0 {
            let mut plaintext = Vec::new();
            plaintext.resize(io_state.plaintext_bytes_to_read(), 0u8);
            self.tls_conn
                .reader()
                .read(&mut plaintext)
                .unwrap();
            io::stdout()
                .write_all(&plaintext)
                .unwrap();
        }

        // If wethat fails, the peer might have started a clean TLS-level
        // session closure.
        if io_state.peer_has_closed() {
            self.clean_closure = true;
            self.closing = true;
            return;
        }
    }

    fn do_write(&mut self) {
        self.tls_conn
            .write_tls(&mut self.socket)
            .unwrap();
    }

    /// Registers self as a 'listener' in mio::Registry
    fn register(&mut self, registry: &mio::Registry) {
        let interest = self.event_set();
        registry
            .register(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Reregisters self as a 'listener' in mio::Registry.
    fn reregister(&mut self, registry: &mio::Registry) {
        let interest = self.event_set();
        registry
            .reregister(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Use wants_read/wants_write to register for different mio-level
    /// IO readiness events.
    fn event_set(&self) -> mio::Interest {
        let rd = self.tls_conn.wants_read();
        let wr = self.tls_conn.wants_write();

        if rd && wr {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if wr {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closing
    }
}
impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_conn.writer().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_conn.writer().flush()
    }
}

impl io::Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_conn.reader().read(bytes)
    }
}

/// This is an example cache for client session data.
/// It optionally dumps cached data to a file, but otherwise
/// is just in-memory.
///
/// Note that the contents of such a file are extremely sensitive.
/// Don't write this stuff to disk in production code.
struct PersistCache {
    cache: Mutex<collections::HashMap<Vec<u8>, Vec<u8>>>,
    filename: Option<String>,
}

impl PersistCache {
    /// Make a new cache.  If filename is Some, load the cache
    /// from it and flush changes back to that file.
    fn new(filename: &Option<String>) -> Self {
        let cache = PersistCache {
            cache: Mutex::new(collections::HashMap::new()),
            filename: filename.clone(),
        };
        if cache.filename.is_some() {
            cache.load();
        }
        cache
    }

    /// If we have a filename, save the cache contents to it.
    fn save(&self) {
        use rustls::internal::msgs::base::PayloadU16;
        use rustls::internal::msgs::codec::Codec;

        if self.filename.is_none() {
            return;
        }

        let mut file =
            fs::File::create(self.filename.as_ref().unwrap()).expect("cannot open cache file");

        for (key, val) in self.cache.lock().unwrap().iter() {
            let mut item = Vec::new();
            let key_pl = PayloadU16::new(key.clone());
            let val_pl = PayloadU16::new(val.clone());
            key_pl.encode(&mut item);
            val_pl.encode(&mut item);
            file.write_all(&item).unwrap();
        }
    }

    /// We have a filename, so replace the cache contents from it.
    fn load(&self) {
        use rustls::internal::msgs::base::PayloadU16;
        use rustls::internal::msgs::codec::{Codec, Reader};

        let mut file = match fs::File::open(self.filename.as_ref().unwrap()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let mut cache = self.cache.lock().unwrap();
        cache.clear();
        let mut rd = Reader::init(&data);

        while rd.any_left() {
            let key_pl = PayloadU16::read(&mut rd).unwrap();
            let val_pl = PayloadU16::read(&mut rd).unwrap();
            cache.insert(key_pl.0, val_pl.0);
        }
    }
}

impl rustls::client::StoresClientSessions for PersistCache {
    /// put: insert into in-memory cache, and perhaps persist to disk.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache
            .lock()
            .unwrap()
            .insert(key, value);
        self.save();
        true
    }

    /// get: from in-memory cache
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache
            .lock()
            .unwrap()
            .get(key)
            .cloned()
    }
}

const USAGE: &'static str = "
Connects to the TLS server at hostname:PORT.  The default PORT
is 443.  By default, this reads a request from stdin (to EOF)
before making the connection.  --http replaces this with a
basic HTTP GET request for /.

If --cafile is not supplied, a built-in set of CA certificates
are used from the webpki-roots crate.

Usage:
  tlsclient [options] [--suite SUITE ...] [--proto PROTO ...] <hostname>
  tlsclient (--version | -v)
  tlsclient (--help | -h)

Options:
    -p, --port PORT     Connect to PORT [default: 443].
    --http              Send a basic HTTP GET request for /.
    --cafile CAFILE     Read root certificates from CAFILE.
    --auth-key KEY      Read client authentication key from KEY.
    --auth-certs CERTS  Read client authentication certificates from CERTS.
                        CERTS must match up with KEY.
    --protover VERSION  Disable default TLS version list, and use
                        VERSION instead.  May be used multiple times.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Send ALPN extension containing PROTOCOL.
                        May be used multiple times to offer several protocols.
    --cache CACHE       Save session cache to file CACHE.
    --no-tickets        Disable session ticket support.
    --no-sni            Disable server name indication support.
    --insecure          Disable certificate verification.
    --verbose           Emit log output.
    --max-frag-size M   Limit outgoing messages to M bytes.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
    --clientip IP       The IP of client.
    --clientport PORT   The poet number of client.
    --verifierip IP     The IP of verifier.
    --verifierport PORT       The port number of verifier.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_port: Option<u16>,
    flag_http: bool,
    flag_verbose: bool,
    flag_protover: Vec<String>,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_max_frag_size: Option<usize>,
    flag_cafile: Option<String>,
    flag_cache: Option<String>,
    flag_no_tickets: bool,
    flag_no_sni: bool,
    flag_insecure: bool,
    flag_auth_key: Option<String>,
    flag_auth_certs: Option<String>,
    arg_hostname: String,
    flag_clientip: String,
    flag_clientport: String,
    flag_verifierip: String,
    flag_verifierport: String
}

// TODO: um, well, it turns out that openssl s_client/s_server
// that we use for testing doesn't do ipv6.  So we can't actually
// test ipv6 and hence kill this.
fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}

/// Find a ciphersuite with the given name
fn find_suite(name: &str) -> Option<rustls::SupportedCipherSuite> {
    for suite in rustls::ALL_CIPHER_SUITES {
        let sname = format!("{:?}", suite.suite()).to_lowercase();

        if sname == name.to_string().to_lowercase() {
            return Some(*suite);
        }
    }

    None
}

/// Make a vector of ciphersuites named in `suites`
fn lookup_suites(suites: &[String]) -> Vec<rustls::SupportedCipherSuite> {
    let mut out = Vec::new();

    for csname in suites {
        let scs = find_suite(csname);
        match scs {
            Some(s) => out.push(s),
            None => panic!("cannot look up ciphersuite '{}'", csname),
        }
    }

    out
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(versions: &[String]) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => &rustls::version::TLS12,
            "1.3" => &rustls::version::TLS13,
            _ => panic!(
                "cannot look up version '{}', valid are '1.2' and '1.3'",
                vname
            ),
        };
        out.push(version);
    }

    out
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

#[cfg(feature = "dangerous_configuration")]
mod danger {
    use super::rustls;

    pub struct NoCertificateVerification {}

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}

#[cfg(feature = "dangerous_configuration")]
fn apply_dangerous_options(args: &Args, cfg: &mut rustls::ClientConfig) {
    if args.flag_insecure {
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    }
}

#[cfg(not(feature = "dangerous_configuration"))]
fn apply_dangerous_options(args: &Args, _: &mut rustls::ClientConfig) {
    if args.flag_insecure {
        panic!("This build does not support --insecure.");
    }
}

/// Build a `ClientConfig` from our arguments
fn make_config(args: &Args) -> Arc<rustls::ClientConfig> {
    let mut root_store = RootCertStore::empty();

    if args.flag_cafile.is_some() {
        let cafile = args.flag_cafile.as_ref().unwrap();

        let certfile = fs::File::open(&cafile).expect("Cannot open CA file");
        let mut reader = BufReader::new(certfile);
        root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut reader).unwrap());
    } else {
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS
                .0
                .iter()
                .map(|ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                }),
        );
    }

    let suites = if !args.flag_suite.is_empty() {
        lookup_suites(&args.flag_suite)
    } else {
        rustls::DEFAULT_CIPHER_SUITES.to_vec()
    };

    let versions = if !args.flag_protover.is_empty() {
        lookup_versions(&args.flag_protover)
    } else {
        rustls::DEFAULT_VERSIONS.to_vec()
    };

    let config = rustls::ClientConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suite/versions selected")
        .with_root_certificates(root_store);

    let mut config = match (&args.flag_auth_key, &args.flag_auth_certs) {
        (Some(key_file), Some(certs_file)) => {
            let certs = load_certs(certs_file);
            let key = load_private_key(key_file);
            config
                .with_single_cert(certs, key)
                .expect("invalid client auth certs/key")
        }
        (None, None) => config.with_no_client_auth(),
        (_, _) => {
            panic!("must provide --auth-certs and --auth-key together");
        }
    };

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    if args.flag_no_tickets {
        config.enable_tickets = false;
    }

    if args.flag_no_sni {
        config.enable_sni = false;
    }

    config.session_storage = Arc::new(PersistCache::new(&args.flag_cache));

    config.alpn_protocols = args
        .flag_proto
        .iter()
        .map(|proto| proto.as_bytes().to_vec())
        .collect();
    config.max_fragment_size = args.flag_max_frag_size;

    apply_dangerous_options(args, &mut config);

    Arc::new(config)
}

//=============================== verifier's program starts ===================================
use rustls::client::tls13;
use rustls::uint_to_yint;
use rustls::kx;
use rustls::client::ectf;
use rustls::error::Error;
use curv::BigInt;
use curv::arithmetic::Converter;
use curv::arithmetic::traits::*;
use ring::ec::curve25519::ops::ExtPoint;
use ring::ec::curve25519::ops;
use ring::ec::curve25519::ed25519::verification::{GFp_x25519_ge_add, GFp_x25519_extpoint_from_private_generic_masked, GFp_x25519_ge_double_scalarmult_vartime};
use ring::ec::curve25519::scalar::{Scalar, SCALAR_LEN};
use paillier::traits::EncryptWithChosenRandomness;
use paillier::{
    Encrypt, Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext, RawPlaintext, Mul, Add
};


fn pop(barry: &[u8]) -> [u8; 32] {
    barry.try_into().expect("slice with incorrect length")
}

fn send_g_v_to_client(mut stream: &TcpStreamNet, u_coor: &Vec<u8>) {
    let mut buf = [0; 256];
    stream.write(&u_coor).unwrap();
}

fn compute_and_send_g_vy_to_client(mut stream: &TcpStreamNet, kxchg: kx::KeyExchange) 
-> Vec<u8>{
    let mut buf = [0; 256];
    let read_bytes = stream.read(&mut buf).unwrap(); // read g^v
    println!("g^y received from client {:?}", &buf[..read_bytes]);

    // g^vy
    let verifier_server_shared = kxchg
    .complete(&buf[..read_bytes].to_vec())
    .ok_or_else(|| Error::PeerMisbehavedError("key exchange failed".to_string())).unwrap();
    // println!("\n[verifier side: server's key share (payload.0)] {:?}", &their_key_share.payload.0);
    let mut U_vy_bytes = verifier_server_shared.shared_secret.clone(); // little endian
    println!("U_vy little endian = {:?}", U_vy_bytes);
    U_vy_bytes.reverse();  // big endian
    stream.write(&U_vy_bytes).unwrap();

    U_vy_bytes
}


// TLS 1.2
fn compute_g_vy(kxchg: kx::KeyExchange, buf: &[u8]) 
-> Vec<u8>{
    // let mut buf = [0; 256];
    // let read_bytes = stream.read(&mut buf).unwrap(); // read g^v
    // println!("g^y received from client {:?}", &buf[..read_bytes]);

    // g^vy
    let verifier_server_shared = kxchg
    .complete(&buf.to_vec())
    .ok_or_else(|| Error::PeerMisbehavedError("key exchange failed".to_string())).unwrap();
    // println!("\n[verifier side: server's key share (payload.0)] {:?}", &their_key_share.payload.0);
    let mut U_vy_bytes = verifier_server_shared.shared_secret.clone(); // little endian
    println!("U_vy little endian = {:?}", U_vy_bytes);
    U_vy_bytes.reverse();  // big endian
    // stream.write(&U_vy_bytes).unwrap();

    U_vy_bytes
}

fn get_payload(mut stream: &TcpStreamNet) 
->  Vec<u8> {
    let mut buf = [0; 8000000]; 
    let read_bytes = stream.read(&mut buf).unwrap(); 
    buf[..read_bytes].to_vec()
}


fn get_seq(mut stream: &TcpStreamNet) 
->  u64 {

    fn pop(barry: &[u8]) -> [u8; 8] {
        barry.try_into().expect("slice with incorrect length")
    }
    let mut buf = [0; 100000]; 
    let read_bytes = stream.read(&mut buf).unwrap(); 
    let mut bytes = buf[..read_bytes].to_vec();
    let num_of_zero_bytes = 8 - bytes.len();
    if num_of_zero_bytes > 0 {
        for _ in 0..num_of_zero_bytes {
            bytes.push(0);
        }
    }

    let tmp: [u8; 8] = pop(&bytes);

    u64::from_be_bytes(tmp)
}



fn handle_client_once(mut stream: TcpStreamNet) {
    let mut buf = [0; 512];

    let bytes_read = stream.read(&mut buf).unwrap();
    println!("{:?}", &buf[..bytes_read]);
    if bytes_read == 0 {
        println!("byteread = 0");
    }

    println!("{}", &str::from_utf8(&buf).unwrap()[..4]);
    stream.write(&buf[..bytes_read]).unwrap();
    // thread::sleep(time::Duration::from_secs(1));
}

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

fn main_in_verifier(listener: &TcpListener) {
    
    let start = Instant::now();

    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
        
    if args.flag_verbose {
        env_logger::Builder::new()
            .parse_filters("trace")
            .init();
    }

    let port = args.flag_port.unwrap_or(443);
    let addr = lookup_ipv4(args.arg_hostname.as_str(), port);

    let config = make_config(&args);

    let server_name = args
        .arg_hostname
        .as_str()
        .try_into()
        .expect("invalid DNS name");

    let support_tls12 = config.supports_version(ProtocolVersion::TLSv1_2);
    let support_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);

    let verifier_keypair = if support_tls13 {
        Some(tls13::initial_key_share(&config, &server_name).unwrap())
    } else {
        None
    };
    
    if support_tls13 {
        // hs.rs
        let verifier_keypair = verifier_keypair.unwrap();
        // transform from verifier's seed to its ext_point
        let mut verifier_extpoint = ExtPoint::new_at_infinity(); 
        let privkey_verifier: &[u8; SCALAR_LEN] = verifier_keypair.privkey.private_key.bytes_less_safe().try_into().unwrap();
        let privkey_verifier = ops::MaskedScalar::from_bytes_masked(*privkey_verifier);
        unsafe { 
            GFp_x25519_extpoint_from_private_generic_masked(
                &mut verifier_extpoint, 
                &privkey_verifier,
            )
        };  

        let serialized_point = verifier_extpoint.into_encoded_point().to_vec();
        // let listener = TcpListener::bind(CLIENT_IP_WITH_PORT).unwrap();

        // send serialized ExtPoint: g^v
        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        send_g_v_to_client(&stream, &serialized_point);


        // tls13.rs
        // send U_vy_bytes
        stream = listener.incoming().next().unwrap().expect("failed"); 
        let U_vy_bytes: Vec<u8> = compute_and_send_g_vy_to_client(&stream, verifier_keypair.clone());
        let x2 = BigInt::from_bytes(&U_vy_bytes); // for ectf 
        let y2 = ectf::get_v_coordinate(x2.clone());

        println!("x2 (U_vy) = {}", &x2);
        let U_vy_hex = x2.clone().to_hex();
        println!("\nU_vy hex: {}\n", U_vy_hex);

        // p for 25519
        let p: BigInt = BigInt::from_str_radix(
            // "115792089237316195423570985008687907853269984665640564039457584007908834671663",
            "57896044618658097711785492504343953926634992332820282019728792003956564819949",
            10
        ).unwrap();
        let a2 = BigInt::from(486662);
        let (s2, duration_hs) = rustls::client::ectf::ectf(&listener, p.clone(), a2.clone(), x2.clone(), y2.clone());

        println!("check point 2 => client side");

        // use std::{thread};
        // thread::sleep(Duration::from_millis(2000));

        // Handle the 2PC-HMAC for shared message
        println!("========== Handling 2PC-HMAC for shared message ==========");
        let start_2pc_hmac = Instant::now();
        handle_2pc_hmac_msg_verifier(s2.to_hex().to_string().clone());
        let duration_2pc_hmac = start_2pc_hmac.elapsed();
        // println!("s2: {}", s2.to_hex().to_string());
        println!("========== Handled 2PC-HMAC for shared message ==========");

        println!("========== 2PC-HMAC for shared message ==========");
        use std::env;
        use std::fs;
        let fs_verifier_share = format!("{}{}", emp_path, "msg_verifier_share_le.txt"); //"./rustls/src/emp/emp-ag2pc/2pc_hmac/msg_verifier_share_le.txt";
        let mut verifier_share = fs::read_to_string(fs_verifier_share).expect("failed reading");
        // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        // stream.write(&verifier_share.as_bytes()).unwrap();

        println!("========== HS ==========");
        let mut verifier_share_be: String = verifier_share.chars().rev().collect();
        for i in 0..256 {
            verifier_share_be = format!("{}{}", verifier_share_be, "0");
        }
        let mut verifier_share_le: String = verifier_share_be.chars().rev().collect();

        call_emp_2pc_hmac_key_iopad(verifier_share_le.clone(), String::from("HS_ipad_le.txt"));
        let fs_hs_ipad = format!("{}{}", emp_path, "HS_ipad_le.txt"); // "./rustls/src/emp/emp-ag2pc/2pc_hmac/HS_ipad_le.txt";
        let mut hs_ipad_le = fs::read_to_string(fs_hs_ipad).expect("failed reading");

        // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        // stream.write(&hs_ipad_le.as_bytes()).unwrap();

        call_emp_2pc_hmac_key_iopad(verifier_share_le.clone(), String::from("HS_opad_le.txt"));
        let fs_hs_opad = format!("{}{}", emp_path, "HS_opad_le.txt"); //"./rustls/src/emp/emp-ag2pc/2pc_hmac/HS_opad_le.txt";
        let mut hs_opad_le = fs::read_to_string(fs_hs_opad).expect("failed reading");

        // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        // stream.write(&hs_opad_le.as_bytes()).unwrap();

        println!("========== CHTS ==========");
        let chts_verifier_share_fs = String::from("CHTS_le.txt");
        let chts_ipad_le_fs = String::from("CHTS_ipad_le.txt");
        let chts_opad_le_fs = String::from("CHTS_opad_le.txt");
        handle_2pc_hamc_expand(
            hs_ipad_le.clone(), 
            hs_opad_le.clone(), 
            chts_verifier_share_fs.clone()
        );
        handle_CHTS_CATS_EMS_ipad_opad(
            listener,
            chts_verifier_share_fs.clone(),
            chts_ipad_le_fs.clone(),
            chts_opad_le_fs.clone()
        );

        println!("========== SHTS ==========");
        let shts_verifier_share_fs = String::from("SHTS_le.txt");
        let shts_ipad_le_fs = String::from("SHTS_ipad_le.txt");
        let shts_opad_le_fs = String::from("SHTS_opad_le.txt");
        handle_2pc_hamc_expand(
            hs_ipad_le.clone(), 
            hs_opad_le.clone(), 
            shts_verifier_share_fs.clone()
        );
        handle_CHTS_CATS_EMS_ipad_opad(
            listener,
            shts_verifier_share_fs.clone(),
            shts_ipad_le_fs.clone(),
            shts_opad_le_fs.clone()
        );

        println!("check point - after SHTS");

        // There are 2 possibilities for the received message
        // due to the 50% success probability of ECtF:
        // 1. The abort message (ECtF not correct)
        // 2. Proceed to dHS and secrets/keys afterwards (ECtF correct)

        // Receive client message
        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        let client_message = get_payload(&stream);
        println!("address: {:?}", stream.local_addr().unwrap());
        println!("client_message: {:?}", client_message);

        // Verifier reply and abort
        if client_message == String::from("Hey").as_bytes().to_vec() {
            println!("Verifier reply");
            let signal_to_client: Vec<u8> = String::from("After SHTS").as_bytes().to_vec();
            println!("address: {:?}", stream.local_addr().unwrap());
            stream.write(&signal_to_client).unwrap();
            println!("signal_to_client: {:?}", signal_to_client);
            println!("Sent Verifier reply");
            println!("********** Abort ***********");
            main_in_verifier(listener);
            return;
        }

        println!("========== dHS ==========");
        let dhs_verifier_share_fs = String::from("dHS_le.txt");
        let dhs_ipad_le_fs = String::from("dHS_ipad_le.txt");
        let dhs_opad_le_fs = String::from("dHS_opad_le.txt");

        // will call "hi expand" when meeting error?
        handle_2pc_hamc_expand(
            hs_ipad_le.clone(), 
            hs_opad_le.clone(), 
            dhs_verifier_share_fs.clone()
        );
        // stuck inside handle_2pc_hamc_expand

        // handle_CHTS_CATS_EMS_ipad_opad(
        handle_dHS_MS_ipad_opad(
            listener,
            dhs_verifier_share_fs.clone(),
            dhs_ipad_le_fs.clone(),
            dhs_opad_le_fs.clone()
        );

        let fs_dhs_ipad = format!("{}{}", emp_path, "dHS_ipad_le.txt"); //"./rustls/src/emp/emp-ag2pc/2pc_hmac/dHS_ipad_le.txt";
        let mut dhs_ipad_le = fs::read_to_string(fs_dhs_ipad).expect("failed reading");
        let fs_dhs_opad = format!("{}{}", emp_path, "dHS_opad_le.txt"); //"./rustls/src/emp/emp-ag2pc/2pc_hmac/dHS_opad_le.txt";
        let mut dhs_opad_le = fs::read_to_string(fs_dhs_opad).expect("failed reading");

        println!("========== MS ==========");
        let ms_verifier_share_fs = String::from("MS_le.txt");
        let ms_ipad_le_fs = String::from("MS_ipad_le.txt");
        let ms_opad_le_fs = String::from("MS_opad_le.txt");
        handle_2pc_hamc_expand(
            dhs_ipad_le.clone(), 
            dhs_opad_le.clone(), 
            ms_verifier_share_fs.clone()
        );
        // handle_CHTS_CATS_EMS_ipad_opad(
        handle_dHS_MS_ipad_opad(
            listener,
            ms_verifier_share_fs.clone(),
            ms_ipad_le_fs.clone(),
            ms_opad_le_fs.clone()
        );

        let fs_ms_ipad = format!("{}{}", emp_path, "MS_ipad_le.txt"); //"./rustls/src/emp/emp-ag2pc/2pc_hmac/MS_ipad_le.txt";
        let mut ms_ipad_le = fs::read_to_string(fs_ms_ipad).expect("failed reading");
        let fs_ms_opad = format!("{}{}", emp_path, "MS_opad_le.txt"); //"./rustls/src/emp/emp-ag2pc/2pc_hmac/MS_opad_le.txt";
        let mut ms_opad_le = fs::read_to_string(fs_ms_opad).expect("failed reading");

        println!("========== CATS ==========");
        let cats_verifier_share_fs = String::from("CATS_le.txt");
        let cats_ipad_le_fs = String::from("CATS_ipad_le.txt");
        let cats_opad_le_fs = String::from("CATS_opad_le.txt");
        handle_2pc_hamc_expand(
            ms_ipad_le.clone(), 
            ms_opad_le.clone(), 
            cats_verifier_share_fs.clone()
        );
        handle_CHTS_CATS_EMS_ipad_opad(
            listener,
            cats_verifier_share_fs.clone(),
            cats_ipad_le_fs.clone(),
            cats_opad_le_fs.clone()
        );

        println!("========== SATS ==========");
        let sats_verifier_share_fs = String::from("SATS_le.txt");
        let sats_ipad_le_fs = String::from("SATS_ipad_le.txt");
        let sats_opad_le_fs = String::from("SATS_opad_le.txt");
        handle_2pc_hamc_expand(
            ms_ipad_le.clone(), 
            ms_opad_le.clone(), 
            sats_verifier_share_fs.clone()
        );
        let SATS_key = handle_SATS_ipad_opad(
            listener,
            sats_verifier_share_fs.clone(),
            sats_ipad_le_fs.clone(),
            sats_opad_le_fs.clone()
        );
        let SATS_key_Prk = ring::hkdf::Prk::hmac_key_to_prk(SATS_key.clone());

        let decrypter = rustls::tls13::Tls13CipherSuite::derive_decrypter_deco(&SATS_key_Prk);

        println!("========== EMS ==========");
        let ems_verifier_share_fs = String::from("EMS_le.txt");
        let ems_ipad_le_fs = String::from("EMS_ipad_le.txt");
        let ems_opad_le_fs = String::from("EMS_opad_le.txt");
        handle_2pc_hamc_expand(
            ms_ipad_le.clone(), 
            ms_opad_le.clone(), 
            ems_verifier_share_fs.clone()
        );
        handle_CHTS_CATS_EMS_ipad_opad(
            listener,
            ems_verifier_share_fs.clone(),
            ems_ipad_le_fs.clone(),
            ems_opad_le_fs.clone()
        );

        // let fs_sats_ipad = format!("{}{}", emp_path, "SATS_ipad_le.txt");//"./rustls/src/emp/emp-ag2pc/2pc_hmac/SATS_ipad_le.txt";
        // let mut sats_ipad_le = fs::read_to_string(fs_sats_ipad).expect("failed reading");
        // let fs_sats_opad = format!("{}{}", emp_path, "SATS_opad_le.txt");//"./rustls/src/emp/emp-ag2pc/2pc_hmac/SATS_opad_le.txt";
        // let mut sats_opad_le = fs::read_to_string(fs_sats_opad).expect("failed reading");

        // println!("========== tksapp key ==========");
        // let tksapp_key_verifier_share_fs = String::from("tksapp_key_le.txt");
        // handle_2pc_hamc_expand(
        //     sats_ipad_le.clone(), 
        //     sats_opad_le.clone(), 
        //     tksapp_key_verifier_share_fs.clone()
        // );

        // // Get the share of verifier
        // let fs_tksapp_key_le_v = "./rustls/src/emp/emp-ag2pc/2pc_hmac/tksapp_key_le.txt";
        // let mut tksapp_key_le_v = fs::read_to_string(fs_tksapp_key_le_v).expect("failed reading");
        // // Get the share from the client
        // let mut stream = TcpStreamNet::connect("127.0.0.1:8081").unwrap();
        // let tksapp_key_c = get_share(&stream);
        // // Get the real tksapp key
        // let tksapp_key_le = string_xor(tksapp_key_c, tksapp_key_le_v);
        // let tksapp_key_be: String = tksapp_key_le.chars().rev().collect();
        // let tksapp_key_be_u8_vec: Vec<u8> = be_bin_string_to_u8_vec(tksapp_key_be);
        // let mut tksapp_key_vec: Vec<u8> = Vec::new();
        // for i in 0..16 {
        //     tksapp_key_vec.push(tksapp_key_be_u8_vec[i]);
        // }
        // println!("tksapp_key_be_u8_vec: {:?}", tksapp_key_be_u8_vec);
        // println!("tksapp_key_vec: {:?}", tksapp_key_vec);

        // println!("========== tksapp iv ==========");
        // let tksapp_iv_verifier_share_fs = String::from("tksapp_iv_le.txt");
        // handle_2pc_hamc_expand(
        //     sats_ipad_le.clone(), 
        //     sats_opad_le.clone(), 
        //     tksapp_iv_verifier_share_fs.clone()
        // );

        // // Get the share of verifier
        // let fs_tksapp_iv_le_v = "./rustls/src/emp/emp-ag2pc/2pc_hmac/tksapp_iv_le.txt";
        // let mut tksapp_iv_le_v = fs::read_to_string(fs_tksapp_iv_le_v).expect("failed reading");
        // // Get the share from the client
        // let mut stream = TcpStreamNet::connect("127.0.0.1:8081").unwrap();
        // let tksapp_iv_c = get_share(&stream);
        // // Get the real tksapp iv
        // let tksapp_iv_le = string_xor(tksapp_iv_c, tksapp_iv_le_v);
        // let tksapp_iv_be: String = tksapp_iv_le.chars().rev().collect();
        // let tksapp_iv_be_u8_vec: Vec<u8> = be_bin_string_to_u8_vec(tksapp_iv_be);
        // let mut tksapp_iv_vec: Vec<u8> = Vec::new();
        // for i in 0..12 {
        //     tksapp_iv_vec.push(tksapp_iv_be_u8_vec[i]);
        // }
        // println!("tksapp_iv_be_u8_vec: {:?}", tksapp_iv_be_u8_vec);
        // println!("tksapp_iv_vec: {:?}", tksapp_iv_vec);
        

        println!("check point 2 => client side");

        // Ready for the received html.
        use std::fs::File;
        use std::io::prelude::*;
        let mut output_file = File::create("./output.html").unwrap();

        loop {
            // Receive client message
            let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            let client_message = get_payload(&stream);
            println!("address: {:?}", stream.local_addr().unwrap());
            println!("client_message: {:?}", client_message);

            // Verifier reply and abort
            if client_message == String::from("Hey").as_bytes().to_vec() {
                println!("Verifier reply");
                let signal_to_client: Vec<u8> = String::from("After SATS").as_bytes().to_vec();
                println!("address: {:?}", stream.local_addr().unwrap());
                stream.write(&signal_to_client).unwrap();
                println!("signal_to_client: {:?}", signal_to_client);
                println!("Sent Verifier reply");
            }

            use rustls::internal::msgs::message::MessagePayload;
            use std::convert::TryFrom;
            let stream = listener.incoming().next().unwrap().expect("failed"); 
            let payload_i_bytes = get_payload(&stream);
            println!("len of payload_i_bytes: {:?}", payload_i_bytes.len());
            // println!("payload_i_bytes: {:?}",  payload_i_bytes.clone());
            let stream = listener.incoming().next().unwrap().expect("failed");
            let seq_i = get_seq(&stream);
            // let payload_i: Payload = serde_json::from_str(str::from_utf8(payload_i_bytes.as_slice()).unwrap()).unwrap();
            let opaque_msg_i = OpaqueMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload {0: payload_i_bytes},
            };
            // println!("payload_i_bytes = {:?}", payload_i.clone());
            // println!("seq i = {}", seq_i);

            let plain_msg_i = decrypter.decrypt(opaque_msg_i, seq_i).unwrap();
            // let plain_msg_i = match decrypter.decrypt(opaque_msg_i.clone(), seq_i) {
            //     Ok(_) => {
            //         println!("Decrypt ok");
            //         decrypter.decrypt(opaque_msg_i, seq_i).unwrap()
            //     },
            //     Err(_) => {
            //         println!("Decrypt err: Payload skipped");
            //         continue
            //     }
            // };

            // let plain_msg_i = Message::try_from(plain_msg_i).unwrap();
            let plain_msg_i = match Message::try_from(plain_msg_i.clone()) {
                Ok(_) => {
                    println!("Payload ok");
                    Message::try_from(plain_msg_i.clone()).unwrap()
                },
                Err(_) => {
                    println!("Payload skipped");
                    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                    let signal_to_client: Vec<u8> = String::from("Continue").as_bytes().to_vec();
                    // println!("address: {:?}", stream.local_addr().unwrap());
                    stream.write(&signal_to_client).unwrap();
                    continue
                },
            };
            // println!("plain_msg1: {:?}", plain_msg_i);
            if plain_msg_i.payload.content_type() == ContentType::Handshake {
                println!("Handshake!");
                println!("{:?}", plain_msg_i.payload);
                continue;
            }
            else if plain_msg_i.payload.content_type() == ContentType::Alert {
                println!("Alert!");
                println!("{:?}", plain_msg_i.payload);
                break;
            }
            else if plain_msg_i.payload.content_type() == ContentType::ApplicationData {
                let payload: Payload = match plain_msg_i.payload {
                    MessagePayload::ApplicationData(content) => {
                        println!("ApplicationData -> ApplicationData!");
                        content
                    },
                    MessagePayload::Alert(_) => {
                        println!("ApplicationData -> Alert!");
                        Payload(vec![0, 0, 0])
                    },
                    MessagePayload::Handshake(_) => {
                        println!("ApplicationData -> Handshake!");
                        Payload(vec![0, 0, 0])
                    },
                    MessagePayload::ChangeCipherSpec(_) => {
                        println!("ApplicationData -> ChangeCipherSpec!");
                        Payload(vec![0, 0, 0])
                    },
                };
                    
                let html = String::from_utf8_lossy(&payload.0).into_owned();
                println!("html:\n{:?}", html);

                // Save the received html
                use std::fs::OpenOptions;
                let mut file = OpenOptions::new().append(true).open("output.html").unwrap();
                file.write(html.as_bytes());

                
                use std::env;
                let args: Vec<String> = env::args().collect();
                // println!("{:?}", args); 
                if args[2] == "services.clp.com.hk" {

                    if html == "0\r\n\r\n" {
                        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                        let signal_to_client: Vec<u8> = String::from("Exit").as_bytes().to_vec();
                        println!("address: {:?}", stream.local_addr().unwrap());
                        stream.write(&signal_to_client).unwrap();

                        let duration = start.elapsed();
                        println!("Time elapsed is: {:?} ns", duration.as_nanos());
                        println!("Time elapsed for HS is: {:?} ns", duration_hs.as_nanos());
                        println!("Time elapsed for 2PC-HMAC is: {:?} ns", duration_2pc_hmac.as_nanos());
                        return;
                    }
                    else {
                        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                        let signal_to_client: Vec<u8> = String::from("Continue").as_bytes().to_vec();
                        println!("address: {:?}", stream.local_addr().unwrap());
                        stream.write(&signal_to_client).unwrap();
                    }
                }
                else if args[2] == "www.google.com" {

                    let test: String = html.chars().rev().take(7).collect();
                    let mut target: String = String::from("</html>");
                    target = target.chars().rev().collect();
                    
                    if test == target {
                        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                        let signal_to_client: Vec<u8> = String::from("Exit").as_bytes().to_vec();
                        println!("address: {:?}", stream.local_addr().unwrap());
                        stream.write(&signal_to_client).unwrap();

                        let duration = start.elapsed();
                        println!("Time elapsed is: {:?} ns", duration.as_nanos());
                        println!("Time elapsed for HS is: {:?} ns", duration_hs.as_nanos());
                        println!("Time elapsed for 2PC-HMAC is: {:?} ns", duration_2pc_hmac.as_nanos());
                        return;
                    }
                    else {
                        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                        let signal_to_client: Vec<u8> = String::from("Continue").as_bytes().to_vec();
                        println!("address: {:?}", stream.local_addr().unwrap());
                        stream.write(&signal_to_client).unwrap();
                    }
                }

                else if args[2] == "www.youtube.com" {

                    let test: String = html.chars().rev().take(7).collect();
                    let mut target: String = String::from("</html>");
                    target = target.chars().rev().collect();
                    
                    if test == target {
                        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                        let signal_to_client: Vec<u8> = String::from("Exit").as_bytes().to_vec();
                        println!("address: {:?}", stream.local_addr().unwrap());
                        stream.write(&signal_to_client).unwrap();

                        let duration = start.elapsed();
                        println!("Time elapsed is: {:?} ns", duration.as_nanos());
                        println!("Time elapsed for HS is: {:?} ns", duration_hs.as_nanos());
                        println!("Time elapsed for 2PC-HMAC is: {:?} ns", duration_2pc_hmac.as_nanos());
                        return;
                    }
                    else {
                        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                        let signal_to_client: Vec<u8> = String::from("Continue").as_bytes().to_vec();
                        println!("address: {:?}", stream.local_addr().unwrap());
                        stream.write(&signal_to_client).unwrap();
                    }
                }

                else if args[2] == "www.facebook.com" {

                    let test: String = html.chars().rev().take(4).collect();
                    let mut target: String = String::from("\r\n\r\n");
                    target = target.chars().rev().collect();
                    
                    if test == target {
                        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                        let signal_to_client: Vec<u8> = String::from("Exit").as_bytes().to_vec();
                        println!("address: {:?}", stream.local_addr().unwrap());
                        stream.write(&signal_to_client).unwrap();

                        let duration = start.elapsed();
                        println!("Time elapsed is: {:?} ns", duration.as_nanos());
                        println!("Time elapsed for HS is: {:?} ns", duration_hs.as_nanos());
                        println!("Time elapsed for 2PC-HMAC is: {:?} ns", duration_2pc_hmac.as_nanos());
                        return;
                    }
                    else {
                        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                        let signal_to_client: Vec<u8> = String::from("Continue").as_bytes().to_vec();
                        println!("address: {:?}", stream.local_addr().unwrap());
                        stream.write(&signal_to_client).unwrap();
                    }
                }
            }
            else {
                println!("other content type: Heartbeat or ChangeCipherSpec");
            }
        }
        
        // // handle abort or receive the first payload
        // let stream = listener.incoming().next().unwrap().expect("failed");
        // let payload1_bytes = get_payload(&stream);
        // let stream = listener.incoming().next().unwrap().expect("failed");
        // let seq1 = get_seq(&stream);

        // let payload1: Payload = serde_json::from_str(str::from_utf8(payload1_bytes.as_slice()).unwrap()).unwrap();
        // let opaque_msg1 = OpaqueMessage {
        //     typ: ContentType::ApplicationData,
        //     version: ProtocolVersion::TLSv1_3,
        //     payload: payload1.clone(),
        // };
        // println!("payload1_bytes = {:?}", payload1.clone());
        // println!("seq 1 = {}", seq1);


        // let stream = listener.incoming().next().unwrap().expect("failed"); 
        // let payload2_bytes = get_payload(&stream);
        // let stream = listener.incoming().next().unwrap().expect("failed");
        // let seq2 = get_seq(&stream);

        // let payload2: Payload = serde_json::from_str(str::from_utf8(payload2_bytes.as_slice()).unwrap()).unwrap();
        // let opaque_msg2 = OpaqueMessage {
        //     typ: ContentType::ApplicationData,
        //     version: ProtocolVersion::TLSv1_2,
        //     payload: payload2.clone(),
        // };
        // println!("payload2_bytes = {:?}", payload2.clone());
        // println!("seq 2 = {}", seq2);



        // let stream = listener.incoming().next().unwrap().expect("failed"); 
        // let payload3_bytes = get_payload(&stream);
        // let stream = listener.incoming().next().unwrap().expect("failed");
        // let seq3 = get_seq(&stream);

        // let payload3: Payload = serde_json::from_str(str::from_utf8(payload3_bytes.as_slice()).unwrap()).unwrap();
        // let opaque_msg3 = OpaqueMessage {
        //     typ: ContentType::ApplicationData,
        //     version: ProtocolVersion::TLSv1_2,
        //     payload: payload3.clone(),
        // };
        // println!("payload3_bytes = {:?}", payload3.clone());
        // println!("seq 3 = {}", seq3);


        // let stream = listener.incoming().next().unwrap().expect("failed"); 
        // let payload4_bytes = get_payload(&stream);
        // let stream = listener.incoming().next().unwrap().expect("failed");
        // let seq4 = get_seq(&stream);

        // let payload4: Payload = serde_json::from_str(str::from_utf8(payload4_bytes.as_slice()).unwrap()).unwrap();
        // let opaque_msg4 = OpaqueMessage {
        //     typ: ContentType::ApplicationData,
        //     version: ProtocolVersion::TLSv1_2,
        //     payload: payload4.clone(),
        // };
        // println!("payload4_bytes = {:?}", payload4.clone());
        // println!("seq 4 = {}", seq4);


        // println!("check point 3");


        // let plain_msg1 = decrypter.decrypt(opaque_msg1, seq1).unwrap();
        // println!("plain_msg1: {:#?}", plain_msg1);

        // let plain_msg2 = decrypter.decrypt(opaque_msg2, seq2).unwrap();
        // println!("plain_msg2: {:#?}", plain_msg2);

        // let plain_msg3 = decrypter.decrypt(opaque_msg3, seq3).unwrap();
        // println!("plain_msg3: {:#?}", plain_msg3);

        // let plain_msg4 = decrypter.decrypt(opaque_msg4, seq4).unwrap();
        // println!("plain_msg4: {:#?}", plain_msg4);

        // // use crate::msgs::base::Payload;
        // // // meet unwrap error here
        // let payload1: Payload = serde_json::from_str(str::from_utf8(payload1_bytes.as_slice()).unwrap()).unwrap();
        // let payload2: Payload = serde_json::from_str(str::from_utf8(payload2_bytes.as_slice()).unwrap()).unwrap();
        // println!("payload 1: {:?}", payload1);
        // println!("payload 2: {:?}", payload2);

        println!("hello, verifier!");
        println!();

        let duration = start.elapsed();
        println!("Time elapsed is: {:?} ns", duration.as_nanos());
        println!("Time elapsed for HS is: {:?} ns", duration_hs.as_nanos());
        println!("Time elapsed for 2PC-HMAC is: {:?} ns", duration_2pc_hmac.as_nanos());

        process::exit(1);
    }
    else if support_tls12 {

        let mut s2: BigInt = BigInt::from(0);
        let mut duration_hs: Duration;

        let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
        let args: Args = Docopt::new(USAGE)
            .and_then(|d| Ok(d.help(true)))
            .and_then(|d| Ok(d.version(Some(version))))
            .and_then(|d| d.deserialize())
            .unwrap_or_else(|e| e.exit());

        println!("args.flag_suite[0]: {:?}", args.flag_suite[0]);

        if args.flag_suite[0] == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" {

            // ======================= Verifier PK -> Client =======================
            // Get server key g^y
            let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            let ecdh_params_public = get_payload(&stream); 
            println!("ecdh_params.public.0: {:?}", ecdh_params_public);

            let kx_groups = [&kx::X25519, &kx::SECP256R1, &kx::SECP384R1];
            let group =
                kx::KeyExchange::choose(kx::NamedGroup::X25519, &kx_groups)
                    .ok_or_else(|| {
                        Error::PeerMisbehavedError("peer chose an unsupported group".to_string())
                    }).unwrap();

            // kx: (v, g^v)
            let kx = kx::KeyExchange::start(group).ok_or(Error::FailedToGetRandomBytes).unwrap();
            println!("The current client key in kx is (v, g^v).: {:?}", kx.pubkey.bytes.as_ref());
            println!("Length: {:?}", kx.pubkey.bytes.as_ref().len());

            // // Send g^v to client
            // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            // stream.write(&kx.pubkey.bytes.as_ref()).unwrap();

            // hs.rs
            let verifier_keypair = kx.clone();
            // transform from verifier's seed to its ext_point
            let mut verifier_extpoint = ExtPoint::new_at_infinity(); 
            let privkey_verifier: &[u8; SCALAR_LEN] = verifier_keypair.privkey.private_key.bytes_less_safe().try_into().unwrap();
            let privkey_verifier = ops::MaskedScalar::from_bytes_masked(*privkey_verifier);
            unsafe { 
                GFp_x25519_extpoint_from_private_generic_masked(
                    &mut verifier_extpoint, 
                    &privkey_verifier,
                )
            };  

            let serialized_point = verifier_extpoint.into_encoded_point().to_vec();
            // let listener = TcpListener::bind(CLIENT_IP_WITH_PORT).unwrap();
            println!("serialized_point: {:?}", serialized_point);

            // send serialized ExtPoint: g^v
            let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            send_g_v_to_client(&stream, &serialized_point);

            // send U_vy_bytes
            // stream = listener.incoming().next().unwrap().expect("failed"); 
            let U_vy_bytes: Vec<u8> = compute_g_vy(verifier_keypair.clone(), &ecdh_params_public.clone());

            let x2 = BigInt::from_bytes(&U_vy_bytes); // for ectf 
            let y2 = ectf::get_v_coordinate(x2.clone());

            println!("x2 (U_vy) = {}", &x2);
            let U_vy_hex = x2.clone().to_hex();
            println!("\nU_vy hex: {}\n", U_vy_hex);

            // ======================= [Start] ECtF =======================
            // p for 25519
            let p: BigInt = BigInt::from_str_radix(
                // "115792089237316195423570985008687907853269984665640564039457584007908834671663",
                "57896044618658097711785492504343953926634992332820282019728792003956564819949",
                10
            ).unwrap();
            let a2 = BigInt::from(486662);
            (s2, duration_hs) = rustls::client::ectf::ectf(&listener, p.clone(), a2.clone(), x2.clone(), y2.clone());

            // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            // stream.write(&s2.to_bytes()).unwrap();
            // ======================= [End] ECtF =======================
        }
        else if args.flag_suite[0] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {

            // ======================= Verifier PK -> Client =======================
            // Get server key g^y
            let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            let ecdh_params_public = get_payload(&stream); 
            println!("ecdh_params.public.0: {:?}", ecdh_params_public);

            let kx_groups = [&kx::X25519, &kx::SECP256R1, &kx::SECP384R1];
            let group =
                kx::KeyExchange::choose(kx::NamedGroup::secp256r1, &kx_groups)
                    .ok_or_else(|| {
                        Error::PeerMisbehavedError("peer chose an unsupported group".to_string())
                    }).unwrap();
            
            // kx: (v, g^v)
            let kx = kx::KeyExchange::start(group).ok_or(Error::FailedToGetRandomBytes).unwrap();
            println!("The current client key in kx is (v, g^v).: {:?}", kx.pubkey.bytes.as_ref());
            println!("Length: {:?}", kx.pubkey.bytes.as_ref().len());

            // Send g^v to client
            let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            stream.write(&kx.pubkey.bytes.as_ref()).unwrap();

            // kxd: verifier share -> ( verifier_pubkey: g^v, shared_secret: g^vy} )
            // ecdh_params_public: server key = (y, g^y)
            // kx: verifier key = (v, g^v) (kx.pubkey.bytes)
            // kxd: (g^y)^v => (v, g^vy)
            let kxd = rustls::tls12::complete_ecdh(kx.clone(), &ecdh_params_public).unwrap();
            println!("kxd: {:?}", kxd);

            // g^vy
            let mut verifier_shared_secret = kxd.shared_secret.clone();
            // verifier_shared_secret.reverse(); // big endian

            // ======================= [Start] ECtF =======================
            // p for secp256r1
            let p: BigInt = BigInt::from_str_radix(
                "115792089210356248762697446949407573530086143415290314195533631308867097853951",
                10
            ).unwrap();
            let a2 = BigInt::from(0);
            let x2 = BigInt::from_bytes(&verifier_shared_secret); // g^vy
            let y2 = ectf::get_secp256r1_v_coordinate(x2.clone(), p.clone());
            println!("(x2, y2): ({:?}, {:?})", x2, y2);
            (s2, duration_hs) = rustls::client::ectf::ectf(&listener, p.clone(), a2.clone(), x2.clone(), y2.clone());
            println!("s2: {:?}", s2);

            // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            // stream.write(&s2.to_bytes()).unwrap();
            // ======================= [End] ECtF =======================
        }
        
        // ======================= [Start] extented master secret =======================
        // Generate the HMAC Key
        println!("========== [Start] ems 2PC mod add ==========");
        println!("s2: {:?}", s2);
        let key_ipad_filename = String::from("tls12_ems_s1s2sum_ipad.txt");
        let key_opad_filename = String::from("tls12_ems_s1s2sum_opad.txt");
        if args.flag_suite[0] == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" {
            let s2_hex = s2.clone().to_hex().to_string();
            call_emp_2pc_tls12_ems_s1s2sum(
                s2_hex.clone(),
                "tls12_ems_s1s2sum.txt".to_string()
            );

            let fs_ems_sum = format!("{}{}", emp_path, "tls12_ems_s1s2sum.txt");
            let mut ems_sum_le = fs::read_to_string(fs_ems_sum).expect("failed reading");

            // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            // stream.write(&ems_sum_le.as_bytes()).unwrap();
            println!("========== [End] ems 2PC mod add ==========");

            println!("========== [Start] ems 2PC-HMAC for Key XOR ipad/opad ==========");
            // Calculate the Key with ipad/opad
            handle_ems_s1s2sum_ipad_opad_curve25519(
                listener,
                ems_sum_le.clone(),
                key_ipad_filename.clone(),
                key_opad_filename.clone()
            );
            println!("========== [End] ems 2PC-HMAC for Key XOR ipad/opad ==========");
        }
        else if args.flag_suite[0] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
            let s2_hex = s2.clone().to_hex().to_string();
            call_emp_2pc_tls12_ems_s1s2sum_secp256r1(
                s2_hex.clone(),
                "tls12_ems_s1s2sum.txt".to_string()
            );

            let fs_ems_sum = format!("{}{}", emp_path, "tls12_ems_s1s2sum.txt");
            let mut ems_sum_le = fs::read_to_string(fs_ems_sum).expect("failed reading");

            // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            // stream.write(&ems_sum_le.as_bytes()).unwrap();
            println!("========== [End] ems 2PC mod add ==========");

            println!("========== [Start] ems 2PC-HMAC for Key XOR ipad/opad ==========");
            // Calculate the Key with ipad/opad
            handle_ems_s1s2sum_ipad_opad_secp256r1(
                listener,
                ems_sum_le.clone(),
                key_ipad_filename.clone(),
                key_opad_filename.clone()
            );
            println!("========== [End] ems 2PC-HMAC for Key XOR ipad/opad ==========");
        }

        println!("========== [Start] ems 2PC-HMAC for recursive HMAC ==========");
        let phash1_1_filename = String::from("tls12_ems_Phash1_1.txt");
        let phash1_2_filename = String::from("tls12_ems_Phash1_2.txt");
        let phash2_1_filename = String::from("tls12_ems_Phash2_1.txt");
        let phash2_2_filename = String::from("tls12_ems_Phash2_2.txt");

        // Receive client message
        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        let client_message = get_payload(&stream);
        println!("client incoming message: {:?}", client_message);

        // Verifier reply
        if client_message == String::from("new_ems").as_bytes().to_vec() {

            let a1_filename = String::from("tls12_ems_A1.txt");
            let a2_filename = String::from("tls12_ems_A2.txt");
            let a3_filename = String::from("tls12_ems_A3.txt");

            let ems_output_be = handle_tls12_ems_recursive_hmac(
                listener,
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
        }
        else if client_message == String::from("new").as_bytes().to_vec() {

            let a1_1_filename = String::from("tls12_ems_A1_1.txt");
            let a1_2_filename = String::from("tls12_ems_A1_2.txt");
            let a2_filename = String::from("tls12_ems_A2.txt");
            let a3_filename = String::from("tls12_ems_A3.txt");
            
            let ems_output_be = handle_tls12_ms_recursive_hmac(
                listener,
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
            println!("========== [End] ems 2PC-HMAC for recursive HMAC ==========");
        }
        else {
            println!("Something invalid...");
        }
        // ======================= [End] extented master secret =======================

        // ======================= [Start] key expansion =======================
        // Calculate the Key with ipad/opad
        println!("========== [Start] ke 2PC-HMAC for Key XOR ipad/opad ==========");
        let key_ipad_filename = String::from("tls12_ke_key_ipad.txt");
        let key_opad_filename = String::from("tls12_ke_key_opad.txt");
        handle_ke_key_ipad_opad(
            listener,
            phash1_2_filename.clone(),
            phash2_2_filename.clone(),
            key_ipad_filename.clone(),
            key_opad_filename.clone()
        );
        println!("========== [End] ke 2PC-HMAC for Key XOR ipad/opad ==========");

        println!("========== [Start] ke 2PC-HMAC for recursive HMAC ==========");
        let a1_1_filename = String::from("tls12_ke_A1_1.txt");
        let a1_2_filename = String::from("tls12_ke_A1_2.txt");
        let a2_filename = String::from("tls12_ke_A2.txt");
        let a3_filename = String::from("tls12_ke_A3.txt");
        let phash1_1_filename = String::from("tls12_ke_Phash1_1.txt");
        let phash1_2_filename = String::from("tls12_ke_Phash1_2.txt");
        let phash2_1_filename = String::from("tls12_ke_Phash2_1.txt");
        let phash2_2_filename = String::from("tls12_ke_Phash2_2.txt");
        let ke_output_be = handle_tls12_ke_recursive_hmac(
            listener,
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

        println!("========== [End] ke 2PC-HMAC for recursive HMAC ==========");
        // ======================= [End] key expansion =======================

        // ======================= [Start] client/verifier write key/iv =======================
        println!("========== [Start] client/verifier write key/iv ==========");
        let fs: String = String::from(emp_path);
        let mut suites = if !args.flag_suite.is_empty() {
            lookup_suites(&args.flag_suite)
        } else {
            rustls::DEFAULT_CIPHER_SUITES.to_vec()
        };
        let suites = suites[0];
        println!("suites: {:?}", suites);

        // Truncate key
        let fs_ke_phash1_2: String = format!("{}{}", fs, "tls12_ke_Phash1_2.txt");
        let mut ke_phash1_2_le: String = fs::read_to_string(fs_ke_phash1_2).expect("failed reading");

        let fs_ke_phash2_2: String = format!("{}{}", fs, "tls12_ke_Phash2_2.txt");
        let mut ke_phash2_2_le: String = fs::read_to_string(fs_ke_phash2_2).expect("failed reading");

        let ke_phash1_2_be: String = ke_phash1_2_le.chars().rev().collect();
        let ke_phash2_2_be: String = ke_phash2_2_le.chars().rev().collect();
        let ke_be: String = format!("{}{}", ke_phash1_2_be, ke_phash2_2_be);

        let client_write_key_v: String = ke_be.clone()[0..128].to_string();
        let server_write_key_v: String = ke_be.clone()[128..256].to_string();
        let client_write_iv_v: String = ke_be.clone()[256..288].to_string();
        let server_write_iv_v: String = ke_be.clone()[288..320].to_string();
        let extra_v: String = ke_be.clone()[320..384].to_string();

        println!("client_write_key_v: {:?}", client_write_key_v);
        println!("server_write_key_v: {:?}", server_write_key_v);
        println!("client_write_iv_v: {:?}", client_write_iv_v);
        println!("server_write_iv_v: {:?}", server_write_iv_v);
        println!("extra_v: {:?}", extra_v);

        // Get client shares, and send verifier shares
        let (my_ip_port, target_ip, target_ip_port) = get_ip();
        // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        let mut stream = TcpStreamNet::connect(target_ip_port.as_str()).unwrap();
        let server_write_key_c = get_share(&stream);
        
        // let mut stream = listener.incoming().next().unwrap().expect("failed");
        let mut stream = TcpStreamNet::connect(target_ip_port.as_str()).unwrap(); 
        let server_write_iv_c = get_share(&stream);

        println!("server_write_key_c: {:?}", server_write_key_c);
        println!("server_write_iv_c: {:?}", server_write_iv_c);

        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        stream.write(&client_write_key_v.as_bytes()).unwrap();

        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        stream.write(&client_write_iv_v.as_bytes()).unwrap();

        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        stream.write(&extra_v.as_bytes()).unwrap();

        // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        // stream.write(&server_write_key_v.as_bytes()).unwrap();

        // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        // stream.write(&server_write_iv_v.as_bytes()).unwrap();
        
        // Do XOR and get real keys.
        let server_write_key_bin: String = string_xor(server_write_key_c, server_write_key_v);
        let server_write_iv_bin: String = string_xor(server_write_iv_c, server_write_iv_v);
        let server_write_key: Vec<u8> = be_bin_string_to_u8_vec(server_write_key_bin.clone());
        let server_write_iv: Vec<u8> = be_bin_string_to_u8_vec(server_write_iv_bin.clone());
        let server_write_key_aead = aead::UnboundKey::new(
            &aead::AES_128_GCM, 
            &server_write_key
        ).unwrap();
        let server_write_key_aead_lesssafekey = aead::LessSafeKey::new(
            server_write_key_aead
        );

        let decrypter = suites.tls12().unwrap()
            .aead_alg
            .decrypter(server_write_key_aead_lesssafekey, &server_write_iv);
        println!("========== [End] client/verifier write key/iv ==========");
        // ======================= [End] client/verifier write key/iv =======================

        // ======================= [Start] client finish =======================
        // Calculate the Key with ipad/opad
        println!("========== [Start] cf 2PC-HMAC for Key XOR ipad/opad ==========");
        let phash1_2_filename = String::from("tls12_ems_Phash1_2.txt");
        let phash2_2_filename = String::from("tls12_ems_Phash2_2.txt");
        let key_ipad_filename = String::from("tls12_cf_key_ipad.txt");
        let key_opad_filename = String::from("tls12_cf_key_opad.txt");
        handle_ke_key_ipad_opad(
            listener,
            phash1_2_filename.clone(),
            phash2_2_filename.clone(),
            key_ipad_filename.clone(),
            key_opad_filename.clone()
        );
        println!("========== [End] cf 2PC-HMAC for Key XOR ipad/opad ==========");
        println!("========== [Start] cf 2PC-HMAC for recursive HMAC ==========");
        let a1_filename = String::from("tls12_cf_A1.txt");
        let a2_filename = String::from("tls12_cf_A2.txt");
        let phash1_1_filename = String::from("tls12_cf_Phash1_1.txt");
        let phash1_2_filename = String::from("tls12_cf_Phash1_2.txt");
        let cf_output_be = handle_tls12_cf_sf_recursive_hmac(
            listener,
            key_ipad_filename.clone(),
            key_opad_filename.clone(),
            a1_filename.clone(),
            a2_filename.clone(),
            phash1_1_filename.clone(),
            phash1_2_filename.clone(),
        );

        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        stream.write(&cf_output_be.as_bytes()).unwrap();
        println!("========== [End] cf 2PC-HMAC for recursive HMAC ==========");
        // ======================= [End] client finish =======================

        // ======================= [Start] Server finish message decryption =======================
        println!("========== [Start] Server finish message decryption ==========");
        // Receive client message
        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        let client_message = get_payload(&stream);
        println!("client incoming message: {:?}", client_message);

        // Verifier reply
        if client_message == String::from("abort").as_bytes().to_vec() {
            println!("Verifier reply");
            println!("********** Abort ***********");
            main_in_verifier(listener);
            return;
        }
        else if client_message == String::from("Hey").as_bytes().to_vec() {
            println!("Verifier reply");
            let signal_to_client: Vec<u8> = String::from("After cf").as_bytes().to_vec();
            // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            stream.write(&signal_to_client).unwrap();
        

            // Receive client opaque message
            let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            let payload = get_payload(&stream);
            println!("client opaque message: {:?}", client_message);

            // Receive client opaque message seq_i
            let stream = listener.incoming().next().unwrap().expect("failed");
            let seq_i = get_seq(&stream);
            println!("seq_i: {:?}", seq_i);

            // Verifier decrypt
            let opmsg: OpaqueMessage = OpaqueMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload {0: payload}
            };

            let result = decrypter.decrypt(
                opmsg, 
                seq_i
            ).unwrap();
            println!("result: {:?}", result);

            let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            stream.write(&result.payload.0).unwrap();
        }
        println!("========== [End] Server finish message decryption ==========");
        // ======================= [End] Server finish message decryption =======================

        // ======================= [Start] Abort handling =======================
        // If Abort is required
        // Receive client message
        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        let client_message = get_payload(&stream);
        println!("client_message: {:?}", client_message);

        // Verifier reply and abort
        if client_message == String::from("abort").as_bytes().to_vec() {
            println!("Verifier reply");
            println!("********** Abort ***********");
            main_in_verifier(listener);
            return;
        }
        // ======================= [End] Abort handling =======================

        // ======================= [Start] server finish =======================
        // Calculate the Key with ipad/opad
        println!("========== [Start] sf 2PC-HMAC for Key XOR ipad/opad ==========");
        let phash1_2_filename = String::from("tls12_ems_Phash1_2.txt");
        let phash2_2_filename = String::from("tls12_ems_Phash2_2.txt");
        let key_ipad_filename = String::from("tls12_sf_key_ipad.txt");
        let key_opad_filename = String::from("tls12_sf_key_opad.txt");
        handle_ke_key_ipad_opad(
            listener,
            phash1_2_filename.clone(),
            phash2_2_filename.clone(),
            key_ipad_filename.clone(),
            key_opad_filename.clone()
        );
        println!("========== [End] sf 2PC-HMAC for Key XOR ipad/opad ==========");
        println!("========== [Start] sf 2PC-HMAC for recursive HMAC ==========");
        let a1_filename = String::from("tls12_sf_A1.txt");
        let a2_filename = String::from("tls12_sf_A2.txt");
        let phash1_1_filename = String::from("tls12_sf_Phash1_1.txt");
        let phash1_2_filename = String::from("tls12_sf_Phash1_2.txt");
        let sf_output_be = handle_tls12_cf_sf_recursive_hmac(
            listener,
            key_ipad_filename.clone(),
            key_opad_filename.clone(),
            a1_filename.clone(),
            a2_filename.clone(),
            phash1_1_filename.clone(),
            phash1_2_filename.clone(),
        );

        let mut stream = listener.incoming().next().unwrap().expect("failed"); 
        stream.write(&sf_output_be.as_bytes()).unwrap();
        println!("========== [End] sf 2PC-HMAC for recursive HMAC ==========");
        // ======================= [End] server finish =======================

        // ======================= [Start] Payload handling =======================
        let mut output_file = File::create("./output.html").unwrap();
        loop {

            // ======================= [Start] Abort handling =======================
            // If Abort is required
            // Receive client message
            let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            let client_message = get_payload(&stream);
            println!("client_message: {:?}", client_message);

            // Verifier reply and abort
            if client_message == String::from("abort").as_bytes().to_vec() {
                println!("Verifier reply");
                println!("********** Abort ***********");
                main_in_verifier(listener);
                return;
            }
            // ======================= [End] Abort handling =======================
        
            // Get the encrypted payload.
            let mut stream = listener.incoming().next().unwrap().expect("failed"); 
            let payload = get_payload(&stream); 
            println!("payload: {:?}", payload);
            
            let stream = listener.incoming().next().unwrap().expect("failed");
            let seq_i = get_seq(&stream);
            println!("seq_i: {:?}", seq_i);
            
            let opmsg: OpaqueMessage = OpaqueMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload {0: payload}
            };

            let result = decrypter.decrypt(
                opmsg, 
                seq_i
            ).unwrap();
            println!("result: {:?}", result);

            // let html = str::from_utf8(&result.payload.0).unwrap();
            let html = String::from_utf8_lossy(&result.payload.0).into_owned();
            println!("html:\n{:?}", html);

            // Save the received html
            use std::fs::OpenOptions;
            let mut file = OpenOptions::new().append(true).open("output.html").unwrap();
            file.write(html.as_bytes()).expect("html write failed");

            use std::env;
            let args: Vec<String> = env::args().collect();
            // println!("{:?}", args); 
            if args[2] == "www.yalealumni.yale.edu" {

                let test: String = html.chars().rev().take(2).collect();
                if test == "}}" {
                    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                    let signal_to_client: Vec<u8> = String::from("Exit").as_bytes().to_vec();
                    stream.write(&signal_to_client).unwrap();

                    let duration = start.elapsed();
                    println!("Time elapsed is: {:?} ns", duration.as_nanos());

                    return;
                }
                else {
                    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                    let signal_to_client: Vec<u8> = String::from("Continue").as_bytes().to_vec();
                    stream.write(&signal_to_client).unwrap();
                }
            }
            else if args[2] == "my.polyu.edu.hk" {

                let test: String = html.chars().rev().take(4).collect();
                let mut target: String = String::from("\r\n\r\n");
                target = target.chars().rev().collect();
                
                if test == target {
                    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                    let signal_to_client: Vec<u8> = String::from("Exit").as_bytes().to_vec();
                    println!("address: {:?}", stream.local_addr().unwrap());
                    stream.write(&signal_to_client).unwrap();

                    let duration = start.elapsed();
                    println!("Time elapsed is: {:?} ns", duration.as_nanos());
                    return;
                }
                else {
                    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                    let signal_to_client: Vec<u8> = String::from("Continue").as_bytes().to_vec();
                    println!("address: {:?}", stream.local_addr().unwrap());
                    stream.write(&signal_to_client).unwrap();
                }
            }
            else if args[2] == "cse.hkust.edu.hk" {

                let test: String = html.chars().rev().take(8).collect();
                let mut target: String = String::from("</html>\n");
                target = target.chars().rev().collect();
                
                if test == target {
                    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                    let signal_to_client: Vec<u8> = String::from("Exit").as_bytes().to_vec();
                    println!("address: {:?}", stream.local_addr().unwrap());
                    stream.write(&signal_to_client).unwrap();

                    let duration = start.elapsed();
                    println!("Time elapsed is: {:?} ns", duration.as_nanos());
                    return;
                }
                else {
                    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
                    let signal_to_client: Vec<u8> = String::from("Continue").as_bytes().to_vec();
                    println!("address: {:?}", stream.local_addr().unwrap());
                    stream.write(&signal_to_client).unwrap();
                }
            }
        }
        // ======================= [End] Payload handling =======================
    }

    let duration = start.elapsed();
    println!("Time elapsed is: {:?} ns", duration.as_nanos());
}

fn handle_tls12_ke_recursive_hmac(
    listener: &TcpListener,
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
) -> String {

    let fs: String = String::from(emp_path);

    let fs_ipad = format!("{}{}", fs, key_ipad_filename);
    let mut ipad_le = fs::read_to_string(fs_ipad).expect("failed reading");

    let fs_opad = format!("{}{}", fs, key_opad_filename);
    let mut opad_le = fs::read_to_string(fs_opad).expect("failed reading");

    // For A(1)
    println!("====== Start: 2PC-HMAC (A1) ======");
    let mut a1_input = String::new();
    while a1_input.len() < 512 {
        a1_input = format!("{}{}", a1_input, "0");
    }
    println!("a1_input: {:?}", a1_input);

    handle_emp_2pc_tls12_sha256(
        a1_input.clone(),
        ipad_le.clone(),
        a1_1_filename.clone()
    );

    let fs_a1_1 = format!("{}{}", fs, a1_1_filename);
    let mut a1_1_le = fs::read_to_string(fs_a1_1).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&a1_1_le.as_bytes()).unwrap();

    handle_2pc_hamc_expand(
        a1_1_le.clone(), 
        opad_le.clone(), 
        a1_2_filename.clone()
    );

    let fs_a1_2 = format!("{}{}", fs, a1_2_filename);
    let mut a1_2_le = fs::read_to_string(fs_a1_2).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&a1_2_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (A1) ======");

    // For P_hash[1]
    println!("====== Start: 2PC-HMAC (P_hash[1]) ======");
    let mut phash1_input = a1_2_le.clone();
    phash1_input = phash1_input.chars().rev().collect();
    while phash1_input.len() < 512 {
        phash1_input = format!("{}{}", phash1_input, "0");
    }
    phash1_input = phash1_input.chars().rev().collect();
    println!("phash1_input: {:?}", phash1_input);

    handle_emp_2pc_tls12_sha256(
        phash1_input.clone(),
        ipad_le.clone(),
        phash1_1_filename.clone()
    );

    let fs_phash1_1 = format!("{}{}", fs, phash1_1_filename);
    let mut phash1_1_le = fs::read_to_string(fs_phash1_1).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&phash1_1_le.as_bytes()).unwrap();

    handle_2pc_hamc_expand(
        phash1_1_le.clone(), 
        opad_le.clone(), 
        phash1_2_filename.clone()
    );

    let fs_phash1_2 = format!("{}{}", fs, phash1_2_filename);
    let mut phash1_2_le = fs::read_to_string(fs_phash1_2).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&phash1_2_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (P_hash[1]) ======");

    // For A2
    println!("====== Start: 2PC-HMAC (A2) ======");
    let mut a2_msg_be: String = a1_2_le.chars().rev().collect();
    while a2_msg_be.len() < 512 {
        a2_msg_be = format!("{}{}", a2_msg_be, "0");
    }
    println!("a2_msg_be: {:?}", a2_msg_be);
    let a2_msg_le: String = a2_msg_be.chars().rev().collect();

    handle_emp_2pc_tls12_expand(
        a2_msg_le.clone(),
        ipad_le.clone(), 
        opad_le.clone(), 
        a2_filename.clone()
    );

    let fs_a2 = format!("{}{}", fs, a2_filename);
    let mut a2_le = fs::read_to_string(fs_a2).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&a2_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (A2) ======");

    // For P_hash[2]
    println!("====== Start: 2PC-HMAC (P_hash[2]) ======");
    let mut phash2_input = a2_le.clone();
    phash2_input = phash2_input.chars().rev().collect();
    while phash2_input.len() < 512 {
        phash2_input = format!("{}{}", phash2_input, "0");
    }
    phash2_input = phash2_input.chars().rev().collect();
    println!("phash2_input: {:?}", phash2_input);

    handle_emp_2pc_tls12_sha256(
        phash2_input.clone(),
        ipad_le.clone(),
        phash2_1_filename.clone()
    );

    let fs_phash2_1 = format!("{}{}", fs, phash2_1_filename);
    let mut fs_phash2_1 = fs::read_to_string(fs_phash2_1).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&fs_phash2_1.as_bytes()).unwrap();

    handle_2pc_hamc_expand(
        fs_phash2_1.clone(), 
        opad_le.clone(), 
        phash2_2_filename.clone()
    );

    let fs_phash2_2 = format!("{}{}", fs, phash2_2_filename);
    let mut phash2_2_le = fs::read_to_string(fs_phash2_2).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&phash2_2_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (P_hash[2]) ======");

    // For A3
    println!("====== Start: 2PC-HMAC (A3) ======");
    let mut a3_msg_be: String = a2_le.chars().rev().collect();
    while a3_msg_be.len() < 512 {
        a3_msg_be = format!("{}{}", a3_msg_be, "0");
    }
    println!("a3_msg_be: {:?}", a3_msg_be);
    let a3_msg_le: String = a3_msg_be.chars().rev().collect();

    handle_emp_2pc_tls12_expand(
        a3_msg_le.clone(),
        ipad_le.clone(), 
        opad_le.clone(), 
        a3_filename.clone()
    );

    let fs_a3 = format!("{}{}", fs, a3_filename);
    let mut a3_le = fs::read_to_string(fs_a3).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&a3_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (A3) ======");
    
    let phash1_2_v_be: String = phash1_2_le.chars().rev().collect();
    let phash2_2_v_be: String = phash2_2_le.chars().rev().collect();
    let phash_output_be: String = format!("{}{}", phash1_2_v_be, phash2_2_v_be);

    phash_output_be[0..384].to_string()
}

fn handle_tls12_ems_recursive_hmac(
    listener: &TcpListener,
    key_ipad_filename: String,
    key_opad_filename: String,
    a1_filename: String,
    a2_filename: String,
    a3_filename: String,
    phash1_1_filename: String,
    phash1_2_filename: String,
    phash2_1_filename: String,
    phash2_2_filename: String,
) -> String {

    let fs: String = String::from(emp_path);

    let fs_ipad = format!("{}{}", fs, key_ipad_filename);
    let mut ipad_le = fs::read_to_string(fs_ipad).expect("failed reading");

    let fs_opad = format!("{}{}", fs, key_opad_filename);
    let mut opad_le = fs::read_to_string(fs_opad).expect("failed reading");

    // For A1
    println!("====== Start: 2PC-HMAC (A1) ======");
    handle_2pc_hamc_expand(
        ipad_le.clone(), 
        opad_le.clone(), 
        a1_filename.clone()
    );

    let fs_a1 = format!("{}{}", fs, a1_filename);
    let mut a1_le = fs::read_to_string(fs_a1).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&a1_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (A1) ======");

    // For P_hash[1]
    println!("====== Start: 2PC-HMAC (P_hash[1]) ======");
    let mut phash1_input = a1_le.clone();
    phash1_input = phash1_input.chars().rev().collect();
    while phash1_input.len() < 512 {
        phash1_input = format!("{}{}", phash1_input, "0");
    }
    phash1_input = phash1_input.chars().rev().collect();
    println!("phash1_input: {:?}", phash1_input);

    handle_emp_2pc_tls12_sha256(
        phash1_input.clone(),
        ipad_le.clone(),
        phash1_1_filename.clone()
    );

    let fs_phash1_1 = format!("{}{}", fs, phash1_1_filename);
    let mut phash1_1_le = fs::read_to_string(fs_phash1_1).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&phash1_1_le.as_bytes()).unwrap();

    handle_2pc_hamc_expand(
        phash1_1_le.clone(), 
        opad_le.clone(), 
        phash1_2_filename.clone()
    );

    let fs_phash1_2 = format!("{}{}", fs, phash1_2_filename);
    let mut phash1_2_le = fs::read_to_string(fs_phash1_2).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&phash1_2_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (P_hash[1]) ======");

    // For A2
    println!("====== Start: 2PC-HMAC (A2) ======");
    let mut a2_msg_be: String = a1_le.chars().rev().collect();
    while a2_msg_be.len() < 512 {
        a2_msg_be = format!("{}{}", a2_msg_be, "0");
    }
    println!("a2_msg_be: {:?}", a2_msg_be);
    let a2_msg_le: String = a2_msg_be.chars().rev().collect();

    handle_emp_2pc_tls12_expand(
        a2_msg_le.clone(),
        ipad_le.clone(), 
        opad_le.clone(), 
        a2_filename.clone()
    );

    let fs_a2 = format!("{}{}", fs, a2_filename);
    let mut a2_le = fs::read_to_string(fs_a2).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&a2_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (A2) ======");

    // For P_hash[2]
    println!("====== Start: 2PC-HMAC (P_hash[2]) ======");
    let mut phash2_input = a2_le.clone();
    phash2_input = phash2_input.chars().rev().collect();
    while phash2_input.len() < 512 {
        phash2_input = format!("{}{}", phash2_input, "0");
    }
    phash2_input = phash2_input.chars().rev().collect();
    println!("phash2_input: {:?}", phash2_input);

    handle_emp_2pc_tls12_sha256(
        phash2_input.clone(),
        ipad_le.clone(),
        phash2_1_filename.clone()
    );

    let fs_phash2_1 = format!("{}{}", fs, phash2_1_filename);
    let mut fs_phash2_1 = fs::read_to_string(fs_phash2_1).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&fs_phash2_1.as_bytes()).unwrap();

    handle_2pc_hamc_expand(
        fs_phash2_1.clone(), 
        opad_le.clone(), 
        phash2_2_filename.clone()
    );

    let fs_phash2_2 = format!("{}{}", fs, phash2_2_filename);
    let mut phash2_2_le = fs::read_to_string(fs_phash2_2).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&phash2_2_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (P_hash[2]) ======");

    // For A3
    println!("====== Start: 2PC-HMAC (A3) ======");
    let mut a3_msg_be: String = a2_le.chars().rev().collect();
    while a3_msg_be.len() < 512 {
        a3_msg_be = format!("{}{}", a3_msg_be, "0");
    }
    println!("a3_msg_be: {:?}", a3_msg_be);
    let a3_msg_le: String = a3_msg_be.chars().rev().collect();

    handle_emp_2pc_tls12_expand(
        a3_msg_le.clone(),
        ipad_le.clone(), 
        opad_le.clone(), 
        a3_filename.clone()
    );

    let fs_a3 = format!("{}{}", fs, a3_filename);
    let mut a3_le = fs::read_to_string(fs_a3).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&a3_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (A3) ======");
    
    let phash1_2_v_be: String = phash1_2_le.chars().rev().collect();
    let phash2_2_v_be: String = phash2_2_le.chars().rev().collect();
    let phash_output_be: String = format!("{}{}", phash1_2_v_be, phash2_2_v_be);

    phash_output_be[0..384].to_string()
}

fn handle_tls12_ms_recursive_hmac(
    listener: &TcpListener,
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
) -> String {

    let fs: String = String::from(emp_path);

    let fs_ipad = format!("{}{}", fs, key_ipad_filename);
    let mut ipad_le = fs::read_to_string(fs_ipad).expect("failed reading");

    let fs_opad = format!("{}{}", fs, key_opad_filename);
    let mut opad_le = fs::read_to_string(fs_opad).expect("failed reading");

    // For A1
    println!("====== Start: 2PC-HMAC (A1) ======");
    let mut a1_input = String::new();
    while a1_input.len() < 512 {
        a1_input = format!("{}{}", a1_input, "0");
    }
    println!("a1_input: {:?}", a1_input);

    handle_emp_2pc_tls12_sha256(
        a1_input.clone(),
        ipad_le.clone(),
        a1_1_filename.clone()
    );

    let fs_a1_1 = format!("{}{}", fs, a1_1_filename);
    let mut a1_1_le = fs::read_to_string(fs_a1_1).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&a1_1_le.as_bytes()).unwrap();

    handle_2pc_hamc_expand(
        a1_1_le.clone(), 
        opad_le.clone(), 
        a1_2_filename.clone()
    );

    let fs_a1_2 = format!("{}{}", fs, a1_2_filename);
    let mut a1_2_le = fs::read_to_string(fs_a1_2).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&a1_2_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (A1) ======");

    // For P_hash[1]
    println!("====== Start: 2PC-HMAC (P_hash[1]) ======");
    let mut phash1_input = a1_2_le.clone();
    phash1_input = phash1_input.chars().rev().collect();
    while phash1_input.len() < 512 {
        phash1_input = format!("{}{}", phash1_input, "0");
    }
    phash1_input = phash1_input.chars().rev().collect();
    println!("phash1_input: {:?}", phash1_input);

    handle_emp_2pc_tls12_sha256(
        phash1_input.clone(),
        ipad_le.clone(),
        phash1_1_filename.clone()
    );

    let fs_phash1_1 = format!("{}{}", fs, phash1_1_filename);
    let mut phash1_1_le = fs::read_to_string(fs_phash1_1).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&phash1_1_le.as_bytes()).unwrap();

    handle_2pc_hamc_expand(
        phash1_1_le.clone(), 
        opad_le.clone(), 
        phash1_2_filename.clone()
    );

    let fs_phash1_2 = format!("{}{}", fs, phash1_2_filename);
    let mut phash1_2_le = fs::read_to_string(fs_phash1_2).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&phash1_2_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (P_hash[1]) ======");

    // For A2
    println!("====== Start: 2PC-HMAC (A2) ======");
    let mut a2_msg_be: String = a1_2_le.chars().rev().collect();
    while a2_msg_be.len() < 512 {
        a2_msg_be = format!("{}{}", a2_msg_be, "0");
    }
    println!("a2_msg_be: {:?}", a2_msg_be);
    let a2_msg_le: String = a2_msg_be.chars().rev().collect();

    handle_emp_2pc_tls12_expand(
        a2_msg_le.clone(),
        ipad_le.clone(), 
        opad_le.clone(), 
        a2_filename.clone()
    );

    let fs_a2 = format!("{}{}", fs, a2_filename);
    let mut a2_le = fs::read_to_string(fs_a2).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&a2_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (A2) ======");

    // For P_hash[2]
    println!("====== Start: 2PC-HMAC (P_hash[2]) ======");
    let mut phash2_input = a2_le.clone();
    phash2_input = phash2_input.chars().rev().collect();
    while phash2_input.len() < 512 {
        phash2_input = format!("{}{}", phash2_input, "0");
    }
    phash2_input = phash2_input.chars().rev().collect();
    println!("phash2_input: {:?}", phash2_input);

    handle_emp_2pc_tls12_sha256(
        phash2_input.clone(),
        ipad_le.clone(),
        phash2_1_filename.clone()
    );

    let fs_phash2_1 = format!("{}{}", fs, phash2_1_filename);
    let mut fs_phash2_1 = fs::read_to_string(fs_phash2_1).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&fs_phash2_1.as_bytes()).unwrap();

    handle_2pc_hamc_expand(
        fs_phash2_1.clone(), 
        opad_le.clone(), 
        phash2_2_filename.clone()
    );

    let fs_phash2_2 = format!("{}{}", fs, phash2_2_filename);
    let mut phash2_2_le = fs::read_to_string(fs_phash2_2).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&phash2_2_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (P_hash[2]) ======");

    // For A3
    println!("====== Start: 2PC-HMAC (A3) ======");
    let mut a3_msg_be: String = a2_le.chars().rev().collect();
    while a3_msg_be.len() < 512 {
        a3_msg_be = format!("{}{}", a3_msg_be, "0");
    }
    println!("a3_msg_be: {:?}", a3_msg_be);
    let a3_msg_le: String = a3_msg_be.chars().rev().collect();

    handle_emp_2pc_tls12_expand(
        a3_msg_le.clone(),
        ipad_le.clone(), 
        opad_le.clone(), 
        a3_filename.clone()
    );

    let fs_a3 = format!("{}{}", fs, a3_filename);
    let mut a3_le = fs::read_to_string(fs_a3).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&a3_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (A3) ======");
    
    let phash1_2_v_be: String = phash1_2_le.chars().rev().collect();
    let phash2_2_v_be: String = phash2_2_le.chars().rev().collect();
    let phash_output_be: String = format!("{}{}", phash1_2_v_be, phash2_2_v_be);

    phash_output_be[0..384].to_string()
}

fn handle_tls12_cf_sf_recursive_hmac(
    listener: &TcpListener,
    key_ipad_filename: String,
    key_opad_filename: String,
    a1_filename: String,
    a2_filename: String,
    phash1_1_filename: String,
    phash1_2_filename: String,
) -> String {

    let fs: String = String::from(emp_path);

    let fs_ipad = format!("{}{}", fs, key_ipad_filename);
    let mut ipad_le = fs::read_to_string(fs_ipad).expect("failed reading");

    let fs_opad = format!("{}{}", fs, key_opad_filename);
    let mut opad_le = fs::read_to_string(fs_opad).expect("failed reading");

    // For A1
    println!("====== Start: 2PC-HMAC (A1) ======");
    handle_2pc_hamc_expand(
        ipad_le.clone(), 
        opad_le.clone(), 
        a1_filename.clone()
    );

    let fs_a1 = format!("{}{}", fs, a1_filename);
    let mut a1_le = fs::read_to_string(fs_a1).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&a1_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (A1) ======");

    // For P_hash[1]
    println!("====== Start: 2PC-HMAC (P_hash[1]) ======");
    let mut phash1_input = a1_le.clone();
    phash1_input = phash1_input.chars().rev().collect();
    while phash1_input.len() < 512 {
        phash1_input = format!("{}{}", phash1_input, "0");
    }
    phash1_input = phash1_input.chars().rev().collect();
    println!("phash1_input: {:?}", phash1_input);

    handle_emp_2pc_tls12_sha256(
        phash1_input.clone(),
        ipad_le.clone(),
        phash1_1_filename.clone()
    );

    let fs_phash1_1 = format!("{}{}", fs, phash1_1_filename);
    let mut phash1_1_le = fs::read_to_string(fs_phash1_1).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&phash1_1_le.as_bytes()).unwrap();

    handle_2pc_hamc_expand(
        phash1_1_le.clone(), 
        opad_le.clone(), 
        phash1_2_filename.clone()
    );

    let fs_phash1_2 = format!("{}{}", fs, phash1_2_filename);
    let mut phash1_2_le = fs::read_to_string(fs_phash1_2).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&phash1_2_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (P_hash[1]) ======");

    // For A2
    println!("====== Start: 2PC-HMAC (A2) ======");
    let mut a2_msg_be: String = a1_le.chars().rev().collect();
    while a2_msg_be.len() < 512 {
        a2_msg_be = format!("{}{}", a2_msg_be, "0");
    }
    println!("a2_msg_be: {:?}", a2_msg_be);
    let a2_msg_le: String = a2_msg_be.chars().rev().collect();

    handle_emp_2pc_tls12_expand(
        a2_msg_le.clone(),
        ipad_le.clone(), 
        opad_le.clone(), 
        a2_filename.clone()
    );

    let fs_a2 = format!("{}{}", fs, a2_filename);
    let mut a2_le = fs::read_to_string(fs_a2).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&a2_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (A2) ======");

    let phash1_2_v_be: String = phash1_2_le.chars().rev().collect();
    phash1_2_v_be[0..96].to_string()
}

fn handle_ems_s1s2sum_ipad_opad_curve25519(
    listener: &TcpListener,
    key_le: String,
    output_ipad_file_name: String,
    output_opad_file_name: String
) {

    // 1. Reverse key_le to big endian
    // 2. Reverse key_be by bytes
    // 3. Padding with 0s
    // 4. Do 2PC-HMAC with little endian

    let fs: String = String::from(emp_path);

    // input with little endian s2 as key_le

    // 1. Reverse key_le to big endian
    let mut key_be: String = key_le.chars().rev().collect();
    println!("key_be: {:?}", key_be);

    // 2. Reverse key_be by bytes
    let mut test_sum: String = key_be.clone();
    let mut test_sum_byte = String::new();
    for i in 0..32 {
        let ss: String = test_sum.chars().skip(i*8).take(8).collect();
        test_sum_byte = format!("{}{}", ss, test_sum_byte);
    }
    println!("test_sum_byte: {:?}", test_sum_byte);

    // 3. Padding with 0s
    let mut key_be: String = test_sum_byte.clone();
    for i in 0..256 {
        key_be = format!("{}{}", key_be, "0");
    }
    let mut key_le: String = key_be.chars().rev().collect();

    // 4. Do 2PC-HMAC with little endian
    println!("====== Start: 2PC-HMAC (ipad) ======");
    call_emp_2pc_hmac_key_iopad(key_le.clone(), output_ipad_file_name.clone());
    let fs_ipad = format!("{}{}", fs, output_ipad_file_name);
    let mut ipad_le = fs::read_to_string(fs_ipad).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&ipad_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (ipad) ======");

    println!("====== Start: 2PC-HMAC (opad) ======");
    call_emp_2pc_hmac_key_iopad(key_le.clone(), output_opad_file_name.clone());
    let fs_opad = format!("{}{}", fs, output_opad_file_name);
    let mut opad_le = fs::read_to_string(fs_opad).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&opad_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (opad) ======");
}

fn handle_ems_s1s2sum_ipad_opad_secp256r1(
    listener: &TcpListener,
    key_le: String,
    output_ipad_file_name: String,
    output_opad_file_name: String
) {

    // 1. Reverse key_le to big endian
    // 2. Padding with 0s
    // 3. Do 2PC-HMAC with little endian

    let fs: String = String::from(emp_path);

    // input with little endian s2 as key_le

    // 1. Reverse key_le to big endian
    let mut key_be: String = key_le.chars().rev().collect();
    println!("key_be: {:?}", key_be);

    // 2. Padding with 0s
    // let mut key_be: String = test_sum_byte.clone();
    for i in 0..256 {
        key_be = format!("{}{}", key_be, "0");
    }
    let mut key_le: String = key_be.chars().rev().collect();

    // 3. Do 2PC-HMAC with little endian
    println!("====== Start: 2PC-HMAC (ipad) ======");
    call_emp_2pc_hmac_key_iopad(key_le.clone(), output_ipad_file_name.clone());
    let fs_ipad = format!("{}{}", fs, output_ipad_file_name);
    let mut ipad_le = fs::read_to_string(fs_ipad).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&ipad_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (ipad) ======");

    println!("====== Start: 2PC-HMAC (opad) ======");
    call_emp_2pc_hmac_key_iopad(key_le.clone(), output_opad_file_name.clone());
    let fs_opad = format!("{}{}", fs, output_opad_file_name);
    let mut opad_le = fs::read_to_string(fs_opad).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&opad_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (opad) ======");
}

fn handle_ke_key_ipad_opad(
    listener: &TcpListener,
    ems_phash1_2_filename: String,
    ems_phash2_2_filename: String,
    output_ipad_file_name: String,
    output_opad_file_name: String
) {

    let fs: String = String::from(emp_path);

    // 1. Type conversion with padding of zeros
    let fs_phash1_2 = format!("{}{}", fs, ems_phash1_2_filename.clone());
    let mut ems_phash1_2_v_le = fs::read_to_string(fs_phash1_2).expect("failed reading");
    println!("ems_phash1_2_v_le: {:?}", ems_phash1_2_v_le);

    let fs_phash2_2 = format!("{}{}", fs, ems_phash2_2_filename.clone());
    let mut ems_phash2_2_v_le = fs::read_to_string(fs_phash2_2).expect("failed reading");
    println!("ems_phash2_2_v_le: {:?}", ems_phash2_2_v_le);

    let ems_phash1_2_v_be: String = ems_phash1_2_v_le.chars().rev().collect();
    let ems_phash2_2_v_be: String = ems_phash2_2_v_le.chars().rev().collect();

    let mut ke_key_be = format!("{}{}", ems_phash1_2_v_be, ems_phash2_2_v_be);
    ke_key_be = ke_key_be[0..384].to_string();
    while ke_key_be.len() < 512 {
        ke_key_be = format!("{}{}", ke_key_be, "0");
    }

    let ke_key_le: String = ke_key_be.chars().rev().collect();
    
    println!("====== Start: 2PC-HMAC (ipad) ======");
    call_emp_2pc_hmac_key_iopad(ke_key_le.clone(), output_ipad_file_name.clone());
    let fs_ipad = format!("{}{}", fs, output_ipad_file_name);
    let mut ipad_le = fs::read_to_string(fs_ipad).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&ipad_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (ipad) ======");

    println!("====== Start: 2PC-HMAC (opad) ======");
    call_emp_2pc_hmac_key_iopad(ke_key_le.clone(), output_opad_file_name.clone());
    let fs_opad = format!("{}{}", fs, output_opad_file_name);
    let mut opad_le = fs::read_to_string(fs_opad).expect("failed reading");

    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&opad_le.as_bytes()).unwrap();
    println!("====== End: 2PC-HMAC (opad) ======");
}

fn handle_dHS_MS_ipad_opad(
    listener: &TcpListener,
    input_file_name: String,
    output_ipad_file_name: String,
    output_opad_file_name: String,
) {
    let fs: String = String::from(emp_path);
    
    let fs_share = format!("{}{}", fs, input_file_name);
    let mut share = fs::read_to_string(fs_share).expect("failed reading");
    let mut share_be: String = share.chars().rev().collect();
    for i in 0..256 {
        share_be = format!("{}{}", share_be, "0");
    }
    let mut share_le: String = share_be.chars().rev().collect();

    call_emp_2pc_hmac_key_iopad(share_le.clone(), output_ipad_file_name.clone());
    let fs_ipad = format!("{}{}", fs, output_ipad_file_name);
    let mut ipad_le = fs::read_to_string(fs_ipad).expect("failed reading");

    call_emp_2pc_hmac_key_iopad(share_le.clone(), output_opad_file_name.clone());
    let fs_opad = format!("{}{}", fs, output_opad_file_name);
    let mut opad_le = fs::read_to_string(fs_opad).expect("failed reading");
}

fn handle_CHTS_CATS_EMS_ipad_opad(
    listener: &TcpListener,
    input_file_name: String,
    output_ipad_file_name: String,
    output_opad_file_name: String,
) {
    let fs: String = String::from(emp_path);
    
    let fs_share = format!("{}{}", fs, input_file_name);
    let mut share = fs::read_to_string(fs_share).expect("failed reading");
    let mut share_be: String = share.chars().rev().collect();
    for i in 0..256 {
        share_be = format!("{}{}", share_be, "0");
    }
    let mut share_le: String = share_be.chars().rev().collect();

    call_emp_2pc_hmac_key_iopad(share_le.clone(), output_ipad_file_name.clone());
    let fs_ipad = format!("{}{}", fs, output_ipad_file_name);
    let mut ipad_le = fs::read_to_string(fs_ipad).expect("failed reading");
    
    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    stream.write(&ipad_le.as_bytes()).unwrap();

    call_emp_2pc_hmac_key_iopad(share_le.clone(), output_opad_file_name.clone());
    let fs_opad = format!("{}{}", fs, output_opad_file_name);
    let mut opad_le = fs::read_to_string(fs_opad).expect("failed reading");

    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    stream.write(&opad_le.as_bytes()).unwrap();
}

fn handle_SATS_ipad_opad(
    listener: &TcpListener,
    input_file_name: String,
    output_ipad_file_name: String,
    output_opad_file_name: String,
) -> ring::hmac::Key {

    let (my_ip_port, target_ip, target_ip_port) = get_ip();

    let fs: String = String::from(emp_path);
    
    let fs_share = format!("{}{}", fs, input_file_name);
    let mut share = fs::read_to_string(fs_share).expect("failed reading");
    let mut share_be: String = share.chars().rev().collect();
    for i in 0..256 {
        share_be = format!("{}{}", share_be, "0");
    }
    let mut share_le: String = share_be.chars().rev().collect();

    call_emp_2pc_hmac_key_iopad(share_le.clone(), output_ipad_file_name.clone());
    let fs_ipad = format!("{}{}", fs, output_ipad_file_name);
    let mut key_ipad_le_v = fs::read_to_string(fs_ipad).expect("failed reading");
    
    // let mut stream = TcpStreamNet::connect(TARGET_IP_ADDRESS_WITH_PORT).unwrap();
    let mut stream = TcpStreamNet::connect(&target_ip_port.as_str()).unwrap();
    let key_ipad_le_c = get_share(&stream);
    // println!("CHECK key_ipad_le_c: {}", key_ipad_le_c);
    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&ipad_le.as_bytes()).unwrap();

    call_emp_2pc_hmac_key_iopad(share_le.clone(), output_opad_file_name.clone());
    let fs_opad = format!("{}{}", fs, output_opad_file_name);
    let mut key_opad_le_v = fs::read_to_string(fs_opad).expect("failed reading");

    // let mut stream = TcpStreamNet::connect(TARGET_IP_ADDRESS_WITH_PORT).unwrap();
    let mut stream = TcpStreamNet::connect(&target_ip_port.as_str()).unwrap();
    let key_opad_le_c = get_share(&stream);
    // println!("CHECK key_opad_le_c: {}", key_opad_le_c);
    // let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    // stream.write(&opad_le.as_bytes()).unwrap();

    let key_ipad_le = string_xor(key_ipad_le_c, key_ipad_le_v);
    let key_opad_le = string_xor(key_opad_le_c, key_opad_le_v);

    let key_ipad_be: String = key_ipad_le.chars().rev().collect();
    let key_opad_be: String = key_opad_le.chars().rev().collect();

    ring::hmac::be_bin_to_key(key_ipad_be, key_opad_be, ring::hmac::HMAC_SHA256)
}

fn handle_2pc_hmac_msg_verifier(s2: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let (my_ip_port, target_ip, target_ip_port) = get_ip();

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_hmac_hs_msg_verifier.sh")
                            .arg(s2)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("hello verifier, 2PC-HMAC for shared message!");
}

fn call_emp_2pc_hmac_key_iopad(input: String, output: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let (my_ip_port, target_ip, target_ip_port) = get_ip();

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_hmac_key_iopad_verifier.sh")
                            .arg(input)
                            .arg(output)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("hello verifier, 2PC-HMAC for shared key with padding!");
}

// [DECO] 
pub fn call_emp_2pc_tls12_ems_s1s2sum(input: String, output_filename: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let (my_ip_port, target_ip, target_ip_port) = get_ip();

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_tls12_ems_s1s2sum.sh")
                            .arg(input)
                            .arg(output_filename)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("hello client, 2PC-HMAC for shared message!");
}

// [DECO] 
pub fn call_emp_2pc_tls12_ems_s1s2sum_secp256r1(input: String, output_filename: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let (my_ip_port, target_ip, target_ip_port) = get_ip();

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_tls12_ems_s1s2sum_secp256r1.sh")
                            .arg(input)
                            .arg(output_filename)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("hello client, 2PC-HMAC for shared message!");
}

// [DECO] 
pub fn call_emp_2pc_tls12_ems_s1s2sum_iopad(input: String, output_filename: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let (my_ip_port, target_ip, target_ip_port) = get_ip();

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_tls12_ems_s1s2sum_iopad.sh")
                            .arg(input)
                            .arg(output_filename)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("hello client, 2PC-HMAC for shared message!");
}

// [DECO]
fn handle_emp_2pc_tls12_sha256(msg: String, state: String, output: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let (my_ip_port, target_ip, target_ip_port) = get_ip();

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
fn handle_emp_2pc_tls12_expand(msg: String, ipad_state: String, opad_state: String, output: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let (my_ip_port, target_ip, target_ip_port) = get_ip();

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

fn handle_2pc_make_emp() {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let (my_ip_port, target_ip, target_ip_port) = get_ip();

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_make_emp.sh")
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("Make emp!");
}

fn handle_2pc_hamc_expand(x_ipad: String, x_opad: String, output: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let (my_ip_port, target_ip, target_ip_port) = get_ip();

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_hmac_expand_verifier.sh")
                            .arg(x_ipad)
                            .arg(x_opad)
                            .arg(output)
                            .arg(target_ip)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("Make emp!");
}

// [DECO]
pub fn get_share(mut stream: &TcpStreamNet) -> String {
    let mut buf = [0; 10000];
    let read_bytes = stream.read(&mut buf).unwrap();
    let vs_bit: Vec<u8> = buf[..read_bytes].to_vec();
    let mut vs = String::new();
    for i in 0..vs_bit.len() {
        vs = format!("{}{}", vs, (vs_bit[i]-48).to_string());
    }
    vs
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

pub fn get_ip() -> (String, String, String) {

    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let mut my_ip_port = args.flag_verifierip.trim().to_string() + ":" + &args.flag_verifierport.trim().to_string();
    let mut target_ip = args.flag_clientip.clone().trim().to_string();
    let mut target_ip_port = args.flag_clientip.trim().to_string() + ":" + &args.flag_clientport.trim().to_string();

    (
        my_ip_port,
        target_ip,
        target_ip_port
    )
}

fn main() {

    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
    // println!("{:?}", args); 

    let my_ip_port = args.flag_verifierip + ":" + &args.flag_verifierport;
    // let listener = TcpListener::bind(MY_IP_ADDRESS_WITH_PORT).unwrap();
    let listener = TcpListener::bind(&my_ip_port).unwrap();
    
    // handle_2pc_make_emp();

    // Check if the target is the same as client
    let mut stream = listener.incoming().next().unwrap().expect("failed"); 
    let client_hostname = get_payload(&stream);
    
    if client_hostname != String::from(args.arg_hostname).as_bytes().to_vec() {
        println!("Not a matched target with client!");
        println!("Terminating...");

        let signal_to_client: Vec<u8> = String::from("Halt").as_bytes().to_vec();
        stream.write(&signal_to_client).unwrap();

        return;
    }
    else {
        let signal_to_client: Vec<u8> = String::from("Continue").as_bytes().to_vec();
        stream.write(&signal_to_client).unwrap();
    }

    main_in_verifier(&listener);

}

//0000000000000000000000000000000011111111111111111111111111111110111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001