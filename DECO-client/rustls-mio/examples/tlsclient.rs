use std::process;
use std::sync::{Arc, Mutex};

// use mio;
use mio::net::TcpStream;

// use std::sync::Arc;
use std::net::TcpStream as TcpStreamNet;
use std::io::Write as WriteNet;

use std::collections;
use std::convert::TryInto;
use std::fs;
use std::io;
use std::io::{BufReader, Read, Write};
use std::net::SocketAddr;
use std::str;

use env_logger;

#[macro_use]
extern crate serde_derive;

use docopt::Docopt;

use rustls;
use webpki_roots;

use rustls::{OwnedTrustAnchor, RootCertStore};

const CLIENT: mio::Token = mio::Token(0);

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
        // println!("locator in new() from rustls-mio/examples/tlsclient.rs");
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
            println!("\n=== assert ev.is_readable ===");
            self.do_read();
            // println!("after do_read");
        }

        if ev.is_writable() {
            println!("=== assert ev.is_writable===");
            self.do_write();
        }

        if self.is_closed() {
            println!("Connection closed [located in function ready() self.is_closed()");
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

        println!("Hi do_read");

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let io_state = match self.tls_conn.process_new_packets() {
            Ok(io_state) => {
                println!("After process_new_packets [OK]");
                // Since this function will be execute many times within a loop,
                // we need to take care all possibilities for the message.
                io_state
            },
            Err(err) => {
                println!("TLS error: {:?} [fail to process_new_packets]", err);
                main_client();
                self.closing = true;
                return;
            }
        };

        println!("io_state: {:?}", io_state);

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
            println!("\n>>>>>> io::stdout begin >>>>>>\n");
            // println!("plaintext: \n{:?}", &plaintext);
            io::stdout()
                .write_all(&plaintext)
                .unwrap();
            println!("\n<<<<<< io::stdout finish <<<<<<\n");
            
        }

        // If wethat fails, the peer might have started a clean TLS-level
        // session closure.
        if io_state.peer_has_closed() {
            self.clean_closure = true;
            self.closing = true;
            println!("=== iostate.peer_has_closed locator ===");
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
    --username USERNAME          The username.
    --password PASSWORD         The password.
    --curlfilename FILENAME       The filename for curl.
    --postfilename FILENAME       The filename for POST.
    --postshfilename FILENAME     The filename for POST string handling.
    --towngas-account-number ACNO   The account number of Towngas user.
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
    flag_verifierport: String,
    flag_username: String,
    flag_password: String,
    flag_curlfilename: String,
    flag_postfilename: String,
    flag_postshfilename: String,
    flag_towngas_account_number: String
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

// [DECO]
fn handle_2pc_make_emp() {

    let (my_ip_port, target_ip, target_ip_port) = rustls::get_ip();

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut child = Command::new("sh")
                            .arg("./rustls/src/2pc_make_emp.sh")
                            // .arg(crate::rustls::TARGET_IP)
                            .arg(&target_ip.as_str())
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("Make emp!");
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

/// Parse some arguments, then make a TLS client connection
/// somewhere.
pub fn main_client() {

    println!("\n************  RUSTLS-MIO main() BEGINS  ************\n");
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    // println!("tls_version = {}", &version); // output = 0.01

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

    let sock = TcpStream::connect(addr).unwrap();
    let server_name = args
        .arg_hostname
        .as_str()
        .try_into()
        .expect("invalid DNS name");
    let mut tlsclient = TlsClient::new(sock, server_name, config);

    

    // [DECO] Curl
    let mut req_string: String = String::new();
    if args.arg_hostname == "eservice.towngas.com" {

        let mut cookie: String = String::new();
        cookie = get_cookie();
        println!("{:?}", cookie);

        // req_string = format!(
        //     // "POST /NewsNotices/GetNewsNoticeAsyncNew HTTP/1.0\r\nHost: {}\r\nCookie: {}\r\nContent-Length: 20\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\naccountNo=3170005480",
        //     post_req.to_string(),
        //     args.arg_hostname,
        //     cookie
        // )

        // Get the POST request String
        handle_post_towngas(
            args.flag_postshfilename.trim().to_string(), 
            args.arg_hostname,
            cookie, 
            args.flag_towngas_account_number.trim().to_string()
        );
        let post_filename = format!("{}{}", "./rustls/src/post/", args.flag_postfilename);
        req_string = fs::read_to_string(post_filename).expect("failed reading");
        println!("req_string: {:?}", req_string);
    }
    else if args.arg_hostname == "services.clp.com.hk" {
        let mut cookie: String = String::new();
        cookie = get_cookie();
        println!("{:?}", cookie);
        // req_string = format!(
        //     "POST /Service/ServiceGetAccBaseInfoWithBillV2.ashx HTTP/1.1\r\nHost: {}\r\nhtml-lang: en\r\nx-csrftoken: f080d694d4ce4e09a5bc5dabc412daf4\r\norigin: https://services.clp.com.hk\r\nsec-fetch-site: same-origin\r\nsec-fetch-mode: cors\r\nsec-fetch-dest: empty\r\nreferer: https://services.clp.com.hk/en/dashboard/index.aspx\r\ncookie: _TrJa53u6G6UdJZLz_banner=nIpPgqYPNddBPZIsGZEYwy3ScdxdfyCP2M%2bSbkQBuCIWccH4aIBcSx8YZXEbuKrsIRqvkR9rDZqTC%2bj7WAvi7l%2bXwONQRbJX6Ss9%2bMDCJB%2foUrjrBtAU2Oxegk7VHcBe; __cfruid=80f3878002a0cac331a3d33a4206fcbc3df3cf02-1648621885; _gcl_au=1.1.1162346131.1648621887; s_fid=2D24ED317DDDA1ED-1074AE599F661584; s_cc=true; _uetsid=07f71cc0aff311ec9c6cc139d07997a4; _uetvid=07fa53c0aff311ec9dd7ad8907a12e2c; _ga=GA1.3.2113631785.1648621889; _gid=GA1.3.23136439.1648621889; _fbp=fb.2.1648621889382.287938445; _hjSessionUser_2304500=eyJpZCI6IjYzOWE2NWJmLWQ1NzUtNTE2ZC1iZGI1LTJmNWU3ODE5MTE2OSIsImNyZWF0ZWQiOjE2NDg2MjE4ODk5NjIsImV4aXN0aW5nIjpmYWxzZX0=; website#lang=en; K2Cie90hi___AntiXsrfToken=f080d694d4ce4e09a5bc5dabc412daf4; ARRAffinity=4ac8da8f677f0c8447fe184d1b1a24e0386c5e64351b4a5cd8290d896ff9a8d6; ARRAffinitySameSite=4ac8da8f677f0c8447fe184d1b1a24e0386c5e64351b4a5cd8290d896ff9a8d6; _ga=GA1.4.2113631785.1648621889; _gid=GA1.4.23136439.1648621889; ASP.NET_SessionId=ptxa0lcc4gqnve5wwkzzn10t; _gat_UA-68003422-2=1;{}\r\ncontent-length: 19\r\ncontent-type: application/x-www-form-urlencoded\r\n\r\nassCA=&genPdfFlag=X",
        //     args.arg_hostname,
        //     cookie
        // )
        // Get the POST request String
        handle_post_clp(
            args.flag_postshfilename.trim().to_string(), 
            args.arg_hostname,
            cookie
        );
        let post_filename = format!("{}{}", "./rustls/src/post/", args.flag_postfilename);
        req_string = fs::read_to_string(post_filename).expect("failed reading");
        println!("req_string: {:?}", req_string);
    }
    else if args.flag_postshfilename == "" {
        println!("HI");
        req_string = format!(
            "GET / HTTP/1.0\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
            args.arg_hostname
        );
    }
    else {
        // req_string = format!(
        //     "GET / HTTP/1.0\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
        //     args.arg_hostname
        // );

        let mut cookie: String = String::new();
        cookie = get_cookie();
        println!("{:?}", cookie);

        handle_post_clp(
            args.flag_postshfilename.trim().to_string(), 
            args.arg_hostname,
            cookie
        );
        let post_filename = format!("{}{}", "./rustls/src/post/", args.flag_postfilename);
        req_string = fs::read_to_string(post_filename).expect("failed reading");
        println!("req_string: {:?}", req_string);
    }
    
    if args.flag_http {
        let httpreq = req_string;
        // format!(
        //     // "GET / HTTP/1.0\r\nHost: {}\r\nConnection: \
        //     //                    close\r\nAccept-Encoding: identity\r\n\r\n",
        //     // args.arg_hostname
        //     "POST /NewsNotices/GetNewsNoticeAsyncNew HTTP/1.0\r\nHost: {}\r\nCookie: {}\r\nContent-Length: 20\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\naccountNo=3170005480",
        //     args.arg_hostname,
        //     cookie
        // );
        tlsclient
            .write_all(httpreq.as_bytes())
            .unwrap();
    } else {
        let mut stdin = io::stdin();
        tlsclient
            .read_source_to_end(&mut stdin)
            .unwrap();
    }

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(32);
    tlsclient.register(poll.registry());

    println!("\n************  RUSTLS-MIO before loop  ************\n");

    loop {
        poll.poll(&mut events, None).unwrap();

        for ev in events.iter() {
            println!("\n+++ into for ev in event +++");
            tlsclient.ready(&ev);
            tlsclient.reregister(poll.registry());
        }
    }
    // println!("\n************  RUSTLS-MIO main() ENDS  ************\n"); // unreachable

}

// [DECO] Curl
fn get_cookie() -> String {
    use std::fs::File;
    use std::io::prelude::*;

    let mut file_name = String::from("./rustls/src/cookie.txt");
    let mut contents = fs::read_to_string(file_name).expect("failed reading");
    let mut line_vec: Vec<&str> = contents.split("\n").collect();

    let mut cookie_vec: Vec<String> = Vec::new();
    for i in 4..line_vec.len()-1 {
        let mut line: Vec<&str> = line_vec[i].split("\t").collect();
        cookie_vec.push(format!("{}={}", String::from(line[5]), String::from(line[6])));
    }
    // println!("{:?}",cookie_vec);
    let mut output: String = String::from(cookie_vec[0].clone());
    for i in 1..cookie_vec.len() {
        output = format!("{};{}", output, cookie_vec[i]);
    }
    println!("{:?}", output);
    output
}

// [DECO] POST
fn handle_post_towngas(filename: String, hostname: String, cookie: String, acno: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut filename_with_path: String = String::from("./rustls/src/post/");
    filename_with_path = format!("{}{}", filename_with_path, filename);

    let mut child = Command::new("sh")
                            .arg(filename_with_path)
                            .arg(hostname)
                            .arg(cookie)
                            .arg(acno)
                            .spawn()
                            .expect("failed to execute process");

    println!("curl!");
    let output = child.wait_with_output();
}

// [DECO] POST
fn handle_post_clp(filename: String, hostname: String, cookie: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut filename_with_path: String = String::from("./rustls/src/post/");
    filename_with_path = format!("{}{}", filename_with_path, filename);

    let mut child = Command::new("sh")
                            .arg(filename_with_path)
                            .arg(hostname)
                            .arg(cookie)
                            .spawn()
                            .expect("failed to execute process");

    println!("curl!");
    let output = child.wait_with_output();
}

// [DECO] POST
fn handle_post(filename: String, hostname: String, cookie: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut filename_with_path: String = String::from("./rustls/src/post/");
    filename_with_path = format!("{}{}", filename_with_path, filename);

    let mut child = Command::new("sh")
                            .arg(filename_with_path)
                            .arg(hostname)
                            .arg(cookie)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("curl!");
}

// [DECO] Curl
fn handle_curl(filename: String, username: String, password: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut filename_with_path: String = String::from("./rustls/src/curl/");
    filename_with_path = format!("{}{}", filename_with_path, filename);

    let mut child = Command::new("sh")
                            .arg(filename_with_path)
                            .arg(username)
                            .arg(password)
                            .spawn()
                            .expect("failed to execute process");

    println!("curl!");
    let output = child.wait_with_output();
}

// [DECO] Curl
fn handle_curl_towngas(username: String, password: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    let mut child = Command::new("sh")
                            .arg("./rustls/src/curl/curl_towngas.sh")
                            .arg(username)
                            .arg(password)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("curl!");
}

// [DECO] Curl
fn handle_curl_clp(username: String, password: String) {

    use std::process::{Command, Stdio};
    use std::io::{self, Write};

    println!("{:?}", username);

    let mut child = Command::new("sh")
                            .arg("./rustls/src/curl/curl_clp.sh")
                            .arg(username)
                            .arg(password)
                            .spawn()
                            .expect("failed to execute process");

    let output = child.wait_with_output();
    println!("curl!");
}

fn get_payload(mut stream: &TcpStreamNet) 
->  Vec<u8> {
    use std::io::Read;
    // println!("address: {:?}", stream.local_addr().unwrap());
    let mut buf = [0; 16]; 
    let read_bytes = stream.read(&mut buf).unwrap(); 
    buf[..read_bytes].to_vec()
}

fn handle_ip() {

    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    use std::env;
    use std::fs::File;
    use std::io::Write;

    let mut my_ip_port_fs = File::create("./rustls/src/ip/my_ip_with_port.txt").unwrap();
    let mut target_ip_fs = File::create("./rustls/src/ip/target_ip.txt").unwrap();
    let mut target_ip_port_fs = File::create("./rustls/src/ip/target_ip_with_port.txt").unwrap();

    let my_ip_port = args.flag_clientip + ":" + &args.flag_clientport;
    writeln!(my_ip_port_fs, "{}", my_ip_port).expect("Unable to write file");

    let target_ip = args.flag_verifierip.clone();
    let target_ip_port = args.flag_verifierip + ":" + &args.flag_verifierport;
    writeln!(target_ip_fs, "{}", target_ip).expect("Unable to write file");
    writeln!(target_ip_port_fs, "{}", target_ip_port).expect("Unable to write file");

}

fn main() {
    // [DECO]
    // handle_2pc_make_emp();

    // IP handling
    handle_ip();

    // Argument list
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    // Tell verifier the target
    let (my_ip_port, target_ip, target_ip_port) = rustls::get_ip();
    let signal_to_verifier: Vec<u8> = String::from(args.arg_hostname.clone()).as_bytes().to_vec();
    let mut stream = TcpStreamNet::connect(&target_ip_port).unwrap();
    stream.write(&signal_to_verifier).unwrap();

    let client_message = get_payload(&stream);
    if client_message == String::from("Halt").as_bytes().to_vec() {
        println!(
            "Please input the correct hostname! You wrote {:?} which is not matched with the verifier...", 
            args.arg_hostname.clone()
        );
        println!("Terminating...");
        return;
    }

    // Cookie handling
    handle_curl(
        args.flag_curlfilename.trim().to_string(), 
        args.flag_username.trim().to_string(), 
        args.flag_password.trim().to_string()
    );

    // println!("args.flag_password.trim().to_string(): {:?}", args.flag_password.trim().to_string());
    // if args.arg_hostname == "eservice.towngas.com" {
    //     handle_curl_towngas(args.flag_username.trim().to_string(), args.flag_password.trim().to_string());
    // }
    // else if args.arg_hostname == "services.clp.com.hk" {
    //     handle_curl_clp(args.flag_username.trim().to_string(), args.flag_password.trim().to_string());
    // }
    // handle_curl();
    // get_cookie();

    // [DECO]
    main_client();
}