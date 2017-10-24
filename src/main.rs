// `error_chain!` can recurse deeply
#![recursion_limit = "1024"]

#[macro_use] extern crate error_chain;
extern crate futures;
extern crate openssl;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_openssl;
extern crate tokio_proto;
extern crate tokio_service;

use errors::*;
use futures::{Future, Stream};
use openssl::pkey::PKey;
use openssl::ssl::SslAcceptorBuilder;
use openssl::ssl::SslMethod;
use openssl::x509::{X509};
use std::fs::File;
use std::io::Read;
use tokio_core::net::TcpListener;
use tokio_core::reactor::Core;
use tokio_openssl::SslAcceptorExt;

mod errors {
    error_chain!{
        foreign_links {
            Io(::std::io::Error);
            Handshake(::openssl::ssl::HandshakeError<::std::net::TcpStream>);
            SslErrorStack(::openssl::error::ErrorStack);
            Ssl(::openssl::ssl::Error);
        }
    }
}

quick_main!(run);
fn run() -> Result<()> {

    let addr = "127.0.0.1:1234".parse().unwrap();
    let pkey_buf = {
        let mut buf = vec![];
        File::open("key.pem")?.read_to_end(&mut buf)?;
        buf
    };
    let cert_buf = {
        let mut buf = vec![];
        File::open("cert.pem")?.read_to_end(&mut buf)?;
        buf
    };
    let trusted_cert_buf = {
        let mut buf = vec![];
        File::open("trusted.pem")?.read_to_end(&mut buf)?;
        buf
    };

    let pkey = PKey::private_key_from_pem(&pkey_buf)?;
    let cert = X509::from_pem(&cert_buf)?;
    let trusted_cert = X509::from_pem(&trusted_cert_buf)?;

    let acceptor = SslAcceptorBuilder::mozilla_modern(SslMethod::tls(), &pkey, &cert, &[trusted_cert])?.build();

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let socket = TcpListener::bind(&addr, &handle).unwrap();

    println!("Listening on {}", addr);
    let done = socket.incoming().for_each(move |(socket, addr)| {
        println!("Got connection");

        let alphabet = acceptor.accept_async(socket)
            .map_err(Error::from)
            .and_then(|stream| {
                println!("Accepted TLS");
                ::tokio_io::io::read_exact(stream, [0u8; 8]).map_err(Error::from)
            });

        let check = alphabet.and_then(|(_stream, buf)| {
            println!("got 8 letters");
            if buf == *b"ABCDEFGH" {
                println!("got the alphabet!");
            }
            Ok(())
        })
        .map_err(move |err| println!("Error: {:?} - {}", err, addr));

        handle.spawn(check);
        Ok(())
    });

    core.run(done).unwrap();
    Ok(())
}
