extern crate serde_yaml;

use async_std::net::TcpListener;
use async_std::prelude::*;
use async_std::task;
use clap::{App, Arg};
use std::sync::Arc;

use socks5::{Config, Socks5};

fn main() -> std::io::Result<()> {
    env_logger::init();

    let matches = App::new("A lightweight and fast socks5 server written in Rust")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("CONFIG")
                .help("config file")
                .required(false)
                .takes_value(true)
                .default_value("socks5.conf")
        ).get_matches();

    let config = Arc::new(Config::load_from_file(matches
        .value_of("config").unwrap().to_string()
    ).unwrap());

    let _bla1 = config.get_ingress();
    let _bla2 = config.get_egress();

    log::debug!("Config:  {}", matches.value_of("config").unwrap());
    log::debug!("Listen:  {}", &config.listen);
    log::debug!("Ingress: {}", &config.ingress.allow.join(", "));
    log::debug!("Egress:  {}", &config.egress.allow.join(", "));

    let bind_str = config.listen.clone();
    let bind_addr = bind_str.split(":").nth(0).expect("127.0.0.1");

    task::block_on( async {    
        let listener = TcpListener::bind(&bind_str).await?;
        log::info!("Listening on {}", listener.local_addr()?);

        let mut incoming = listener.incoming();

        while let Some(stream) = incoming.next().await {
            let addr = bind_addr.to_string();
            let stream = stream?;

            let cfg = Arc::clone(&config);
            task::spawn(async {
                match Socks5::process(stream, addr, cfg).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("Error: {}", e);
                    }
                }
            });
        }
        Ok(())
    })
}
