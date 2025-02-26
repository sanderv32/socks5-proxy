extern crate serde_yaml;

use async_std::net::TcpListener;
use async_std::prelude::*;
use async_std::task;
use clap::{Arg, Command};
use std::sync::Arc;

use socks5::{Config, Socks5};

fn main() -> std::io::Result<()> {
    env_logger::init();

    let matches = Command::new("A lightweight and fast socks5 server written in Rust")
        .version(concat!(env!("CARGO_PKG_VERSION"), '+', env!("GIT_HASH")))
        .author(env!("CARGO_PKG_AUTHORS"))
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("CONFIG")
                .help("config file")
                .required(false)
                .default_value("socks5.conf")
                .env("CONFIG"),
        )
        .get_matches();

    let config =
        Arc::new(Config::load(matches.get_one::<String>("config").unwrap().to_string()).unwrap());

    log::debug!("Config:  {}", matches.get_one::<String>("config").unwrap());
    log::debug!("Listen:  {}", &config.listen.as_ref().unwrap());
    log::debug!("Ingress: {}", &config.ingress.as_ref().unwrap().join(", "));
    log::debug!("Egress:  {}", &config.egress.as_ref().unwrap().join(", "));

    let bind_str = config.listen.as_ref().unwrap().clone();
    let bind_addr = bind_str.split(':').next().expect("127.0.0.1");

    task::block_on(async {
        let listener = TcpListener::bind(&bind_str).await?;
        log::info!("Listening on {}", listener.local_addr()?);

        let mut incoming = listener.incoming();

        while let Some(stream) = incoming.next().await {
            let addr = bind_addr.to_string();
            let stream = stream?;

            let cfg = Arc::clone(&config);
            task::spawn(async {
                let peer_addr = &stream.peer_addr().ok();
                if peer_addr.is_some() {
                    if let Err(e) = Socks5::process(stream, addr, cfg).await {
                        match e.kind() {
                            std::io::ErrorKind::NotConnected => {
                                log::error!("Not connected to {}", peer_addr.unwrap())
                            }
                            _ => log::error!("Error: {}", e),
                        }
                    }
                }
            });
        }
        Ok(())
    })
}
