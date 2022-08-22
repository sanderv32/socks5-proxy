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
                .env("CONFIG"),
        )
        .get_matches();

    let config = Arc::new(Config::load(matches.value_of("config").unwrap().to_string()).unwrap());

    log::debug!("Config:  {}", matches.value_of("config").unwrap());
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
                if let Err(e) = Socks5::process(stream, addr, cfg).await {
                    // We ignore "Socket not connected" errors for now
                    if e.raw_os_error() != Some(107) {
                        log::error!("Error: {}", e);
                    }
                }
            });
        }
        Ok(())
    })
}
