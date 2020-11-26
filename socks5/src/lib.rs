pub mod server;
pub mod config;

pub use self::{
    config::Config,
    server::Socks5,
};

#[macro_use] extern crate lazy_static;
