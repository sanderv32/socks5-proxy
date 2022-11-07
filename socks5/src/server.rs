#![allow(dead_code)]

use async_std::io;
use async_std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use async_std::net::{TcpStream, UdpSocket};
use async_std::prelude::*;
use async_std::sync::{Arc, Mutex};
use async_std::task;
use bytes::{Buf, BufMut};
use cidr_utils::cidr::{Ipv4Cidr, Ipv6Cidr};
use std::collections::HashSet;
use std::time::Duration;
use std::{net::Shutdown, str::FromStr};

use trust_dns_resolver::Resolver;

use crate::{config::RuleType, Config};

lazy_static! {
    static ref HASHSET: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

enum Host {
    Name(String),
    Ip(IpAddr),
    None,
}

impl ToString for Host {
    fn to_string(&self) -> String {
        match self {
            Host::Name(e) => e.to_string(),
            Host::Ip(e) => e.to_string(),
            Host::None => "None".to_string(),
        }
    }
}

#[derive(Copy, Clone)]
pub struct Socks5 {}

impl Socks5 {
    // start from ATYPE, then ADDRESS and PORT
    fn socket_addr_to_vec(socket_addr: std::net::SocketAddr) -> Vec<u8> {
        let mut res = Vec::new();
        let ip_bytes = match socket_addr.ip() {
            IpAddr::V4(ip) => {
                res.push(0x01);
                ip.octets().to_vec()
            }
            IpAddr::V6(ip) => {
                res.push(0x04);
                ip.octets().to_vec()
            }
        };
        for val in ip_bytes.iter() {
            res.push(*val);
        }
        res.put_u16(socket_addr.port());
        res
    }

    //    fn allow(peer: std::net::IpAddr, rules: Vec<RuleType>) -> io::Result<()> {
    fn allow(peer: Host, rules: Vec<RuleType>) -> io::Result<()> {
        let allowed_ip = match &peer {
            Host::Ip(e) => match e {
                IpAddr::V4(a) => rules.iter().filter(|i| i.is_cidr()).any(|i| {
                    match Ipv4Cidr::from_str(i.to_string()) {
                        Ok(e) => e.contains(a),
                        Err(_e) => {
                            log::error!("Unable to convert ipv4 CIDR to string");
                            false
                        }
                    }
                }),
                IpAddr::V6(a) => rules.iter().filter(|i| i.is_cidr()).any(|i| {
                    let addr = i.to_string().replace(['[', ']'], "");
                    match Ipv6Cidr::from_str(addr) {
                        Ok(e) => e.contains(a),
                        Err(_e) => {
                            log::error!("Unable to convert ipv6 CIDR to string");
                            false
                        }
                    }
                }),
            },
            Host::Name(e) => {
                let resolver = Resolver::from_system_conf().unwrap();
                let addr = IpAddr::from(*resolver.ipv4_lookup(e).unwrap().iter().next().unwrap());
                rules
                    .iter()
                    .filter(|i| i.is_hostname())
                    .any(|a| a.to_string() == *e)
                    || Self::allow(Host::Ip(addr), rules).is_ok()
            }
            Host::None => false,
        };

        if !allowed_ip {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!("Filter: connection denied [{}]", peer.to_string()),
            ));
        }

        Ok(())
    }

    pub async fn process(stream: TcpStream, addr: String, config: Arc<Config>) -> io::Result<()> {
        let config = config.clone();
        let peer_addr = stream.peer_addr().unwrap();
        log::debug!("Accepted from: {}", peer_addr);

        Self::allow(Host::Ip(peer_addr.ip()), config.get_ingress())?;

        let mut reader = stream.clone();
        let mut writer = stream;

        // read socks5 header
        let mut buffer = vec![0u8; 512];
        reader.read_exact(&mut buffer[0..2]).await?;
        if buffer[0] != 0x05 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "only socks5 protocol is supported!",
            )); // stream will be closed automaticly
        }
        let methods = buffer[1] as usize;
        reader.read_exact(&mut buffer[0..methods]).await?;
        let mut has_no_auth = false;
        for item in buffer.iter().take(methods) {
            if *item == 0x00 {
                has_no_auth = true;
            }
        }

        if !has_no_auth {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "only no-auth is supported!",
            )); // stream will be closed automaticly
        }

        // server send to client accepted auth method (0x00 no-auth only yet)
        writer.write(&[0x05u8, 0x00]).await?;
        writer.flush().await?;

        // read socks5 cmd
        reader.read_exact(&mut buffer[0..4]).await?;
        let cmd = buffer[1]; // support 0x01(CONNECT) and 0x03(UDP Associate)
        let atype = buffer[3];

        let mut addr_port = String::from("");
        let mut ip_addr: Host = Host::None;
        let mut flag_addr_ok = true;

        // parse addr and port first
        match atype {
            0x01 => {
                // ipv4: 4bytes + port
                reader.read_exact(&mut buffer[0..6]).await?;
                let mut tmp_array: [u8; 4] = Default::default();
                tmp_array.copy_from_slice(&buffer[0..4]);
                let v4addr = Ipv4Addr::from(tmp_array);
                let port: u16 = buffer[4..6].as_ref().get_u16();
                let socket = SocketAddrV4::new(v4addr, port);
                addr_port = format!("{}", socket);
                ip_addr = Host::Ip(v4addr.into());
                // println!("ipv4: {}", addr_port);
            }
            0x03 => {
                reader.read_exact(&mut buffer[0..1]).await?;
                let len = buffer[0] as usize;
                reader.read_exact(&mut buffer[0..len + 2]).await?;
                let port: u16 = buffer[len..len + 2].as_ref().get_u16();
                if let Ok(addr) = std::str::from_utf8(&buffer[0..len]) {
                    addr_port = format!("{}:{}", &addr, port);
                    if IpAddr::from_str(addr).is_err() {
                        ip_addr = Host::Name(addr.to_string());
                    } else {
                        ip_addr = Host::Ip(IpAddr::from_str(addr).unwrap());
                    }
                } else {
                    flag_addr_ok = false;
                }
            }
            0x04 => {
                // ipv6: 16bytes + port
                reader.read_exact(&mut buffer[0..18]).await?;
                let mut tmp_array: [u8; 16] = Default::default();
                tmp_array.copy_from_slice(&buffer[0..16]);
                let v6addr = Ipv6Addr::from(tmp_array);
                let port: u16 = buffer[16..18].as_ref().get_u16();
                let socket = SocketAddrV6::new(v6addr, port, 0, 0);
                addr_port = format!("{}", socket);
                ip_addr = Host::Ip(v6addr.into());
            }
            _ => {
                flag_addr_ok = false;
            }
        }
        if !flag_addr_ok {
            writer
                .write(&[0x05u8, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "address is not valid!".to_string(),
            ));
        }

        Self::allow(ip_addr, config.get_egress())?;

        // parse cmd: support CONNECT(0x01) and UDP (0x03) currently
        match cmd {
            0x01 => {
                //create connection to remote server
                if let Ok(remote_stream) = TcpStream::connect(addr_port.as_str()).await {
                    log::debug!("connect to {} ok", addr_port);
                    writer
                        .write(&[0x05u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                        .await?;
                    let mut remote_read = remote_stream.clone();
                    let mut remote_write = remote_stream;
                    task::spawn(async move {
                        match io::copy(&mut reader, &mut remote_write).await {
                            Ok(_) => {}
                            Err(e) => {
                                log::error!("broken pipe: {}", e);
                            }
                        }
                        task::sleep(Duration::from_secs(30)).await;
                        let _ = reader.shutdown(Shutdown::Both);
                        let _ = remote_write.shutdown(Shutdown::Both);
                    });
                    match io::copy(&mut remote_read, &mut writer).await {
                        Ok(_) => {}
                        Err(e) => log::error!("Broken Pipe: {}", e),
                    };
                    task::sleep(Duration::from_secs(30)).await;
                    remote_read.shutdown(Shutdown::Both)?;
                    writer.shutdown(Shutdown::Both)?
                } else {
                    writer
                        .write(&[0x05u8, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                        .await?;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        format!("cannot make connection to {}!", addr_port),
                    )); // stream will be closed automaticly
                };
            }
            0x03 => {
                // UDP Associate
                log::debug!("start udp associate for {}", peer_addr);
                let raw_socket = UdpSocket::bind(format!("{}:0", addr)).await?;
                let socket = Arc::new(raw_socket);
                let socket_addr = socket.local_addr();

                let mut addr_port = String::from("");

                match socket_addr {
                    Ok(addr) => {
                        writer.write(&[0x05u8, 0x00, 0x00]).await?;

                        let content = Self::socket_addr_to_vec(addr);
                        writer.write(&content).await?;

                        HASHSET.lock().await.insert(peer_addr.to_string());

                        task::spawn(async move {
                            let mut buf = vec![0u8; 1];

                            // close connection if we read more bytes
                            if let Err(e) = reader.read_exact(&mut buf[0..1]).await {
                                log::debug!("Error while reading - {}", e);
                            }
                            HASHSET.lock().await.remove(&peer_addr.to_string());
                            log::debug!("udp-tcp disconnect from {}", peer_addr);
                        });

                        //start to transfer data
                        //recv first packet
                        let mut buf = vec![0u8; 2048];
                        let (mut n, local_peer) = socket.recv_from(&mut buf).await?;

                        let socket_remote_raw = UdpSocket::bind("0.0.0.0:0").await?;
                        let socket_remote_reader = Arc::new(socket_remote_raw);
                        let socket_remote_writer = socket_remote_reader.clone();
                        let local_socket_writer = socket.clone();
                        task::spawn(async move {
                            let mut buf = vec![0u8; 2048];

                            loop {
                                if HASHSET.lock().await.contains(&peer_addr.to_string()) {
                                    let res = io::timeout(Duration::from_secs(5), async {
                                        socket_remote_reader.recv_from(&mut buf).await
                                    })
                                    .await;
                                    match res {
                                        Ok((n, remote_addr)) => {
                                            let mut write_packet = vec![0x0u8, 0, 0];

                                            let content = Self::socket_addr_to_vec(remote_addr);
                                            for val in content.iter() {
                                                write_packet.push(*val);
                                            }
                                            for val in buf[0..n].iter() {
                                                write_packet.push(*val);
                                            }
                                            // write the udp packet at once
                                            let _ = local_socket_writer
                                                .send_to(&write_packet, local_peer)
                                                .await;
                                        }
                                        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                                            log::error!("timeout {:?}", e.kind());
                                        }
                                        Err(e) => {
                                            HASHSET.lock().await.remove(&peer_addr.to_string());
                                            log::error!("error read udp from remote: {}", e);
                                        }
                                    }
                                } else {
                                    break;
                                }
                            }
                        });
                        loop {
                            if HASHSET.lock().await.contains(&peer_addr.to_string()) {
                                if n > 4 {
                                    let mut addr_is_ok = true;
                                    //processing receved packet from client
                                    if buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {
                                        let mut idx = 0usize;
                                        match buf[3] {
                                            0x01 => {
                                                if n < 4 + 4 + 2 {
                                                    addr_is_ok = false;
                                                } else {
                                                    let mut tmp_array: [u8; 4] = Default::default();
                                                    tmp_array.copy_from_slice(&buf[4..8]);
                                                    let v4addr = Ipv4Addr::from(tmp_array);
                                                    let port: u16 = buf[8..10].as_ref().get_u16();
                                                    let socket = SocketAddrV4::new(v4addr, port);
                                                    addr_port = format!("{}", socket);
                                                    idx = 10;
                                                    // println!("ipv4: {}", addr_port);
                                                }
                                            }
                                            0x03 => {
                                                let len = buf[4] as usize;
                                                if n < 4 + len + 2 {
                                                    addr_is_ok = false;
                                                } else {
                                                    let port: u16 = buf[5 + len..5 + 2 + len]
                                                        .as_ref()
                                                        .get_u16();
                                                    if let Ok(addr) =
                                                        std::str::from_utf8(&buf[5..5 + len])
                                                    {
                                                        addr_port = format!("{}:{}", addr, port);
                                                        idx = 5 + 2 + len;
                                                    } else {
                                                        addr_is_ok = false;
                                                    }
                                                }
                                            }
                                            0x04 => {
                                                if n < 4 + 16 + 2 {
                                                    addr_is_ok = false;
                                                } else {
                                                    // ipv6: 16bytes + port
                                                    let mut tmp_array: [u8; 16] =
                                                        Default::default();
                                                    tmp_array.copy_from_slice(&buf[4..20]);
                                                    let v6addr = Ipv6Addr::from(tmp_array);
                                                    let port: u16 = buf[20..22].as_ref().get_u16();
                                                    let socket =
                                                        SocketAddrV6::new(v6addr, port, 0, 0);
                                                    addr_port = format!("{}", socket);
                                                    idx = 22;
                                                }
                                            }
                                            _ => {}
                                        }
                                        if addr_is_ok {
                                            log::debug!(
                                                "send UDP to {} for {}",
                                                addr_port,
                                                peer_addr
                                            );
                                            let _ = socket_remote_writer
                                                .send_to(&buf[idx..n], &addr_port)
                                                .await;
                                        } else {
                                            HASHSET.lock().await.remove(&peer_addr.to_string());
                                        }
                                    }
                                }
                                let read_res = io::timeout(Duration::from_secs(5), async {
                                    socket.recv_from(&mut buf).await
                                })
                                .await;
                                match read_res {
                                    Ok((nn, _)) => {
                                        n = nn;
                                    }
                                    Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                                        n = 0;
                                        log::error!("timeout {:?}", e.kind());
                                    }
                                    Err(_) => {
                                        HASHSET.lock().await.remove(&peer_addr.to_string());
                                    }
                                }
                            } else {
                                break;
                            }
                        }
                    }
                    Err(_) => {
                        writer
                            .write(&[0x05u8, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                            .await?;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            format!("udp listen port failed {}!", addr_port),
                        )); // stream will be closed automaticly
                    }
                }
            }
            _ => {
                writer
                    .write(&[0x05u8, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                    .await?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "command is not supported!",
                ));
            }
        }

        log::debug!("disconnect from {}", peer_addr);
        Ok(())
    }
}
