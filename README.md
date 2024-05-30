# SOCKS5-proxy
A lightweight SOCKS5 proxy.

```text
USAGE:
    socks5-proxy [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --config <CONFIG>    config file
```

### Configuration file
```yaml
---
listen: 127.0.0.1:1080
ingress:
    - 0.0.0.0/0
    - mct-nas.cloud.lan
egress:
    - 0.0.0.0/0
    - www.google.com
```
Default rules are allow all if you don't specify a configuration file.

### Environment variables
The same keywords as in the TOML file are used in environment variables, just append `SOCKS5_` in front of it.

Example:
```bash
RUST_LOG="debug"
SOCKS5_LISTEN="127.0.0.1:1080"
SOCKS5_INGRESS="1.1.1.1/32,9.9.9.9/32"
```

### Included dependencies
This lightweight SOCKS5 proxy server includes `socks5` and `merge-rs` crates. The crate `socks5` is included because this has serveral modifications which is needed for this proxy server. Crate `merge-rs` is included because the crate from crates.io doesn't include the merge strategy `merge::option::overwrite_none` which we need.

### TODO
- Create PR for `socks5` crate
