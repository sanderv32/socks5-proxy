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
```toml
---
listen: 127.0.0.1:1080
ingress:
    allow:
        - 0.0.0.0/0
        - mct-nas.cloud.lan
egress:
    allow:
        - 0.0.0.0/0
        - www.google.com
```
Default rules are allow all if you don't specify a configuration file.