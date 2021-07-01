#![allow(unused_macros)]

extern crate serde_yaml;

use std::fs::File;
use anyhow::Context;
use cidr_utils::cidr::IpCidr;
use serde::Deserialize;
use merge::Merge;

const LISTEN: &'static str = "127.0.0.1:1080";
const ALLOW_ALL: &'static str = "0.0.0.0/0";

#[derive(PartialEq, Eq, Debug)]
pub enum RuleType {
    Hostname(String),
    CIDR(IpCidr),
}

impl ToString for RuleType {
    fn to_string(&self) -> String {
        match self {
            RuleType::Hostname(e) => e.to_string(),
            RuleType::CIDR(e) => {
                e.to_string()
            },
        }
    }
}

impl RuleType {
    pub fn is_cidr(&self) -> bool {
        match *self {
            RuleType::CIDR(_) => true,
            RuleType::Hostname(_) => false,
        }
    }

    pub fn is_hostname(&self) -> bool {
        match *self {
            RuleType::CIDR(_) => false,
            RuleType::Hostname(_) => true,
        }
    }
}

#[derive(Deserialize, Default, Debug)]
pub struct Gress {
    pub allow: Vec<String>,
}

#[derive(Deserialize, Debug, merge::Merge)]
pub struct Config {
    #[merge(strategy = merge::option::overwrite_none)]
    pub listen: Option<String>,

    #[merge(strategy = merge::option::overwrite_none)]
    pub ingress: Option<Vec<String>>,
    #[merge(strategy = merge::option::overwrite_none)]
    pub egress: Option<Vec<String>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: Some(LISTEN.to_string()),
            ingress: Some(vec![ALLOW_ALL.to_string()]),
            egress: Some(vec![ALLOW_ALL.to_string()]),
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self {
            listen: None,
            ingress: None,
            egress: None,
        }
    }

    pub fn load(filename: String) -> anyhow::Result<Self> {
        let mut config = Config::new();
        config.merge(Config::load_from_env()?);
        if let Some(user_config) = Config::load_from_file(filename)? {
            config.merge(user_config);
        }
        Ok(config)
    }

    pub fn load_from_env() -> anyhow::Result<Config> {
        envy::prefixed("SOCKS5_").from_env().context("Failed to parse environment variables")
    }

    pub fn load_from_file(filename: String) -> anyhow::Result<Option<Config>> {
        let file = File::open(filename)?;
        serde_yaml::from_reader(file).context("Could not load config file")
    }

    fn cidr_rules(r: Vec<String>) -> Vec<RuleType> {
        let mut rules = Vec::<RuleType>::new();
        for rule in r {
            match IpCidr::from_str(&rule) {
                Ok(e) => {
                    rules.push(RuleType::CIDR(e));
                },
                Err(_) => {
                    rules.push(RuleType::Hostname(rule));
                },
            }
        }
        rules
    }

    pub fn get_ingress(&self) -> Vec<RuleType> {
        Self::cidr_rules(self.ingress.as_ref().unwrap().clone())
    }

    pub fn get_egress(&self) -> Vec<RuleType> {
        Self::cidr_rules(self.egress.as_ref().unwrap().clone())
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;
    use cidr_utils::cidr::IpCidr;

    use crate::config::RuleType;

    #[test]
    fn test1() {
        let rules: Vec<RuleType> = vec![
            RuleType::Hostname("www.google.com".to_string()),
            RuleType::CIDR(IpCidr::from_str("8.8.8.8/32").unwrap()),
            RuleType::CIDR(IpCidr::from_str("127.0.0.1/8").unwrap()),
        ];
        let ip_1 = IpAddr::from_str("8.8.8.8").unwrap();
        let ip_2 = IpAddr::from_str("1.1.1.1").unwrap();
        let hostname_1 = "www.google.com";
        let hostname_2 = "www.crates.io";
        let hostname_3 = "localhost";

        // Check CIDR's
        assert_eq!(true, rules.iter().filter(|i| i.is_cidr()).any(|a| IpCidr::from_str(a.to_string()).unwrap().contains(ip_1)));
        assert_eq!(false, rules.iter().filter(|i| i.is_cidr()).any(|a| IpCidr::from_str(a.to_string()).unwrap().contains(ip_2)));

        // Check Hostnames
        assert_eq!(true, rules.iter().filter(|i| i.is_hostname()).any(|a| a.to_string() == hostname_1));
        assert_eq!(true, rules.iter().filter(|i| i.is_hostname()).any(|a| a.to_string() == hostname_3));
        assert_eq!(false, rules.iter().filter(|i| i.is_hostname()).any(|a| a.to_string() == hostname_2));

    }
}