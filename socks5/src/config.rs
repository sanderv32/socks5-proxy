#![allow(unused_macros)]

extern crate serde_yaml;

use std::{fs::File, io::Error};
use cidr_utils::cidr::IpCidr;
use serde::{Serialize, Deserialize};

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

#[derive(Serialize, Deserialize, Default)]
pub struct Gress {
    pub allow: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub listen: String,

    pub ingress: Gress,
    pub egress: Gress,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1080".to_string(),
            ingress: Gress {
                allow: vec!["0.0.0.0/0".to_string()],
            },
            egress: Gress {
                allow: vec!["0.0.0.0/0".to_string()],
            }
        }
    }
}

impl Config {
    pub fn new() -> Self {
    
        Self {
            ..Default::default()
        }
    }

    pub fn load_from_file(filename: String) -> Result<Config, Error> {
        let file = File::open(filename)?;
        let config: Config = serde_yaml::from_reader(file).unwrap();
        Ok(config)
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
        Self::cidr_rules(self.ingress.allow.clone())
    }

    pub fn get_egress(&self) -> Vec<RuleType> {
        Self::cidr_rules(self.egress.allow.clone())
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