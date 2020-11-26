extern crate serde_yaml;

use std::{io::Error, fs::File};
use serde::{Serialize, Deserialize};

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
            },
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
}