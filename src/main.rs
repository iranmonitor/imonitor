mod app;
mod app_types;
mod config;
mod db;
mod hardware;
mod http;
mod platform;
mod network_rules;
mod source_ip;
mod radar_client;
mod runner;
mod types;
mod util;
mod views;
mod ads;
mod speedtest;

use std::process;

fn main() {
    if let Err(error) = app::entry() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}
