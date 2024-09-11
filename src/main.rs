use clap::Parser;
use log;
use reqwest::Client;
use serde::Deserialize;
use config::Config;
use std::net::IpAddr;
use std::error;
use serde_json::json;
use tokio::process::Command;

#[derive(Debug, Deserialize)]
struct CloudflareConfig {
    zoneid: String,
    cloudflare_zone_api_token: String,
    dns_record: String, // Comma-separated DNS records
    ttl: u32,
    proxied: bool,
    what_ip: String,
}

/// Command-line options
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn init_logger(verbose: bool) {
    let log_level = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    env_logger::builder()
        .filter(None, log_level)
        .init();
}

fn read_config(config_file: &str) -> Result<CloudflareConfig, Box<dyn error::Error>> {
    let settings = Config::builder()
        .add_source(config::File::with_name(config_file))
        .build()?;

    let config: CloudflareConfig = settings.try_deserialize()?;
    Ok(config)
}

async fn get_external_ip() -> Result<IpAddr, Box<dyn error::Error>> {
    let client = Client::new();
    let resp = client.get("https://checkip.amazonaws.com").send().await?;
    let ip_str = resp.text().await?.trim().to_string();
    let ip: IpAddr = ip_str.parse()?;
    Ok(ip)
}

async fn get_internal_ip() -> Result<String, Box<dyn error::Error>> {
    let output = Command::new("ip")
        .args(&["route", "get", "1.1.1.1"])
        .output().await?;

    if !output.status.success() {
        return Err("Failed to get internal IP".into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let interface: &str = stdout
        .lines()
        .find(|line| line.contains("dev"))
        .and_then(|line| line.split_whitespace().nth(4))
        .ok_or("No valid interface found")?;

    let ip_output = Command::new("ip")
        .args(&["-o", "-4", "addr", "show", interface, "scope", "global"])
        .output().await?;

    let ip = String::from_utf8_lossy(&ip_output.stdout)
        .lines()
        .next()
        .ok_or("No IP address found")?
        .split_whitespace()
        .nth(3)
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_string();

    Ok(ip)
}

async fn update_cloudflare_dns(config: CloudflareConfig, ip: IpAddr) -> Result<(), Box<dyn error::Error>> {
    let client = Client::new();

    // Split comma-separated DNS records
    let dns_records: Vec<&str> = config.dns_record.split(',').collect();

    for record in dns_records {
        log::debug!("Fetching DNS record for: {}", record);

        let res = client.get(format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=A&name={}",
            config.zoneid, record
        ))
            .header("Authorization", format!("Bearer {}", config.cloudflare_zone_api_token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let json: serde_json::Value = res.json().await?;
        if !json["success"].as_bool().unwrap_or(false) {
            log::error!("Error getting DNS record info: {}", json);
            return Err("Error getting DNS record info".into());
        }

        // Extract the DNS record ID
        let record_id = json["result"][0]["id"].as_str().unwrap();
        log::info!("DNS Record ID for {} is {}", record, record_id);

        let body = json!({
            "type": "A",
            "name": record,
            "content": ip.to_string(),
            "ttl": config.ttl,
            "proxied": config.proxied
        });

        // Update the DNS record
        let update_res = client.put(format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            config.zoneid, record_id
        ))
            .header("Authorization", format!("Bearer {}", config.cloudflare_zone_api_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let update_json: serde_json::Value = update_res.json().await?;
        if !update_json["success"].as_bool().unwrap_or(false) {
            log::error!("Failed to update DNS record: {}", update_json);
            return Err("Failed to update DNS record".into());
        }

        log::info!("DNS Record for {} successfully updated to IP: {}", record, ip);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn error::Error>> {
    let args = Args::parse();
    init_logger(args.verbose);

    log::info!("Starting Cloudflare DNS updater...");

    let config = read_config("cloudflareddns.ini")?;

    let ip = match config.what_ip.as_str() {
        "external" => get_external_ip().await?,
        "internal" => {
            let ip_str = get_internal_ip().await?;
            ip_str.parse()?
        },
        _ => return Err("Invalid what_ip option".into()),
    };

    update_cloudflare_dns(config, ip).await?;

    Ok(())
}
