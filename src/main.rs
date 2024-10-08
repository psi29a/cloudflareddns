use clap::{CommandFactory, Parser};
use log;
use serde::Deserialize;
use config::Config;
use std::net::IpAddr;
use std::error::Error;
use serde_json::json;

#[derive(Debug, Deserialize)]
struct CloudFlareDDNSConfig {
    zone_id: String,
    api_token: String,
    dns_record: String, // Comma-separated DNS records
    ttl: u32,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    zone_id: Option<String>,

    #[arg(long)]
    api_token: Option<String>,

    #[arg(long)]
    dns_record: Option<String>, // Comma-separated DNS records

    #[arg(long)]
    ttl: Option<u32>,

    #[arg(long)]
    ip: Option<String>,

    #[arg(long)]
    config: Option<String>,

    #[arg(long, default_value = "false")]
    dry: bool,

    #[arg(long, default_value = "false")]
    verbose: bool,

    #[arg(long, default_value = "false")]
    debug: bool,
}

fn read_config_from_file(config_file: String) -> Result<CloudFlareDDNSConfig, Box<dyn Error>> {
    let settings = Config::builder()
        .add_source(config::File::with_name(&*config_file))
        .build()?;
    let config: CloudFlareDDNSConfig = settings.try_deserialize()?;
    Ok(config)
}

fn merge_config(cli_args: Args, file_config: Option<CloudFlareDDNSConfig>) -> CloudFlareDDNSConfig {
    let default_config = file_config.unwrap_or_else(|| CloudFlareDDNSConfig {
        zone_id: "".to_string(),
        api_token: "".to_string(),
        dns_record: "".to_string(),
        ttl: 1,
    });

    CloudFlareDDNSConfig {
        zone_id: cli_args.zone_id.unwrap_or(default_config.zone_id),
        api_token: cli_args.api_token.unwrap_or(default_config.api_token),
        dns_record: cli_args.dns_record.unwrap_or(default_config.dns_record),
        ttl: cli_args.ttl.unwrap_or(default_config.ttl),
    }
}

fn init_logger(verbose: bool, dry: bool, debug: bool) {
    let log_level = if debug {
        log::LevelFilter::Debug
    } else if verbose || dry {
        log::LevelFilter::Info
    } else {
        log::LevelFilter::Warn
    };

    env_logger::builder()
        .filter(None, log_level)
        .init();
}

fn get_external_ip() -> Result<IpAddr, Box<dyn Error>> {
    let resp = minreq::get("http://checkip.amazonaws.com").send()?;
    let ip: IpAddr = resp.as_str()?.trim().to_string().parse()?;
    Ok(ip)
}

fn get_provided_ip(ip: Option<String>) -> Result<IpAddr, Box<dyn Error>> {
    match ip {
        Some(ip_str) => {
            ip_str.parse().map_err(|e| {
                let error_message = format!("'{}' is an invalid IP Address: {}", ip_str, e);
                error_message.into()
            })
        }
        None => Err("No IP provided".into()), // Return error if no IP provided
    }
}

fn update_cloudflare_dns(config: CloudFlareDDNSConfig, ip: IpAddr, dry: bool) -> Result<(), Box<dyn Error>> {
    // Split comma-separated DNS records
    let dns_records: Vec<&str> = config.dns_record.split(',').collect();

    for record in dns_records {
        log::info!("Fetching DNS record for: {}", record);

        let res = minreq::get(format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=A&name={}",
            config.zone_id, record
        ))
            .with_header("Authorization", format!("Bearer {}", config.api_token))
            .with_header("Content-Type", "application/json")
            .send()?;

        let json: serde_json::Value = res.json()?;
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
        });

        if dry {
            log::info!("Test mode enabled, skipping DNS record update");
            log::info!("Would have updated DNS record for {} to IP: {}", record, ip);
            log::info!("body: {}", body);
            continue;
        }

        // Update the DNS record
        let update_res = minreq::put(format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            config.zone_id, record_id
        ))
            .with_header("Authorization", format!("Bearer {}", config.api_token))
            .with_header("Content-Type", "application/json")
            .with_json(&body)?
            .send()?;

        let update_json: serde_json::Value = update_res.json()?;
        if !update_json["success"].as_bool().unwrap_or(false) {
            log::error!("Failed to update DNS record: {}", update_json);
            return Err("Failed to update DNS record".into());
        }

        log::info!("DNS Record for {} successfully updated to IP: {}", record, ip);
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let dry = args.dry;
    let provided_ip = args.ip.clone();
    init_logger(args.verbose, dry, args.debug);

    // Default config path
    let default_config_path = "cloudflareddns.ini";

    // Determine whether to use config file or CLI arguments
    let config_file = args.config.clone().unwrap_or(default_config_path.to_string());

    // Try reading the config file if it exists, otherwise proceed with CLI args
    let file_config = if std::path::Path::new(&config_file).exists() {
        Some(read_config_from_file(config_file)?)
    } else {
        None
    };

    // Merge CLI arguments and config file values
    let config = merge_config(args, file_config);

    // Check if all required fields are filled, otherwise display help
    if config.zone_id.is_empty() || config.api_token.is_empty() || config.dns_record.is_empty() {
        println!("Missing required arguments: zone_id, api_token, or dns_record");
        Args::command().print_help()?;
        return Ok(());
    }

    // now start the actual work
    log::info!("Starting Cloudflare DNS updater...");

    // Determine the IP to use
    let ip = if let Some(ref _ip_str) = provided_ip {
        // Provided IP is filled, try to get it
        get_provided_ip(provided_ip)?
    } else {
        // No IP provided, fall back to external IP
        get_external_ip()?
    };

    log::info!("IP address: {}", ip);

    update_cloudflare_dns(config, ip, dry)?;

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_read_config_from_file() {
        let config_content = r#"
        zone_id = "example-zone-id"
        api_token = "example-api-token"
        dns_record = "example.com"
        ttl = 3600
        "#;

        let config_path = "test_config.ini";
        let mut file = File::create(config_path).expect("Unable to create test config file");
        file.write_all(config_content.as_bytes()).expect("Unable to write to test config file");

        let config = read_config_from_file(config_path.to_string()).expect("Failed to read config file");

        assert_eq!(config.zone_id, "example-zone-id");
        assert_eq!(config.api_token, "example-api-token");
        assert_eq!(config.dns_record, "example.com");
        assert_eq!(config.ttl, 3600);

        std::fs::remove_file(config_path).expect("Unable to delete test config file");
    }

    #[test]
    fn test_merge_config() {
        let cli_args = Args {
            zone_id: Some("cli-zone-id".to_string()),
            api_token: None,
            dns_record: Some("cli-dns-record".to_string()),
            ttl: Some(7200),
            ip: None,
            config: None,
            dry: false,
            verbose: false,
            debug: false,
        };

        let file_config = Some(CloudFlareDDNSConfig {
            zone_id: "file-zone-id".to_string(),
            api_token: "file-api-token".to_string(),
            dns_record: "file-dns-record".to_string(),
            ttl: 3600,
        });

        let merged_config = merge_config(cli_args, file_config);

        assert_eq!(merged_config.zone_id, "cli-zone-id");
        assert_eq!(merged_config.api_token, "file-api-token");
        assert_eq!(merged_config.dns_record, "cli-dns-record");
        assert_eq!(merged_config.ttl, 7200);
    }

    #[test]
    fn test_get_provided_ip() {
        let valid_ip = "8.8.8.8".to_string();
        let invalid_ip = "invalid_ip".to_string();

        assert_eq!(get_provided_ip(Some(valid_ip)).unwrap(), "8.8.8.8".parse::<IpAddr>().unwrap());
        assert!(get_provided_ip(Some(invalid_ip)).is_err());
        assert!(get_provided_ip(None).is_err());
    }
}