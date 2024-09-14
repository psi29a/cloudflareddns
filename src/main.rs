use log;
use std::net::IpAddr;
use std::error::Error;
use serde_json::json;

const HELP: &str = "\
small, fast rust based cloudflare dns zone updater

Usage: cloudflareddns [OPTIONS]

Options:
      --zoneid <ZONEID>
      --apitoken <API_TOKEN>
      --dnsrecord <DNS_RECORD>
      --ttl <TTL>
      --verbose
  -h, --help                       Print help
  -V, --version                    Print version
";

#[derive(Debug)]
struct Args {
    zone_id: String,
    api_token: String,
    dns_record: String, // Comma-separated DNS records
    ttl: u32,
    dry: Option<bool>,
    verbose: Option<bool>,
    debug: Option<bool>,
}

fn parse_args() -> Result<Args, pico_args::Error> {
    let mut pargs = pico_args::Arguments::from_env();

    // Help has a higher priority and should be handled separately.
    if pargs.contains(["-h", "--help"]) {
        print!("{}", HELP);
        std::process::exit(0);
    }

    let args = Args {
        zone_id: pargs.value_from_str("--zoneid")?,
        api_token: pargs.value_from_str("--apitoken")?,
        dns_record: pargs.value_from_str("--dnsrecord")?,
        ttl: pargs.opt_value_from_fn("--ttl", parse_number)?.unwrap_or(128),
        dry: pargs.opt_free_from_str()?,
        verbose: pargs.opt_free_from_str()?,
        debug: pargs.opt_free_from_str()?,
    };

    Ok(args)
}

fn parse_number(s: &str) -> Result<u32, &'static str> {
    s.parse().map_err(|_| "not a number")
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
    let resp = minreq::get("https://checkip.amazonaws.com").send()?;
    let ip: IpAddr = resp.as_str()?.trim().to_string().parse()?;
    Ok(ip)
}

fn update_cloudflare_dns(config: Args, ip: IpAddr) -> Result<(), Box<dyn Error>> {
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

        if config.dry.unwrap_or(false) {
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
    // parse command line arguments
    let args = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {}.", e);
            std::process::exit(1);
        }
    };

    //  setup logging
    init_logger(args.verbose.unwrap_or(false), args.dry.unwrap_or(false), args.debug.unwrap_or(false));

    // now start the actual work
    log::info!("Starting Cloudflare DNS updater...");

    // get external IP address
    let ip= get_external_ip()?;
    log::info!("IP address: {}", ip);

    // update cloudflare DNS
    update_cloudflare_dns(args, ip)?;
    Ok(())
}