
# CloudFlareDDNS

A CloudFlare DNS record updater written in Rust

Small, fast and meant to be run periodically.

## Usage

```bash
cloudflaredns
```

## Output

    [2024-09-11T20:24:49Z INFO  cloudflaredns] Starting Cloudflare DNS updater...
    [2024-09-11T20:24:50Z INFO  cloudflaredns] DNS Record ID for ddns.example.net is 995a899deaf65240ac0a04dd7710a6ac
    [2024-09-11T20:24:50Z INFO  cloudflaredns] DNS Record for ddns.example.net successfully updated to IP: 74.6.143.25