# cert-police

A comprehensive Certificate Transparency monitoring tool that discovers new subdomains, verifies their DNS resolution, and automatically performs security scanning.

## 🚀 Features

### Core Monitoring
- **Real-time Certificate Transparency Monitoring** - Continuously monitors CT logs for new certificates
- **Intelligent Domain Matching** - Dual matching strategy:
  - **Domain Mode**: Strict subdomain matching for targets with dots (e.g., `example.com`)
  - **String Mode**: Flexible keyword matching for targets without dots (e.g., `shopify`, `google`)
- **DNS Resolution Verification** - Automatically checks if discovered domains resolve to IP addresses
- **File Separation** - Organizes findings into resolved vs unresolved domain files

### Advanced Security Features
- **Automatic Vulnerability Scanning** - Integrated Nuclei scanning for resolved domains
- **TLS Certificate Analysis** - Uses tlsx for detailed certificate information
- **Real-time Notifications** - Instant alerts for new resolved domains and vulnerabilities
- **Smart State Management** - Tracks domains that change from unresolved to resolved

### Reliability & Performance
- **Auto-reconnection** - Infinite retry mechanism with connection monitoring
- **Robust Error Handling** - Handles network failures and timeouts gracefully
- **Duplicate Prevention** - Intelligent deduplication across all output files
- **Performance Optimization** - Efficient file handling and processing

## 📁 Output Files

- **`found_subdomains.txt`** - Discovered domains that don't resolve (inactive)
- **`resolved_subdomains.txt`** - Discovered domains that resolve (active targets)
- **`nuclei_results/`** - Directory containing vulnerability scan results (one file per domain)

## 🛠️ Installation

```bash
git clone https://github.com/0x1git/cert-police.git
cd cert-police
chmod +x cert-police.sh
```

### Dependencies
The script automatically installs missing dependencies:
- `certstream` - Certificate Transparency monitoring
- `dig` - DNS resolution checking
- `nuclei` - Vulnerability scanning
- `notify` - Real-time notifications
- `tlsx` - TLS certificate analysis
- `jq` - JSON parsing
- `anew` - File deduplication

## 📝 Usage

### Basic Monitoring
```bash
# Monitor domains from targets.txt
./cert-police.sh -t targets.txt

# Silent mode (minimal output)
./cert-police.sh -s -t targets.txt
```

### With Notifications
```bash
# Enable notifications for new resolved domains
./cert-police.sh -n -t targets.txt
```

### With Vulnerability Scanning
```bash
# Enable Nuclei scanning for resolved domains
./cert-police.sh -u -t targets.txt
```

### Full Feature Set
```bash
# All features: silent mode + notifications + nuclei scanning
./cert-police.sh -s -n -u -t targets.txt
```

## 🎯 Target Configuration

Create a `targets.txt` file with your monitoring targets:

```
# Domain targets (exact/subdomain matching)
example.com
company.org
mysite.net

# Keyword targets (flexible string matching)
company
company2
mysite
```

**Matching Logic:**
- **Targets with dots** → Domain matching: `api.example.com` ✅, `notexample.com` ❌
- **Targets without dots** → String matching: `admin.anything.com` ✅, `myadmin.site.org` ✅

## 🔔 Notification Setup

Configure the notify tool for real-time alerts:

```bash
# Create provider config
mkdir -p ~/.config/notify
nano ~/.config/notify/provider-config.yaml
```

Example configuration:
```yaml
discord:
  - id: "cert-alerts"
    discord_webhook_url: "WEBHOOK_URL"

slack:
  - id: "security-alerts"
    slack_webhook_url: "WEBHOOK_URL"
```

## 🔍 Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --target FILE` | Specify target domains/keywords file |
| `-s, --silent` | Run in silent mode (minimal output) |
| `-n, --notify` | Enable notifications for resolved domains |
| `-u, --nuclei` | Enable Nuclei vulnerability scanning |
| `-h, --help` | Show usage information |

## 📊 Example Output

```
[INFO] No. of domains/Keywords to monitor 5
[INFO] Notify is enabled (only for resolved domains)
[INFO] Nuclei scanning is enabled for resolved domains
[INFO] Unresolved domains: found_subdomains.txt
[INFO] Resolved domains: resolved_subdomains.txt
[INFO] Nuclei results: nuclei_results/

[RESOLVED] api.example.com
[SCAN] Running Nuclei scan on api.example.com
[VULN] Vulnerabilities found on api.example.com
[UNRESOLVED] test.example.com
[RESOLVED] admin.company.org (moved from unresolved)
```

## 🔧 Advanced Configuration

### Custom Nuclei Templates
Modify the nuclei template path in the script:
```bash
# Default: /root/nuclei-templates/http/
# Customize as needed for your environment
```

### Notification Channels
The script uses two notification channels:
- `certpolice` - New domain discoveries
- `reconftw` - Vulnerability findings

## 🏃‍♂️ Workflow

1. **Monitor** Certificate Transparency logs continuously
2. **Match** discovered domains against your targets
3. **Verify** DNS resolution for matched domains
4. **Organize** domains into resolved/unresolved files
5. **Scan** resolved domains with Nuclei (if enabled)
6. **Notify** about new discoveries and vulnerabilities
7. **Track** domain state changes over time

## 🔄 Auto-Reconnection

The script includes robust connection handling:
- Detects connection timeouts (5-minute threshold)
- Automatically reconnects with 10-second delays
- Infinite retry mechanism for continuous monitoring
- Graceful handling of network interruptions

## 🙏 Credits

This project is a comprehensive rewrite inspired by [CertEagle](https://github.com/devanshbatham/CertEagle) by [Devansh Batham](https://github.com/devanshbatham), expanding beyond the original's Slack-only limitation to provide a full-featured security monitoring solution.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
