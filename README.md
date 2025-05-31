# 🔍 Automated Web Secrets Scanner

An enterprise-grade, fully automated pipeline for detecting exposed secrets (API keys, tokens, credentials) in live web applications. Features continuous monitoring, smart validation, baseline management, and real-time Slack notifications with clean, actionable insights.

## ✨ What's New

- **Enhanced Slack Notifications**: Clean format showing unique findings with new secret tracking
- **Progress Monitoring**: Real-time progress tracking for all scan phases
- **Scan Resumption**: Ability to resume interrupted scans
- **Katana Integration**: Advanced JavaScript crawling with headless browser support
- **Config Helper**: Automated configuration management with runtime validation
- **Improved CLI**: More intuitive command-line interface with extensive options
- **Performance Optimizations**: Better resource management and concurrent processing

## 🚀 Key Features

### Core Capabilities
- **Multi-Tool Detection**: Integrates TruffleHog, Gitleaks, and custom patterns
- **1600+ Regex Patterns**: Comprehensive pattern database with custom pattern support
- **Smart Validation**: API validation reduces false positives by up to 80%
- **Baseline Management**: Only alerts on new findings with historical tracking
- **URL Discovery**: Multiple sources including GAU, Wayback, and Katana
- **Dynamic Content Support**: Full JavaScript rendering with Playwright

### Advanced Features
- **Progress Monitoring**: Real-time visibility into scan progress
- **Scan Resumption**: Resume interrupted scans from last checkpoint
- **Dry Run Mode**: Test configuration without actual scanning
- **Multiple Scan Types**: Full, incremental, or quick scans
- **Custom Pattern Support**: Add organization-specific detection rules
- **Batch Processing**: Efficient handling of large domain lists

### Reporting & Notifications
- **Interactive HTML Reports**: Beautiful dashboards with filtering and charts
- **Slack Integration**: Real-time alerts with unique/new secret tracking
- **Manual Review Interface**: Web-based UI for finding triage
- **JSON/CSV Export**: Multiple output formats for integration

## 📋 Architecture Overview

```
Domain Input → URL Discovery → Content Fetching → Secret Scanning → Validation → Baseline → Reporting
     ↓              ↓                ↓                  ↓              ↓            ↓           ↓
  domains.txt    gau/katana    Crawlee/Playwright   TruffleHog    API calls    History    Slack/HTML
                 wayback        Dynamic JS render    Gitleaks      Verify      Compare    Notifications
                                                     Custom         Active      New/Old
```

## 🔧 System Requirements

### Minimum Requirements
- **OS**: Ubuntu 20.04+ or similar Linux distribution
- **Python**: 3.8+ with pip
- **Node.js**: 14+ with npm  
- **Go**: 1.16+ (for discovery tools)
- **RAM**: 8GB minimum (16GB recommended)
- **Storage**: 100GB+ for content storage
- **Network**: Stable internet connection

### Optional
- **Docker**: For containerized deployment
- **Kubernetes**: For scalable deployments

## 📦 Quick Start Installation

### 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/automated-secrets-scanner.git
cd automated-secrets-scanner

# Run automated installer
chmod +x scripts/install_tools.sh
./scripts/install_tools.sh
```

### 2. Configure Environment

```bash
# Copy and configure environment
cp .env.example .env
nano .env

# Key settings to configure:
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
ENABLE_KATANA=true
ENABLE_VALIDATION=true
LOG_LEVEL=INFO
```

### 3. Install Dependencies

```bash
# Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Node.js dependencies
npm install
```

### 4. Configure Domains

```bash
# Add target domains
echo "example.com" >> config/domains.txt
echo "app.example.com" >> config/domains.txt
```

### 5. Run Your First Scan

```bash
# Basic scan with Slack notifications
python scripts/run_scan.py --domain example.com --slack

# Full scan with all features
python scripts/run_scan.py --validate --slack --verbose
```

## 🏃 Usage Examples

### Basic Commands

```bash
# Scan single domain
python scripts/run_scan.py --domain example.com

# Scan multiple domains from file
python scripts/run_scan.py --domains config/domains.txt

# Quick scan (limited discovery)
python scripts/run_scan.py --domain example.com --scan-type quick

# Dry run (test configuration)
python scripts/run_scan.py --domain example.com --dry-run
```

### Advanced Usage

```bash
# Full scan with all features
python scripts/run_scan.py \
  --domains production_domains.txt \
  --scan-type full \
  --validate \
  --slack \
  --include-problematic \
  --concurrency 10 \
  --timeout 60

# Resume interrupted scan
python scripts/run_scan.py --resume scan_20240115_143022_12345

# Custom patterns only
python scripts/run_scan.py \
  --domain example.com \
  --patterns config/custom_patterns.yaml \
  --disable-trufflehog \
  --disable-gitleaks

# High-performance scan
python scripts/run_scan.py \
  --domains domains.txt \
  --concurrency 20 \
  --batch-size 100 \
  --disable-validation \
  --output-format json
```

### Orchestrator Script

For production environments:

```bash
# Full automated pipeline
./scripts/orchestrator.sh

# Run specific phases
./scripts/orchestrator.sh --phase url_discovery
./scripts/orchestrator.sh --phase scanning
./scripts/orchestrator.sh --phase validation
./scripts/orchestrator.sh --phase reporting
```

## 📊 Understanding Slack Notifications

### New Format Features

The enhanced Slack notifications now show:

1. **Summary Section**
   - Total secrets found (all occurrences)
   - Unique secrets (deduplicated)
   - New secrets (not in baseline)
   - Scan duration and URL count

2. **Severity Breakdown**
   - Only unique counts displayed
   - Clean bullet-point format
   - Color-coded severity levels

3. **Findings by Type**
   - Organized by severity (Critical → High → Medium → Low)
   - Shows unique count with new count in parentheses
   - Example: `Unique Count: 11 (8 new)`
   - Sample locations with truncated URLs

### Example Notification

```
🔍 Secret Scan Alert

Scan ID: scan_20250530_001842_71906
Domain: example.com
Date: 2025-05-30 11:26:41 UTC

📊 Summary
Total Secrets Found: 79
Unique Secrets Found: 34
New Secrets: 30
URLs Scanned: 744
Scan Duration: 66 minutes

Severity Breakdown (Unique Only):
• 🔴 Critical: 4
• 🟠 High: 25
• 🟡 Medium: 2
• 🔵 Low: 2

🔐 Findings by Type (Unique Only)

Critical Severity
1. GCP API Key
• Unique Count: 4 (3 new)
• Status: ❌ Invalid/Inactive
• Sample Locations:
   • influencers.example.com
   • inline-scripts/...inline_2.js
   • [View all 4 locations →]
```

## 🔧 Configuration

### Environment Variables (.env)

```bash
# Slack Configuration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
ENABLE_SLACK=true
SLACK_CHANNEL=#security-alerts

# Discovery Tools
ENABLE_KATANA=true          # Advanced JS crawling
ENABLE_GAU=true             # Get All URLs
ENABLE_WAYBACKURLS=true     # Wayback Machine
KATANA_HEADLESS=true        # Browser mode
KATANA_DEPTH=3              # Crawl depth

# Scanning Configuration
ENABLE_TRUFFLEHOG=true      # TruffleHog scanner
ENABLE_GITLEAKS=true        # Gitleaks scanner
ENABLE_CUSTOM_PATTERNS=true # Custom regex patterns
ENABLE_VALIDATION=true      # API validation
VERIFY_SECRETS=true         # Live verification

# Performance
CONCURRENT_REQUESTS=10      # Parallel requests
SCAN_TIMEOUT=30000         # 30 seconds
CRAWLER_BATCH_SIZE=50      # URLs per batch
MAX_URLS_PER_DOMAIN=10000  # Limit per domain

# Features
ENABLE_PROGRESS_MONITORING=true
SAVE_INTERMEDIATE_RESULTS=true
DRY_RUN=false

# Logging
LOG_LEVEL=INFO             # DEBUG, INFO, WARNING, ERROR
LOG_FILE_PATH=./logs
```

### Slack Configuration (config/slack_config.json)

```json
{
  "webhook_url": "${SLACK_WEBHOOK_URL}",
  "channel": "#security-alerts",
  "username": "Secret Scanner Bot",
  "icon_emoji": ":lock:",
  "mention_users": ["U1234567890"],
  "mention_on_critical": true,
  "rate_limit_delay": 1,
  "max_findings_per_message": 10,
  "formatting": {
    "show_unique_counts_only": true,
    "group_by_type_and_severity": true,
    "include_new_counts": true
  }
}
```

## 📁 Project Structure

```
automated-secrets-scanner/
├── scripts/
│   ├── run_scan.py             # Main entry point
│   ├── orchestrator.sh         # Bash orchestrator
│   ├── install_tools.sh        # Installation script
│   └── config_helper.py        # Configuration helper
│
├── modules/
│   ├── url_discovery/          # URL enumeration
│   │   └── discovery.py        # GAU, Wayback, Katana
│   ├── content_fetcher/        # Web crawling
│   │   └── fetcher.py          # Crawlee/Playwright
│   ├── secret_scanner/         # Detection engines
│   │   └── scanner_wrapper.py  # TruffleHog, Gitleaks
│   ├── validator/              # Validation logic
│   │   ├── auto_validator.py   # API validation
│   │   ├── baseline_manager.py # Historical tracking
│   │   └── manual_review.py    # Web UI
│   └── reporter/               # Reports & alerts
│       ├── html_generator.py   # HTML reports
│       └── slack_notifier.py   # Slack integration
│
├── config/                     # Configuration files
├── patterns/                   # Detection patterns
├── data/                       # Runtime data
├── logs/                       # Application logs
└── tests/                      # Test suite
```

## 🚀 Advanced Features

### Progress Monitoring

Real-time progress tracking during scans:

```bash
# Enable progress monitoring
export ENABLE_PROGRESS_MONITORING=true

# View progress logs
tail -f logs/progress_scan_*.log
```

Progress shows:
- Current phase (URL Discovery → Content Fetching → Scanning → Validation → Reporting)
- Percentage complete
- Estimated time remaining

### Scan Resumption

Resume interrupted scans:

```bash
# Scan gets interrupted
python scripts/run_scan.py --domains large_list.txt
# Ctrl+C or system failure

# Resume from last checkpoint
python scripts/run_scan.py --resume scan_20240115_143022_12345
```

### Custom Patterns

Add organization-specific patterns:

```yaml
# patterns/custom_patterns.yaml
patterns:
  - id: internal_api_key
    name: Internal API Key
    pattern: 'INT_KEY_[A-Z0-9]{32}'
    severity: high
    confidence: 0.9
    keywords:
      - internal_key
      - int_key
    
  - id: jwt_token
    name: JWT Token
    pattern: 'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'
    severity: medium
    confidence: 0.8
```

### Manual Review Interface

```bash
# Start review interface
python -m modules.validator.manual_review

# Access at http://localhost:5000
# Features:
# - Review findings one by one
# - Mark as true/false positive
# - Add notes and remediation steps
# - Export validated results
```

## 🛡️ Security Best Practices

1. **Environment Security**
   ```bash
   # Use secrets management
   export SLACK_WEBHOOK_URL=$(vault read -field=webhook secret/slack)
   
   # Restrict file permissions
   chmod 600 .env
   chmod 700 data/
   ```

2. **Scan Authorization**
   - Only scan domains you own or have permission to test
   - Keep an audit log of all scans
   - Use scope configuration to prevent accidental scans

3. **Data Protection**
   - Encrypt `data/` directory at rest
   - Rotate logs regularly
   - Limit access to reports and findings

4. **Network Security**
   - Use VPN for scanning internal assets
   - Configure proxy for anonymity if needed
   - Implement rate limiting to avoid overload

## 🐛 Troubleshooting

### Common Issues and Solutions

#### Installation Problems

```bash
# Missing Go tools
curl -L https://github.com/lc/gau/releases/latest/download/gau_linux_amd64.tar.gz | tar xz
sudo mv gau /usr/local/bin/

# Python dependency conflicts
python3 -m venv venv --clear
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

#### Memory Issues

```bash
# Reduce concurrent operations
export CONCURRENT_REQUESTS=3
export CRAWLER_BATCH_SIZE=20
export KATANA_PARALLELISM=5

# Monitor memory usage
watch -n 1 'ps aux | grep -E "python|node|chrome" | grep -v grep'
```

#### Slack Notification Issues

```python
# Test Slack connection
python -c "
from modules.reporter.slack_notifier import SlackNotifier
config = {'config_dir': './config'}
notifier = SlackNotifier(config)
if notifier.test_connection():
    print('✅ Slack connection successful')
else:
    print('❌ Slack connection failed')
"
```

#### Scan Failures

```bash
# Check logs for errors
grep -i error logs/scanner_*.log | tail -20

# Validate configuration
python scripts/config_helper.py validate

# Run in debug mode
LOG_LEVEL=DEBUG python scripts/run_scan.py --domain example.com --verbose
```

## 📈 Performance Tuning

### For Large-Scale Operations

```bash
# High-performance configuration
python scripts/run_scan.py \
  --domains fortune500.txt \
  --concurrency 20 \
  --batch-size 100 \
  --timeout 45 \
  --disable-validation \
  --output-format json \
  --disable-katana      # Faster but less thorough
```

### For Maximum Accuracy

```bash
# Thorough scanning configuration
python scripts/run_scan.py \
  --domain critical-app.com \
  --scan-type full \
  --validate \
  --verify-secrets \
  --include-problematic \
  --katana-depth 5 \
  --timeout 120 \
  --patterns config/strict_patterns.yaml
```

### Resource Optimization

```bash
# CPU optimization
export KATANA_PARALLELISM=$(($(nproc) / 2))
export MAX_WORKERS=$(($(nproc) - 2))

# Memory optimization
export NODE_OPTIONS="--max-old-space-size=4096"
export PYTHON_GC_THRESHOLD="700,10,10"

# Disk optimization
# Use fast SSD for data directory
ln -s /mnt/fast-ssd/scanner-data ./data
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Quick Contribution Steps

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add/update tests (`pytest tests/test_your_feature.py`)
5. Update documentation
6. Commit (`git commit -m 'Add amazing feature'`)
7. Push (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v

# Run linting
flake8 modules/ scripts/
black modules/ scripts/ --check

# Run type checking
mypy modules/ scripts/
```

## 📊 Monitoring & Metrics

### Key Metrics to Track

- **Scan Performance**: URLs/second, scan duration
- **Detection Rate**: Secrets found per domain
- **False Positive Rate**: Validated vs raw findings
- **API Health**: Validation success rate
- **System Health**: Memory usage, disk space

### Monitoring Commands

```bash
# Real-time scan monitoring
watch -n 5 'tail -20 logs/scanner_*.log | grep -E "Phase|Found|Error"'

# Daily statistics
python -c "
from modules.reporter import StatsCollector
stats = StatsCollector('./data')
print(stats.get_daily_summary())
"

# Baseline trends
python -m modules.validator.baseline_manager --report trends
```

## 🗺️ Roadmap

### Current Version (v2.0)
- ✅ Enhanced Slack notifications with unique/new tracking
- ✅ Progress monitoring and scan resumption
- ✅ Katana integration for better JS discovery
- ✅ Config helper with validation
- ✅ Improved CLI interface

### Upcoming (v2.1)
- [ ] Web dashboard for real-time monitoring
- [ ] JIRA/ServiceNow integration
- [ ] Scheduled scans with cron
- [ ] Docker Compose deployment
- [ ] Enhanced validation for 20+ services

### Future (v3.0)
- [ ] Machine learning for false positive reduction
- [ ] GraphQL/REST API scanning
- [ ] Mobile app binary scanning
- [ ] Kubernetes operator
- [ ] Multi-tenant support

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Advanced secret detection
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Lightning-fast scanning  
- [Crawlee](https://crawlee.dev/) - Modern web crawling framework
- [Katana](https://github.com/projectdiscovery/katana) - Advanced crawler
- [gau](https://github.com/lc/gau) - Get All URLs
- [Secrets-Patterns-DB](https://github.com/mazen160/secrets-patterns-db) - Pattern database

## 📞 Support

- **Documentation**: See `docs/` directory for detailed guides
- **Issues**: [GitHub Issues](https://github.com/yourusername/automated-secrets-scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/automated-secrets-scanner/discussions)
- **Security**: Report vulnerabilities to security@yourcompany.com

---

**⚠️ Disclaimer**: This tool is powerful and should only be used on domains you own or have explicit permission to test. Always follow responsible disclosure practices for any findings. The authors are not responsible for misuse of this tool.