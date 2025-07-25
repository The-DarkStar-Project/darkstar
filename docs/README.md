# Darkstar - Advanced Vulnerability Management Framework

<p align="center">
  <img src="logo.png" alt="Darkstar Logo" width="300" height="300">
</p>

<p align="center">
  <strong>The ultimate Red Team and Blue Team tool for attack surface mapping and vulnerability management!</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#usage">Usage</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## Features

🔍 **Comprehensive Scanning Modes**
- **Passive Mode**: Stealthy reconnaissance without active scanning
- **Normal Mode**: Balanced scanning with essential active modules  
- **Aggressive Mode**: Full-spectrum scanning with all modules
- **Attack Surface Mode**: Deep asset discovery and mapping
- **OpenVAS Integration**: Enterprise-grade vulnerability assessment

🛠️ **Integrated Security Tools**
- **BBbot**: Advanced black-box reconnaissance
- **Nuclei**: Fast vulnerability scanner with 5000+ templates
- **Rustscan**: Lightning-fast port scanning
- **OpenVAS**: Professional vulnerability management
- **Custom Tools**: Specialized reconnaissance modules

📊 **Advanced Analytics**
- **EPSS Scoring**: Exploit prediction and prioritization
- **CISA KEV Integration**: Known exploited vulnerabilities tracking
- **HIBP Integration**: Breach data correlation
- **Dashboard Insights**: Comprehensive vulnerability visualization

🚀 **Modern Architecture**
- **Factory Pattern**: Modular scanner architecture
- **Async Operations**: High-performance concurrent scanning
- **Docker Support**: Containerized deployment
- **Database Integration**: Persistent result storage

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (recommended)
- [Docker Compose](https://docs.docker.com/compose/install/)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-org/darkstar.git
   cd darkstar
   ```

2. **Start with Docker (Recommended):**
   ```bash
   chmod +x scripts/run.sh
   ./scripts/run.sh
   ```

3. **Manual Setup (Advanced):**
   ```bash
   pip install -r requirements.txt
   # Configure database and environment variables
   cp config/.env.example .env
   # Edit .env with your settings
   ```

### Basic Usage

**Inside the Docker container:**
```bash
# Enter the container
docker exec -it darkstar bash

# Run a basic scan
python src/cli/main.py -t example.com -m 2 -d myorg

# Run multiple targets
python src/cli/main.py -t "example.com,192.168.1.1/24" -m 3 -d myorg

# Enable brute force with timeout
python src/cli/main.py -t target.com -m 3 -d myorg --bruteforce --bruteforce-timeout 600
```

### Scanning Modes

| Mode | Description | Tools Used | Use Case |
|------|-------------|------------|----------|
| 1 | **Passive** | BBbot (passive only) | Stealth reconnaissance |
| 2 | **Normal** | BBbot + Rustscan | Standard security assessment |
| 3 | **Aggressive** | BBbot + Rustscan + Nuclei | Comprehensive vulnerability scan |
| 4 | **Attack Surface** | Asset discovery + targeted scans | Red team engagement |
| 5 | **OpenVAS** | OpenVAS integration | Enterprise vulnerability management |

---

## Architecture

### Project Structure

```
darkstar/
├── src/                           # Main source code
│   ├── cli/                       # Command line interface
│   │   └── main.py               # Application entry point
│   ├── core/                     # Core framework functionality
│   │   ├── config.py             # Configuration management
│   │   ├── logger.py             # Logging setup
│   │   ├── db_helper.py          # Database operations
│   │   └── utils.py              # Utility functions
│   ├── scanners/                 # Scanner implementations
│   │   ├── base_scanner.py       # Abstract base scanner
│   │   ├── scanner_factory.py    # Factory pattern implementation
│   │   ├── passive_scanner.py    # Passive reconnaissance
│   │   ├── normal_scanner.py     # Standard scanning
│   │   ├── aggressive_scanner.py # Comprehensive scanning
│   │   ├── attack_surface_scanner.py # Asset discovery
│   │   └── implementations/      # Tool-specific modules
│   │       ├── bbot.py           # BBbot integration
│   │       ├── nuclei/           # Nuclei scanner variants
│   │       ├── portscan/         # Port scanning tools
│   │       └── openvas/          # OpenVAS integration
│   ├── models/                   # Data models
│   │   └── vulnerability.py      # Vulnerability data structures
│   ├── integrations/             # External API integrations
│   └── tools/                    # Utility tools and scripts
├── config/                       # Configuration files
├── data/                         # Security datasets
├── docker/                       # Docker configuration
├── docs/                         # Documentation
├── sql/                          # Database schemas
├── tests/                        # Test suites
└── scripts/                      # Deployment scripts
```

### Scanner Architecture

The framework uses a factory pattern with inheritance hierarchy:

```python
BaseScanner (Abstract)
├── PassiveScanner      # Mode 1: Light reconnaissance
├── NormalScanner       # Mode 2: Standard scanning  
├── AggressiveScanner   # Mode 3: Full scanning
└── AttackSurfaceScanner # Mode 4: Attack surface mapping
```

Each scanner encapsulates:
- Tool orchestration and execution
- Result processing and enrichment
- Database storage operations
- Error handling and recovery

---

## Usage

### Command Line Options

```bash
python src/cli/main.py [OPTIONS]

Required Arguments:
  -t, --target TARGET          Target(s) to scan (CIDR, IP, domain)
  -m, --mode {1,2,3,4,5}      Scanning mode (see modes above)
  -d, --domain DOMAIN         Organization name for database

Optional Arguments:
  --bruteforce                Enable brute force attacks
  --bruteforce-timeout SEC    Brute force timeout (default: 300)
  -env, --envfile FILE        Environment file location
  -h, --help                  Show help message
```

### Examples

**1. Passive Reconnaissance:**
```bash
python src/cli/main.py -t "target.com" -m 1 -d "myorg"
```

**2. Network Range Scanning:**
```bash
python src/cli/main.py -t "192.168.1.0/24" -m 2 -d "internal_audit"
```

**3. Aggressive Assessment with Brute Force:**
```bash
python src/cli/main.py -t "target.com" -m 3 -d "pentest" --bruteforce
```

**4. Attack Surface Mapping:**
```bash
python src/cli/main.py -t "company.com" -m 4 -d "redteam"
```

**5. Enterprise Vulnerability Scan:**
```bash
python src/cli/main.py -t "10.0.0.0/8" -m 5 -d "enterprise_scan"
```

### Environment Configuration

Create a `.env` file in the project root:

```bash
# Database Configuration
DB_HOST=mariadb
DB_NAME=darkstar
DB_USER=scanner_user
DB_PASSWORD=secure_password

# API Keys
HIBP_KEY=your_hibp_api_key

# OpenVAS Configuration  
OPENVAS_USER=admin
OPENVAS_PASSWORD=secure_openvas_password
```

---

## Documentation

### Core Documentation

- [**Architecture Guide**](ARCHITECTURE.md) - Detailed system architecture
- [**Configuration Guide**](docs/CONFIGURATION.md) - Setup and configuration
- [**Deployment Guide**](docs/DEPLOYMENT.md) - Production deployment
- [**API Reference**](docs/API.md) - Internal API documentation

### Tool-Specific Guides

- [**Scanner Development**](docs/SCANNER_DEVELOPMENT.md) - Creating custom scanners
- [**Database Schema**](docs/DATABASE.md) - Database structure and queries
- [**Integration Guide**](docs/INTEGRATIONS.md) - External service integrations

### Security Datasets

Darkstar leverages high-quality threat intelligence:

- [**EPSS Scores**](https://www.first.org/epss/data_stats) - Exploit prediction scoring
- [**CISA KEV**](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - Known exploited vulnerabilities
- [**CVE Database**](https://cve.mitre.org/) - Common vulnerabilities and exposures

---

## Development

### Running Tests

```bash
# Unit tests
python -m pytest tests/unit/

# Integration tests  
python -m pytest tests/integration/

# All tests with coverage
python -m pytest tests/ --cov=src/
```

### Code Quality

```bash
# Linting
flake8 src/
black src/

# Type checking
mypy src/
```

### Adding New Scanners

1. Inherit from `BaseScanner`
2. Implement required methods
3. Register with `ScannerFactory`
4. Add tests and documentation

Example:
```python
from src.scanners.base_scanner import BaseScanner

class CustomScanner(BaseScanner):
    async def run(self):
        # Implementation here
        pass
```

---

## Security Considerations

⚠️ **Important Security Notes:**

1. **Change Default Passwords**: Update database and OpenVAS passwords before production use
2. **Network Isolation**: Run scans in isolated environments
3. **Permission Management**: Use least-privilege access principles
4. **Data Protection**: Encrypt sensitive scan results
5. **Compliance**: Ensure scans comply with organizational policies

---

## Contributing

We welcome contributions! Please see our [Contributing Guide](docs/CONTRIBUTING.md) for details.

### Quick Contribution Steps

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

---

## Lead Developers

- [![LinkedIn](https://i.sstatic.net/gVE0j.png) Joost Grunwald](https://www.linkedin.com/in/joost-grunwald-1a48a31b2)
- [![LinkedIn](https://i.sstatic.net/gVE0j.png) Patrick Kuin](https://www.linkedin.com/in/patrick-kuin-8a08a81b7)

---

## Support

- 📧 **Email**: support@darkstar-security.com
- 💬 **Discord**: [Join our community](https://discord.gg/darkstar)
- 🐛 **Issues**: [GitHub Issues](https://github.com/your-org/darkstar/issues)
- 📖 **Documentation**: [Full Documentation](https://docs.darkstar-security.com)

---

<p align="center">
  <sub>Built with ❤️ for the security community</sub>
</p>
