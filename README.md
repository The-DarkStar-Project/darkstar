# Darkstar - Advanced Vulnerability Management  
<img src="logo.png" alt="Darkstar Logo" width="300" height="300">

### The ultimate **Red Team** and **Blue Team** tool for attack surface mapping and vulnerability management!  

## 🌟 Features  
- **Multi-Scanner Integration**: Supports Nuclei, OpenVAS, BBbot, RustScan, and more
- **Modular Architecture**: Clean, extensible codebase with clear separation of concerns
- **Database Integration**: MySQL/MariaDB support for vulnerability storage and reporting
- **Docker Support**: Containerized deployment for easy setup and scaling
- **CLI Interface**: Intuitive command-line interface for all operations
- **Comprehensive Reporting**: Detailed vulnerability reports with severity classification
- **API Integrations**: HaveIBeenPwned, CVE databases, and more
- **Dashboard insight**: into vulnerabilities 
- **Attack Surface mapping**: Complete attack surface discovery
- **Easy deployment**: via Docker  

---

## 📁 New Project Structure

```
darkstar/
├── src/                           # Main source code
│   ├── cli/                      # Command-line interface
│   │   └── main.py              # Main entry point
│   ├── core/                    # Core utilities and configuration
│   ├── models/                  # Data models
│   ├── scanners/               # Scanner implementations
│   ├── integrations/           # External service integrations
│   └── tools/                  # Utility tools
├── docs/                      # Comprehensive documentation
├── docker/                    # Docker configurations
└── config/                    # Configuration files
```

## Requirements  
Before installing, ensure you have the following tools:  

- [Docker](https://docs.docker.com/get-docker/)  
- [Docker Compose](https://docs.docker.com/compose/install/)  
- Python 3.8+ (for manual installation)

## 🚀 Quick Setup with Docker  

1. Clone and setup:
   ```bash
   git clone https://github.com/your-org/darkstar.git
   cd darkstar
   ```

2. Configure environment:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. Grant execution permission and start:  
   ```bash
   chmod +x scripts/run.sh
   ./scripts/run.sh
   ```

## 🐳 Using Docker Commands

### Inside the container (NEW STRUCTURE)
- To run a scan with the new structure:
```bash
# Run basic scan
docker exec -it darkstar python3 src/cli/main.py --target testphp.vulnweb.com --mode normal

# Run aggressive scan with bruteforce
docker exec -it darkstar python3 src/cli/main.py --target testphp.vulnweb.com --mode aggressive --bruteforce

# Run WordPress-specific scan
docker exec -it darkstar python3 src/cli/main.py --target wordpress-site.com --scanner wordpress-nuclei

# Get help
docker exec -it darkstar python3 src/cli/main.py --help
```

### Legacy Commands (Still Supported)
- Legacy command structure (for backward compatibility):
```bash
docker exec -it darkstar python3 main.py -t testphp.vulnweb.com,44.228.249.3 -m 2 -d test -env .env
```

## 📖 Usage Examples

### Basic Scanning
```bash
# Nuclei scan
docker exec -it darkstar python3 src/cli/main.py --target example.com --scanner nuclei

# Port scan
docker exec -it darkstar python3 src/cli/main.py --target example.com --scanner rustscan

# OpenVAS scan
docker exec -it darkstar python3 src/cli/main.py --target example.com --scanner openvas
```

### Advanced Scanning
```bash
# Multiple targets
docker exec -it darkstar python3 src/cli/main.py --target "example.com,test.com" --mode aggressive

# Passive reconnaissance
docker exec -it darkstar python3 src/cli/main.py --target example.com --mode passive

# Attack surface mapping
docker exec -it darkstar python3 src/cli/main.py --target example.com --mode attack-surface
```

## 📚 Documentation

- **[User Guide](docs/README.md)**: Complete user documentation
- **[Configuration Guide](docs/CONFIGURATION.md)**: Setup and configuration
- **[Deployment Guide](docs/DEPLOYMENT.md)**: Production deployment
- **[Architecture Guide](ARCHITECTURE.md)**: System design and architecture
- **[Contributing Guide](CONTRIBUTING.md)**: Development guidelines

## 🛠️ Manual Installation

```bash
# Clone the repository
git clone https://github.com/your-org/darkstar.git
cd darkstar

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Run the scanner
python3 src/cli/main.py --help
```

## Datasets
Darkstar leverages high quality threat intelligence sources:
- [Epss Scores](https://www.first.org/epss/data_stats) – Probabilistic vulnerability prioritization
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) – Known exploited vulnerabilities

## 🔒 Security Tip
Please change the database password if running in production environment. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for security best practices.

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Lead Developers
- [![LinkedIn](https://i.sstatic.net/gVE0j.png) Joost Grunwald](https://www.linkedin.com/in/joost-grunwald-1a48a31b2)
- [![LinkedIn](https://i.sstatic.net/gVE0j.png) Patrick Kuin](https://www.linkedin.com/in/patrick-kuin-8a08a81b7)

### License
This project is licensed under [GNU GPLv3](LICENSE)