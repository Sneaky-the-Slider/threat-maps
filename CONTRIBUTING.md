# Contributing to Threat Maps

Thanks for considering contributing! This repo is meant to be a handy reference for cyber threat mapping resources.

## Development Setup

### Prerequisites

- **Python 3.8+** (scripts are written for Python 3.x)
- **pip** for package management
- **Git** for version control

### Environment Setup

1. **Clone the repo:**
   ```bash
   git clone https://github.com/Sneaky-the-Slider/threat-maps.git
   cd threat-maps
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and add your API keys (see [`.env.example`](./.env.example) for required variables).

### Code Style

- Follow **PEP 8** style guidelines
- Use **4 spaces** for indentation
- Keep lines under **100 characters** when possible
- Use **type hints** for function signatures (Python 3.5+)
- Add **docstrings** for public functions and classes

### Running Tests

Tests are located in the [`tests/`](./tests/) directory. Run them with:

```bash
python -m pytest tests/
```

Or for a specific test file:
```bash
python -m pytest tests/test_fetch_otx_sdk.py
```

### Running Scripts

All scripts are in the [`src/`](./src/) directory. Common entry points:

```bash
# Fetch threat data for a single IP
python src/fetch_threat_data.py --ip 8.8.8.8 --output data/ip_lookup.json

# Enrich IPs from a file via GreyNoise
python src/fetch_threat_data_greynoise.py --input ips.txt --output data/greynoise_enriched.json

# Run GNQL query (Enterprise key required)
python src/query_greynoise_gnql.py --api-key YOUR_KEY --query "classification:malicious" --output data/results.json

# Pull OTX TAXII STIX indicators
python src/fetch_threat_data_otx_taxii_stix.py --api-key YOUR_KEY --collection user_yourname --output data/otx.json

# View map demo
python -m http.server 8000
# Then open: http://localhost:8000/src/generate_map.html
```

See individual scripts with `--help` for all options.

## How to Contribute

### 1. Add Data Sources
Found a new threat feed or API? Add it to [`docs/data-sources.md`](./docs/data-sources.md).

### 2. Add Scripts
Have a useful script for fetching or visualizing threat data? Put it in [`src/`](./src/).

### 3. Fix Issues
Found a broken link or outdated info? Open an issue or submit a PR.

## Guidelines

- **Keep it organized** - Follow the existing folder structure
- **Document new additions** - Add descriptions to any new files
- **Test your scripts** - Make sure code works before submitting
- **No secrets** - Don't commit API keys or passwords (use the secrets repo)
- **Use environment variables** - Store API keys in `.env`, never hardcode

## Pull Request Process

1. Fork the repo
2. Create a branch (`git checkout -b feature/new-feed`)
3. Make your changes
4. Run tests to ensure nothing is broken
5. Commit with clear messages
6. Push and open a PR

## Questions?

Open an issue for any questions or suggestions.
