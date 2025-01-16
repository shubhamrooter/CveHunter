# CVE Hunter

CVE Hunter is a powerful and user-friendly tool for scanning domains or IP addresses to detect vulnerabilities (CVEs). Designed for cybersecurity professionals, it provides efficient domain/IP scanning, interactive mode, and export options for results.

## Features

- Scan single or multiple domains/IP addresses.
- Export results in JSON or CSV format.
- Interactive mode for a better user experience.
- Easy-to-use CLI interface.

## Installation

Follow these steps to install CVE Hunter:

```bash
┌──(rooter㉿rooter)-[/tmp/CveHunter]
└─$ git clone https://github.com/shubhamrooter/CveHunter.git

┌──(rooter㉿rooter)-[/tmp/CveHunter]
└─$ cd CveHunter

┌──(rooter㉿rooter)-[/tmp/CveHunter]
└─$ chmod +x cvehunter/cvehunter.py

┌──(rooter㉿rooter)-[/tmp/CveHunter]
└─$ pip install .
```

## Usage

Once installed, use the following commands to run CVE Hunter:

### Basic Help Command

```bash
┌──(rooter㉿rooter)-[/tmp/CveHunter/cvehunter]
└─$ cvehunter -h
```

### Output Example

```bash
╭─────────────────────────── Welcome to CVE Hunter ────────────────────────────╮
│                                                                              │
│  ▄████▄ ██▒   █▓▓█████  ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓▓█████  ██▀███   │
│ ▒██▀ ▀█▓██░   █▒▓█   ▀ ▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒ │
│ ▒▓█    ▄▓██  █▒░▒███   ▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒ │
│ ▒▓▓▄ ▄██▒▒██ █░░▒▓█  ▄ ░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄   │
│ ▒ ▓███▀ ░ ▒▀█░  ░▒████▒░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒ │
│ ░ ░▒ ▒  ░ ░ ▐░  ░░ ▒░ ░ ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░ │
│   ░  ▒    ░ ░░   ░ ░  ░ ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░     ░ ░  ░  ░▒ ░ ▒░ │
│ ░           ░░     ░    ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░         ░     ░░   ░  │
│ ░ ░          ░     ░  ░ ░  ░  ░   ░              ░             ░  ░   ░      │
│ ░           ░                                                                │
│                                github:- @Shubhamrooter | Version: 1.0.0      │
│                                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### Command-Line Options

```text
usage: cvehunter [-h] [-d DOMAIN] [-f FILE] [-o OUTPUT] [--export {json,csv}] [--interactive]

Ultimate CVE Hunter Tool

options:
  -h, --help            Show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        IP address or domain to scan
  -f FILE, --file FILE  File containing list of domains/IPs to scan
  -o OUTPUT, --output OUTPUT
                        Output file to store the results (e.g., result.txt)
  --export {json,csv}   Export results in JSON/CSV format
  --interactive         Run in interactive mode
```

## Examples

### Scan a Single Domain
```bash
cvehunter -d example.com
```

### Scan Multiple Domains from a File
```bash
cvehunter -f domains.txt
```

### Export Results to JSON
```bash
cvehunter -d example.com --export json -o results.json
```

### Run in Interactive Mode
```bash
cvehunter --interactive
```

## Contributions

CVE Hunter is open for contributions! Feel free to submit issues, feature requests, or pull requests to help improve the tool.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contact

Connect with Shubham via:
- **Email**: [info@shubhamrooter.com](mailto:info@shubhamrooter.com)
- **LinkedIn**: [https://www.linkedin.com/in/shubham-tiwari09](https://www.linkedin.com/in/shubham-tiwari09)
- **Twitter**: [https://twitter.com/shubhamtiwari_r](https://twitter.com/shubhamtiwari_r)

---
**GitHub Repository**: [CVE Hunter](https://github.com/shubhamrooter/CveHunter)

For queries or issues, contact **@Shubhamrooter** on GitHub.
