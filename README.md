# FIM-Tool – File Integrity Monitoring (Enhanced)

[![Python 3](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/blue%20team-ready-brightgreen)](#)
[![Stars](https://img.shields.io/github/stars/fadilahmad47/FIM-Tool?style=social)](https://github.com/fadilahmad47/FIM-Tool/stargazers)
[![Forks](https://img.shields.io/github/forks/fadilahmad47/FIM-Tool?style=social)](https://github.com/fadilahmad47/FIM-Tool/network/members)

A fast, lightweight **File Integrity Monitoring (FIM)** tool built for **SOC L1 analysts, sysadmins, and blue-team beginners**.

###  Features
- Multi-hash support: `md5` | `sha256` | `sha512` (default: `md5`)
- Whitelist / Blacklist via JSON config (skip noisy dirs, prioritize critical paths)
- Memory usage monitoring with early-stop
- Clear priority tagging for whitelisted paths
- Ready for SIEM integration & alerting extensions

## Quick Start (30 seconds)

```bash
# 1. Clone & enter
git clone https://github.com/fadilahmad47/FIM-Tool.git
cd FIM-Tool

# 2. Set up venv
python3 -m venv .venv && source .venv/bin/activate

# 3. Install
pip install -r requirements.txt

# 4. Run demo
python file_integrity_checker.py test/ hashes.txt --hash-algo sha256
```

### Sample Config (config.json) | *Optional*
```
json{
  "blacklist": ["/tmp", "/var/log/journal", "/home/kali/Downloads"],
  "whitelist": ["/etc/passwd", "/etc/ssh/sshd_config", "/var/www"]
}
```
### Run with config:
```
bash
python file_integrity_checker.py /etc hashes.txt --hash-algo sha512 --config config.json
```

### Demo Output
```
textScanning test/ with SHA256...
Checked: test/good.txt (hash: 0c15e883...)
Checked: test/bad.txt (hash: 4f48b4f2...)
Mismatches found (1):
- test/bad.txt
```

###  :file_folder: File Structure
```
FIM-Tool/
├── file_integrity_checker.py    ← Main script (fully commented)
├── test/                        ← Demo files (good.txt + tampered bad.txt)
├── hashes.txt                   ← Baseline SHA-256 hashes
├── config.json                  ← Example config
├── requirements.txt
├── .gitignore
└── README.md                    ← You are here
```

## Author
**Fadil Ahmad**  
Cybersecurity Student • Blue-Team Builder • India  

**Connect**  
→ LinkedIn: [linkedin.com/in/fadilahmad47](https://linkedin.com/in/fadilahmad47)  


**Portfolio live & growing — star this repo if it helped you level up! ⭐**
