# FIM-Tool – File Integrity Monitoring  

[![Python 3](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/blue%20team-ready-brightgreen)](#)
[![Stars](https://img.shields.io/github/stars/fadilahmad47/FIM-Tool?style=social)](https://github.com/fadilahmad47/FIM-Tool/stargazers)
[![Forks](https://img.shields.io/github/forks/fadilahmad47/FIM-Tool?style=social)](https://github.com/fadilahmad47/FIM-Tool/network/members)

A fast, lightweight **File Integrity Monitoring (FIM)** tool  

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
### Customization Options
Edit `file_integrity_checker.py` or config for your needs:
- **Memory Threshold**: Set `MEMORY_THRESHOLD_MB = 200` (default: 500) for larger scans.
- **Hash Algo**: Use `--hash-algo sha512` for stronger security (fallback to MD5 on errors).
- **Config Paths**: Add your own in `config.example.json` (e.g., blacklist `/proc` for noise reduction).  

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

**Pro Tips & Precautions**:
- Run as non-root user to avoid risks.
- Backup data before scanning production dirs.
- Avoid critical paths like `/bin`, `/etc`, `/lib` unless testing.
- Update hashes regularly—static DBs miss new threats.  

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
## Contributing
Fork, PR, or issues welcome!  

## Author
**Fadil Ahmad**  
Cybersecurity Student • Blue-Team Builder • India  

**Connect**  
→ LinkedIn: [linkedin.com/in/fadilahmad47](https://linkedin.com/in/fadilahmad47)  


**Portfolio live & growing — star this repo if it helped you level up! ⭐**
