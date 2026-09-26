# SecureMailScope

**A passive forensic tool that reads saved email traffic (SMTP, IMAP, POP3) and tells you how safe its encryption is.**

Smart India Hackathon 2026 | Software | NTRO: Blockchain & Cybersecurity

## The problem
Email servers often use weak encryption, expired certificates, or can be tricked into sending mail with no encryption at all (a STARTTLS downgrade). Most tools test live servers. We analyze **captured traffic (PCAP files)**, so nothing is probed and nothing is touched.

## What it does
Give it a PCAP file. It gives back a **risk score with a plain-English reason** for every email session.

## What is built and tested
- Reads SMTP, IMAP and POP3 sessions from PCAP files
- Reads the TLS handshake: version, cipher, key exchange, certificates
- Checks certificates: expiry, chain linking, key size, signature algorithm
- Detects plaintext logins and leaked credentials
- Detects STARTTLS downgrade (encryption skipped)
- Scores risk with rules + ML (Isolation Forest, Random Forest, SHAP explanations)
- FastAPI backend and Streamlit dashboard
- Real test lab: 16+ captures made with Docker mail servers (good and bad TLS setups)

## How it works
PCAP → Stream extraction → TLS parser → Certificate rules → AI risk engine → API → Dashboard

## Screenshots
![Dashboard](08-reports-docs/screenshots/dashboard.png)

## How to run