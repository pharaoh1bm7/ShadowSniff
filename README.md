# ShadowSniff

**ShadowSniff** is a lightweight, terminal-based network attack detection tool. It monitors your local network in real-time for suspicious traffic patterns like ICMP floods, SYN floods, UDP floods, and port scanning — all while silently logging everything to a secure and private Google Sheet.

It’s built for security researchers, penetration testers, and students who want a portable and discreet solution that works out of the box.

---

## 🔍 Key Features

- ⚡ **Live detection** of:
  - ICMP Echo Floods
  - TCP SYN Floods
  - UDP Floods
  - Port Scanning attempts
- 🖥️ **Live terminal UI** using `rich` (inspired by tools like `netdiscover`)
- ☁️ **Secure cloud logging** to Google Sheets via API
- 🕶️ **Stealth Mode** – no local traces, no files saved on disk
- 🔓 **Open-source & beginner-friendly**

---

## 📦 Requirements

```bash
pip install scapy rich gspread oauth2client
