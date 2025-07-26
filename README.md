
# 🕵️‍♂️ IOC-Digger

**IOC-Digger** is a Python-based tool designed to extract Indicators of Compromise (IOCs) from `.eml` email files. It can identify and display IP addresses, URLs, header metadata, and calculate hashes of any attachments found.

---

## 📌 Features

- ✅ Extracts **IPv4** and **IPv6** addresses
- ✅ Extracts **URLs**
- ✅ Parses and displays important **email headers**
- ✅ Detects and lists **attachments** with their **MD5, SHA-1, and SHA-256 hashes**
- ✅ Supports decoding of **quoted-printable encoded** email content

---

## 📂 Requirements

- Python 3.6+
- No external libraries required (uses only Python standard library)

---

## 🚀 Usage

1. Save the script as `IOC-Digger.py`
2. Open a terminal and run:

```bash
python3 IOC-Digger.py
```

3. Enter the path to your `.eml` file when prompted:

```
Enter the filename with accurate path : /path/to/email.eml
```

4. The tool will output extracted IOCs and attachment hash values.

---

## 📥 Sample Output

```
=============== IPV4 ADDRESSES ===============
192.168.1.1

=============== IPV6 ADDRESSES ===============
fe80::1

=============== URL EXTRACTED ===============
http://malicious.example.com

=============== EXTRACTED HEADERS ===============
From: attacker@example.com
Subject: You've been phished!
...

=============== ATTACHMENT FOUND ===============
Attachment: invoice.pdf
  MD5:     e99a18c428cb38d5f260853678922e03
  SHA-1:   a9993e364706816aba3e25717850c26c9cd0d89d
  SHA-256: 9c56cc51b3744d7e607fc7475e3a6fd15cbbeb27d1e621c6a8abf32ed7bdb0c8
```

---

## 🔐 Disclaimer

This tool is meant for **educational and forensic analysis** purposes. Do not use it on emails or data that you do not have permission to analyze.

---

## 👨‍💻 Author

Created by **Ritik Singhania**  
Inspired by practical threat intelligence and forensic analysis workflows.

---

## 📃 License

MIT License — free to use, modify, and distribute.
