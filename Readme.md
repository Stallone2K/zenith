# Zenith - File Integrity Checker & Malware Scanner

Zenith is a powerful **file integrity monitoring tool** built with **GoLang**, designed to detect unauthorized file modifications, log changes, and scan for malware using **YARA rules**.

## 🚀 Features

- ✅ **File Integrity Checking**: Detects any unauthorized changes in monitored files.
- 🔍 **Malware Scanning**: Uses YARA to detect potential malware in files.
- 📄 **Configurable Watchlist**: Specify directories and files to monitor.
- 📢 **Alerts & Logging**: Sends alerts via webhook, SMTP, or logs suspicious changes.
- 🔒 **Tamper-Proof Logs**: Encrypted logging to prevent unauthorized modifications.

---

## 📦 Installation

### **Prerequisites**

- **Go 1.21+** (Install from [golang.org](https://go.dev/dl/))
- **YARA** (Install via package manager)
  - **Mac**: `brew install yara`
  - **Linux (Debian/Ubuntu)**: `sudo apt install yara`
  - **Windows**: [Download YARA](https://github.com/VirusTotal/yara/releases)

### **Clone & Build**

```sh
git clone https://github.com/yourusername/Zenith.git
cd Zenith
go build -o zenith .
```

### **Run the Tool**

```sh
./zenith
```

---

## 🔧 Usage

### **1. Verify File Integrity**

```sh
./zenith
```

Select **Option 1** and the tool will scan tracked files for changes.

### **2. Update File Hash**

```sh
./zenith
```

Select **Option 2**, then enter the file path to update its hash in `hashes.json`.

### **3. Scan for Malware**

```sh
./zenith
```

Select **Option 3**, then enter the file path and the YARA rule file.

Alternatively, run manually:

```sh
yara rules.yar suspicious-file.exe
```

---

## ⚙️ Configuration

Zenith supports a configurable `config.json` where you can:

- Define directories to monitor.
- Set alert preferences (email/webhooks).
- Customize logging options.

Example:

```json
{
  "watchlist": ["/var/logs", "/etc/ssh"],
  "alerts": {
    "email": "admin@example.com",
    "webhook": "https://hooks.slack.com/..."
  }
}
```

---

## 📜 License

Zenith is licensed under the **MIT License**.

---

## 🤝 Contributing

We welcome contributions! To contribute:

1. Fork the repo
2. Create a new branch (`git checkout -b feature-name`)
3. Commit changes (`git commit -m "Added new feature"`)
4. Push to your branch (`git push origin feature-name`)
5. Open a **Pull Request**

For major changes, please open an issue first to discuss.

---

## 🛠 Future Enhancements

- 📡 **Real-time Monitoring**
- 🛑 **Automatic Quarantine for Malicious Files**
- 🔍 **Advanced Heuristic Analysis with AI**

Stay tuned! 🚀
