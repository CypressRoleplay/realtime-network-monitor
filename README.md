# 🌐 Real-Time Process Network Monitor
*A sleek, real-time process network connection monitoring tool built by Cypress Studios.*

---

## ✨ Features
- 🔍 Real-time monitoring of all process network activity  
- 🎯 Filter by protocol, state, or socket type  
- 💾 Export connection data to CSV with one click  
- ❌ Terminate suspicious processes instantly via right-click  
- 🧠 Lightweight, responsive PyQt5 interface  
- 🔐 Built for visibility, control, and clarity  

---

## 🛠️ Installation

```bash
git clone https://github.com/cypress-studios/process-network-monitor.git
cd process-network-monitor
pip install -r requirements.txt
python network_monitor.py
```

> ⚠️ **Run with admin privileges** for full network visibility:  
> - On **Windows**: Right-click → “Run as Administrator”  
> - On **Linux/macOS**: Use `sudo python network_monitor.py`

---

## 🖥️ Usage

- Click **Refresh Now** to scan connections
- Filter by:
  - **Process name** (e.g. `firefox.exe`)
  - **Protocol** (TCP, UDP, OTHER)
  - **Status** (e.g. ESTABLISHED, LISTEN)
- Right-click a row to:
  - View full connection details
  - Terminate the process (with confirmation)
- Export results to CSV via **Export to CSV**
- Toggle:
  - **Verbose Logging**
  - **All Connections**
  - **All Statuses**

---

## 📊 Example Connections

```
PID 81128: TCP 192.168.0.248:51829 → 52.97.211.226:443 (ESTABLISHED)
PID 25460: TCP 127.0.0.1:6327 → 127.0.0.1:50064 (ESTABLISHED)
```

---

## 📦 Requirements

- Python 3.6+
- PyQt5
- psutil
- dnspython

Install via:

```bash
pip install -r requirements.txt
```

> 🧠 All logs are saved automatically to `network_daddy_YYYYMMDD_HHMMSS.log`

---

## 🤝 Contributing

Contributions are welcome!  
To contribute:

```bash
1. Fork the repository  
2. Create a new branch: git checkout -b feature/YourFeature  
3. Commit your changes: git commit -m "Add YourFeature"  
4. Push to the branch: git push origin feature/YourFeature  
5. Open a pull request  
```

Please follow the existing code style and include test cases where possible.

---

## 📜 License

MIT License  
© Cypress Studios

---

## 🧠 About Cypress Studios

Cypress Studios builds small, powerful open-source tools that empower users.  
No bloat. No noise. Just precision-crafted software built for control.
