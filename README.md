# 🚗 ELM327 Gateway - Autotech AI

One-click OBD-II diagnostic bridge. Connects your ELM327/OBDLink MX+ adapter to Autotech AI's cloud diagnostic system.

**Install once, forget about it.** The app sits in your system tray, auto-detects your adapter, and auto-connects to the server.

---

## Quick Start (Windows)

### 1. Prerequisites

- Windows 10/11
- Python 3.10+ → [Download here](https://www.python.org/downloads/)
  - ⚠️ **Check "Add Python to PATH"** during installation
- OBDLink MX+ paired via Bluetooth in Windows Settings
  - Settings → Bluetooth → Add device → find "OBDLink MX+"

### 2. Install

```cmd
git clone https://github.com/DRawson5570/autotech_ai_scantool.git
cd autotech_ai_scantool
pip install -r requirements.txt
```

### 3. First Run

```cmd
python -m elm327_gateway
```

On first run, you'll be prompted:
```
Enter your Shop ID (provided by Autotech AI): bros_auto
Enter your API Key (provided by Autotech AI): [press Enter if none]
Adapter port [auto-detect]: [press Enter for auto-detect, or type COM4]
```

The app will:
1. 🔍 Auto-detect your OBDLink MX+ on a COM port
2. 🖥️ Start a local gateway server
3. 🔗 Connect outbound to the Autotech AI server
4. 🟢 Appear in your system tray

### 4. Done!

Leave it running. When a tech uses Autotech AI diagnostics, it routes through your gateway automatically.

---

## How It Works

```
Your Laptop                     Autotech AI Server              Tech's Phone
┌──────────────┐    HTTPS out   ┌──────────────────┐           ┌──────────┐
│ Gateway App  │───────────────→│  WebSocket Proxy  │←──────────│ AI Chat  │
│  (tray icon) │                │                   │           │          │
│      ↕       │                └──────────────────┘           └──────────┘
│  Bluetooth   │
│      ↕       │
│  OBDLink MX+ │
│      ↕       │
│   Vehicle    │
└──────────────┘
```

- **Zero open ports needed** — the app connects *outbound* to the server
- **No firewall config** — works behind any firewall, NAT, or hotspot
- **Auto-reconnect** — if the connection drops, it reconnects automatically

---

## Configuration

Config is stored in `~/.autotech_gateway/config.json`:

```json
{
  "server_url": "https://automotive.aurora-sentient.net",
  "shop_id": "bros_auto",
  "api_key": "",
  "adapter_port": "",
  "adapter_type": "serial",
  "gateway_port": 8327,
  "auto_start": true
}
```

| Setting | Description |
|---------|-------------|
| `server_url` | Autotech AI server URL (don't change) |
| `shop_id` | Your unique shop identifier |
| `api_key` | Authentication key (optional during beta) |
| `adapter_port` | COM port (blank = auto-detect) |
| `adapter_type` | `serial` for Bluetooth, `wifi` for WiFi adapters |
| `gateway_port` | Local server port (default: 8327) |

---

## Building a Standalone .exe

To create a single executable that doesn't need Python installed:

```cmd
build.bat
```

This creates `dist\ELM327_Gateway\ELM327_Gateway.exe`.

Copy the entire `dist\ELM327_Gateway\` folder to any Windows machine.

---

## Troubleshooting

### "No ELM327 found"
1. Make sure the OBDLink MX+ is plugged into the car's OBD port
2. Turn the ignition ON (engine doesn't need to be running)
3. Verify Bluetooth is paired in Windows Settings
4. Check which COM port: Device Manager → Ports → "Standard Serial over Bluetooth link"
5. Try specifying the port manually in config.json: `"adapter_port": "COM4"`

### "Cannot reach server"
- Check your internet connection
- The app needs outbound HTTPS (port 443) access
- If behind a corporate proxy, that's not supported yet

### Logs
Check `~/.autotech_gateway/gateway.log` for detailed logs.

---

## Running Headless (No Tray Icon)

```cmd
python -m elm327_gateway --headless
```

Useful for running as a Windows service or on a Raspberry Pi.

---

## License

Proprietary — Autotech AI © 2026
