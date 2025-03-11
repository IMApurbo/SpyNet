# SpyNet

Advanced ARP Spoofing Engine

This tool is for use in illustrative examples in network security documentation. You may use SpyNet in literature without prior coordination or asking for permission.

More information...

## Overview

SpyNet is a Python-based network security tool designed for advanced ARP spoofing and HTTP/HTTPS traffic sniffing. It allows users to intercept network traffic, capture HTTP URLs, and extract HTTPS domains on a local network. The tool features a user-friendly interface with animated visuals, rich terminal tables, and progress bars.

### Features
- **ARP Spoofing**: Perform man-in-the-middle (MITM) attacks by spoofing ARP packets between target devices and the gateway.
- **HTTP Sniffing**: Capture HTTP requests (GET/POST) with full URLs, headers, and body data.
- **HTTPS Domain Extraction**: Extract domains (e.g., `example.com`) from HTTPS traffic using Server Name Indication (SNI).
- **Rich Terminal Interface**: Display captured data in styled tables with separate formats for HTTP and HTTPS traffic.
- **CSV Logging**: Save captured data to a CSV file for later analysis.
- **Cross-Platform Compatibility**: Works on Linux/Unix systems with root privileges.

**Note**: This tool is intended for educational and authorized security testing purposes only. Unauthorized use on networks or devices you do not own or have permission to test is illegal and unethical.

## Installation

### Prerequisites
- **Operating System**: Linux/Unix (tested on Ubuntu, Kali Linux).
- **Python**: Python 3.8 or higher.
- **Root Privileges**: The script requires root access to perform ARP spoofing and packet sniffing.
- **Network Access**: Must be on the same local network as the target devices.

### Installation Steps
1. **Clone the Repository** (or download the script):
   ```bash
   git clone https://github.com/IMApurbo/SpyNet.git
   cd spynet
   ```

2. **Install Dependencies**:
   ```bash
   pip install requirements.txt
   ```

## Usage

### Basic Usage
1. Run the script with root privileges:
   ```bash
   sudo python spynet.py
   ```

2. Follow the interactive prompts:
   - Select a network interface (e.g., `eth0`, `wlan0`).
   - Choose target devices to spoof (by index, comma-separated, or `all`).
   - Decide whether to save results to a CSV file (default: yes).

3. The script will:
   - Perform ARP spoofing to intercept traffic.
   - Sniff HTTP and HTTPS traffic, displaying results in real-time tables.
   - Save POST requests and HTTPS domains to the specified CSV file (if enabled).

4. To stop the script, press `Ctrl+C`. It will restore ARP tables and shut down gracefully.

### Command-Line Arguments
- `-o` or `--output`: Specify an output CSV file directly (bypasses the prompt).
  ```bash
  sudo python spynet.py -o /path/to/output.csv
  ```

### Output
- **HTTP Table**: Displays timestamp, request type (GET/POST), URL, source/destination IPs, headers, and body (magenta header).
- **HTTPS Table**: Displays timestamp, type (HTTPS), domain, and source/destination IPs (red header).
- **CSV File** (if enabled): Logs HTTP POST requests and HTTPS domains with timestamps and IP details.
### ScreenShot
![Screenshot_2025-03-11_09_26_24](https://github.com/user-attachments/assets/cfdca7f1-cb70-456f-9ac2-37ff82c1deef)

#### Example Output
**HTTP Table**:
```
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Timestamp           ┃ Type  ┃ URL                  ┃ Source IP    ┃ Destination IP ┃ Header        ┃ Body          ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ 2025-03-11 12:34:56 │ GET   │ http://example.com   │ 192.168.1.100 │ 93.184.216.34  │ Host: example │ [Body data]   │
└─────────────────────┴───────┴──────────────────────┴──────────────┴──────────────┴───────────────┴───────────────┘
```

**HTTPS Table**:
```
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Timestamp           ┃ Type  ┃ Domain     ┃ Source IP    ┃ Destination IP ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ 2025-03-11 12:35:00 │ HTTPS │ example.com │ 192.168.1.100 │ 93.184.216.34 │
└─────────────────────┴───────┴────────────┴──────────────┴──────────────┘
```

## Troubleshooting
- **Permission Errors**: Ensure you run the script with `sudo`.
- **No Devices Found**: Verify you’re on the correct network and interface.
- **HTTPS Domains Not Showing**: Ensure the target device is making HTTPS requests, and check for TLS Client Hello packets.
- **Scapy/Netifaces Conflicts**: On some systems (e.g., Mac OS with VirtualBox), there may be compatibility issues. Test on a Linux system if problems occur.

## Contributing
Contributions are welcome! Please fork the repository, make your changes, and submit a pull request. Ensure your code follows PEP 8 guidelines and includes appropriate documentation.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Disclaimer
This tool is for educational and authorized use only. The authors are not responsible for any misuse or damage caused by this software. Always obtain explicit permission before testing on any network or device.

## Contact
For questions or support, open an issue on GitHub or contact the maintainers.
