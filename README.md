# Vulnerability Scanner

A web-based vulnerability scanner built with Python, Nmap, and Flask. This tool helps small businesses identify potential security vulnerabilities in their network infrastructure.

## Features

- Quick and full network scans
- Port scanning and service detection
- Basic vulnerability assessment
- PDF report generation
- Modern web interface
- Real-time scan results

## Prerequisites

- Python 3.8 or higher
- Nmap installed on your system
- Root/Administrator privileges (required for Nmap scanning)

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd vulnerability-scanner
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

4. Install Nmap:
- On Ubuntu/Debian:
```bash
sudo apt-get install nmap
```
- On macOS:
```bash
brew install nmap
```
- On Windows:
Download and install from [Nmap's official website](https://nmap.org/download.html)

## Usage

1. Start the application:
```bash
sudo python app.py  # Note: sudo is required for Nmap scanning
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

3. Enter the target IP address or hostname and select the scan type:
   - Quick Scan: Basic port scan and service detection
   - Full Scan: Comprehensive scan with vulnerability checks

4. Click "Start Scan" and wait for the results

5. View the results in the web interface and download the PDF report

## Security Considerations

- Always obtain proper authorization before scanning any network
- Be aware that aggressive scanning might trigger security systems
- Some scans may be illegal if performed without permission
- Use responsibly and ethically

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and legitimate security testing purposes only. The authors are not responsible for any misuse or damage caused by this program. 