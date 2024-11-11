# NetProbe - Network and Directory Scanner

NetProbe is a powerful tool designed to help security professionals and network administrators scan networks, detect open ports, resolve IP addresses, and identify hidden directories. It supports multiple scan types, IP geolocation, and allows for easy navigation and monitoring through a user-friendly graphical interface.

## Features

- **Target Scanning**: Supports multiple scan types:
  - **SYN ACK Scan**: Scans common ports using SYN-ACK packets.
  - **UDP Scan**: Scans for open UDP ports.
  - **Comprehensive Scan**: Performs a thorough scan with detailed information.
  
- **Geolocation**: Automatically retrieves the geolocation of IP addresses and plots them on an interactive map.
  
- **Hidden Directory Discovery**: Integrates with Gobuster to discover hidden directories on web servers.
  
- **Proxy Chain Detection**: Detects the presence of proxy chains in the network.

- **Interactive UI**: Provides a clean and responsive user interface with customizable themes (light/dark mode).

- **Log Saving**: Save the scan results and logs in a text file for later reference.

- **Documentation & User Feedback**: Access the user documentation and submit feedback directly from the interface.

## Requirements

To use NetProbe, you will need the following tools installed:

- **Nmap**: A powerful network scanner for detecting open ports and services.
- **Gobuster**: A tool for discovering hidden directories on web servers.
- **Python 3.x** and the following dependencies:
  - `tkinter` for the graphical user interface.
  - `ttkthemes` for themed widgets.
  - `termcolor` for colored output in the terminal.
  - `Pillow` for handling images.
  - `pyfiglet` for creating ASCII banners.
  - `requests` for HTTP requests and geolocation.
  - `scapy` for network packet manipulation.
  - `folium` for generating interactive maps.

### Install the required dependencies using `pip`:

```bash
pip install ttkthemes termcolor pillow pyfiglet requests scapy folium
```

Also, ensure **Nmap** and **Gobuster** are installed on your system.

## Usage

### 1. Running the application

```bash
python netprobe.py
```

### 2. Scanning

- **Enter Target**: Type an IP address or domain name in the input field.
- **Select Scan Type**: Choose the type of scan to perform:
  1. **SYN ACK Scan**: Scans common ports using SYN-ACK packets.
  2. **UDP Scan**: Scans for open UDP ports.
  3. **Comprehensive Scan**: A thorough scan with detailed results.
  
- **View Results**: The scan results will appear in the log window. Any discovered directories will be listed, and you can choose to visit them in your web browser.
- **Geolocation**: NetProbe will automatically retrieve and display the geolocation of the IP address on an interactive map.
  
### 3. Saving Logs

After a scan, you can save the log by navigating to the "File" menu and selecting "Save Log."

### 4. Switching Themes

Switch between light and dark themes using the "Theme" menu in the top bar.

### 5. User Feedback

You can provide feedback on the tool using the "User Feedback" option in the "Help" menu.

## License

NetProbe is open-source and available for use under the MIT License.

## Disclaimer

NetProbe is intended for educational and legal penetration testing use only. Ensure you have permission before scanning any network. Unauthorized scanning or probing of networks may be illegal in your jurisdiction.

## Author

NetProbe was developed by **Yohannes**. If you have any questions or suggestions, feel free to reach out via email or the GitHub repository.

