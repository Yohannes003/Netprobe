import tkinter as tk
from tkinter import ttk, scrolledtext, simpledialog, messagebox, filedialog
from ttkthemes import ThemedStyle
from termcolor import colored
from PIL import Image, ImageTk  
import shutil
import pyfiglet
import logging
import subprocess
import nmap
import webbrowser
import requests
import socket
import ipaddress
import folium
from scapy.layers.inet import IP, ICMP
from scapy.all import sr1
import threading

class NetProbeGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("NetProbe")
        self.master.geometry("800x600")
        self.master.resizable(True, True)

        # Set the ThemedStyle
        self.style = ThemedStyle(master)
        self.style.set_theme("clam")  # Choose a modern theme
        self.style.configure('DarkTheme.TButton', background='#333333', foreground='#FFFFFF')  # Customize dark theme button

        # Set dark theme initially
        self.dark_theme = True

        # Company logo (replace 'netprobe_logo.png' with the actual logo file)
        logo_path = '/home/yohannes/Documents/python/NetProbe/netprobe_logo.png'
        logo_image = Image.open(logo_path)
        logo_image = ImageTk.PhotoImage(logo_image)

        logo_label = ttk.Label(self.master, image=logo_image)
        logo_label.photo = logo_image 
        logo_label.pack()
        
        # Custom font
        self.custom_font = ("Helvetica", 12, "bold")

        # Background color
        self.background_color = self.style.lookup('TFrame', 'background')  # Use theme background color

        # Foreground color
        self.foreground_color = "#00FF00"  # You can customize this color

        # Log text color
        self.log_text_color = self.style.lookup('TLabel', 'foreground')  # Use theme label text color

        # Creating the menu bar
        menubar = tk.Menu(master)
        master.config(menu=menubar)

        # Creating the file menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Log", command=self.save_log)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_application)

        # Creating the help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.open_documentation)
        help_menu.add_command(label="User Feedback", command=self.show_user_feedback_dialog)

        # Creating the theme switch button
        theme_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Theme", menu=theme_menu)
        theme_menu.add_command(label="Switch Theme", command=self.toggle_theme)

        # Creating input entry, scan button, progress bar, status bar, log text
        self.create_input_entry()
        self.create_scan_button()
        self.progress_bar = ttk.Progressbar(self.master, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.progress_bar.pack(pady=10)
        self.create_status_bar()
        self.create_log_text()  # Move this line up

        # Dark theme flag
        self.dark_theme = True
        self.update_theme()
        self.toggle_theme()

    def print_banner(self):
        banner = pyfiglet.figlet_format("Network and Hidden Directory Scanner", font="small")
        resized_banner = "*" * shutil.get_terminal_size().columns
        colored_banner = colored(resized_banner + "\n" + banner + "\n" + resized_banner, color="cyan")
        print(colored_banner)

    def print_welcome_banner(self):
        print("*" * 50)
        print("Welcome to NetProbe")
        print("*" * 50)

    def create_input_entry(self):
        self.target_entry = ttk.Entry(self.master, font=self.custom_font)
        self.target_entry.insert(tk.END, "Enter IP or Domain Name")
        self.target_entry.bind("<FocusIn>", self.clear_entry)
        self.target_entry.bind("<FocusOut>", self.restore_entry)
        self.target_entry.pack(pady=(20, 10), ipadx=5, ipady=5, fill=tk.X)

    def create_scan_button(self):
        scan_button = ttk.Button(self.master, text="Scan", command=self.scan_target, style="Hacker.TButton")
        scan_button.pack(pady=10)

    def create_status_bar(self):
        self.status_bar = ttk.Label(self.master, text="Ready", anchor=tk.W, style="Status.TLabel")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def create_log_text(self):
        log_frame = ttk.Frame(self.master, style="Hacker.TFrame", width=500, height=300)
        log_frame.pack_propagate(0)
        log_frame.pack(pady=(0, 10))

        log_label = ttk.Label(log_frame, text="Log:", font=self.custom_font, foreground=self.log_text_color,
                              background=self.background_color)
        log_label.pack(anchor=tk.W, pady=(0, 5))

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=50, height=10,
                                                  font=self.custom_font, foreground=self.log_text_color,
                                                  background=self.background_color)
        self.log_text.pack(side=tk.LEFT, fill=tk.Y)

        log_scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_text.config(yscrollcommand=log_scrollbar.set)

    def update_status_bar(self, message):
        self.status_bar.config(text=message)
        self.master.update_idletasks()

    def save_log(self):
        log_content = self.log_text.get("1.0", tk.END)
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(log_content)
            self.print_to_log(f"Log saved to {file_path}")

    def exit_application(self):
        if messagebox.askyesno("Exit", "Do you really want to exit?"):
            self.master.destroy()

    def show_about(self):
        messagebox.showinfo("About", "NetProbe v1.0\n\nA network and directory scanner\nDeveloped by Yohannes")

    def open_documentation(self):
        documentation_text = """
        NetProbe Documentation:
        -----------------------
        1. Enter the target IP or domain in the input field.
        2. Choose the scan type and click the 'Scan' button.
        3. Review scan results in the log.

        Additional Features:
        ---------------------
        - Save Log: Save the log to a text file.
        - Exit: Close the application.
        - About: Display information about NetProbe.
        - Documentation: Access the user documentation.
        - User Feedback: Provide feedback to the developer.

        Scan Types:
        ------------
        1. SYN ACK Scan: Scans common ports using SYN ACK packets.
        2. UDP Scan: Scans for open UDP ports.
        3. Comprehensive Scan: Performs a comprehensive scan with detailed information.

        Theme:
        -------
        - Switch between light and dark themes from the 'Theme' menu.

        Note: Ensure that Nmap and Gobuster are installed on your system for full functionality.
        """
        messagebox.showinfo("NetProbe Documentation", documentation_text)

    def show_user_feedback_dialog(self):
        feedback = simpledialog.askstring("User Feedback", "Please provide your feedback:")
        if feedback:
            messagebox.showinfo("Thank You!", "Thank you for providing feedback!")

    def resolve_target(self, target):
        try:
            ip_addresses = [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
            return ip_addresses
        except ValueError:
            try:
                ip_addr = socket.gethostbyname(target)
                return [ip_addr]
            except socket.gaierror as e:
                logging.error("Error resolving the target: " + str(e))
                return []

    def get_ip_geolocation(self, ip_address):
        try:
            response = requests.get(f"http://ipinfo.io/{ip_address}/json")
            response.raise_for_status()

            data = response.json()

            if "loc" in data:
                latitude, longitude = map(float, data["loc"].split(","))
                self.print_to_log(f"Geolocation for IP {ip_address}: Latitude {latitude}, Longitude {longitude}")

                # to generate the map after retrieving geolocation
                self.create_map([(latitude, longitude)], ip_address)

                return latitude, longitude
            else:
                self.print_to_log(f"Geolocation information not available for IP {ip_address}")
                return None, None

        except requests.exceptions.RequestException as e:
            logging.error(f"Error retrieving geolocation for IP {ip_address}: {e}")
            return None, None

    def visit_and_retrieve_directory(self, ip_addr, port_choice, discovered_directory, protocol="http"):
        url = f"{protocol}://{ip_addr}:{port_choice}/{discovered_directory}"
        try:
            webbrowser.open_new_tab(url)
            response = requests.get(url, verify=False)
            if response.status_code == 200:
                self.print_to_log("Directory contents:")
                self.print_to_log(response.text)
        except requests.RequestException as e:
            self.print_to_log(f"Error occurred while retrieving directory contents for {protocol}: {e}")

    def scan_ip(self, ip_addr, scan_type):
        logger = logging.getLogger()
        logger.info(f"Scanning IP address {ip_addr} using scan type {scan_type}...")
        scanner = nmap.PortScanner()
        nmap_version = scanner.nmap_version()
        logger.info("Nmap Version: " + str(nmap_version[0]))

        try:
            if scan_type == "1":
                scanner.scan(ip_addr, "1-1024", "-v -sS -O")
            elif scan_type == "2":
                scanner.scan(ip_addr, "1-1024", "-v -sU")
            elif scan_type == "3":
                scanner.scan(ip_addr, "1-65535", "-v -O -sS -sV -sC")

            if "tcp" in scanner[ip_addr]:
                open_tcp_ports = scanner[ip_addr]["tcp"].keys()
                if open_tcp_ports:
                    logger.info("Open TCP ports for " + ip_addr)
                    port_choice = simpledialog.askinteger("Enter Port",
                                                          "Enter the port number to scan for hidden directories (e.g., 80, 443): ")
                    port_choice = int(port_choice)
                    if port_choice in open_tcp_ports:
                        logger.info(
                            f"Port {port_choice} is open. Starting Gobuster scan for hidden directories on port {port_choice}...")

                        protocol = "https" if port_choice == 443 else "http"

                        if protocol == "https":
                            command = f"gobuster dir -u {protocol}://{ip_addr}:{port_choice}/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html -k -q"
                        else:
                            command = f"gobuster dir -u {protocol}://{ip_addr}:{port_choice}/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -q"

                        try:
                            process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                       text=True)
                            while True:
                                output = process.stdout.readline()
                                if output == '' and process.poll() is not None:
                                    break
                                if output:
                                    logger.info(output.strip())
                                    if output.startswith("Found directory"):
                                        discovered_directory = output.split(' ')[-1]
                                        logger.info(
                                            f"Discovered directory: {protocol}://{ip_addr}/{discovered_directory}")
                                        self.visit_and_retrieve_directory(ip_addr, port_choice, discovered_directory,
                                                                          protocol)
                            process.communicate()
                        except subprocess.CalledProcessError as e:
                            logger.error("Error occurred while executing Gobuster command: " + str(e))
                    else:
                        logger.info(f"Port {port_choice} is not open.")
                else:
                    logger.info("No open TCP ports found for " + ip_addr)
            else:
                logger.info("No open TCP ports found for " + ip_addr)
        except Exception as e:
            logger.error("Error scanning IP: " + str(e))

    def detect_proxy_chains(self, ip_addr):
        try:
            packet = IP(dst=ip_addr, ttl=(1, 2)) / ICMP()
            response = sr1(packet, timeout=2, verbose=0)

            if response and response.src != ip_addr:
                self.print_to_log(f"Possible use of proxy chains. Detected intermediate hop: {response.src}")
            else:
                self.print_to_log("No evidence of proxy chains detected.")

        except Exception as e:
            self.print_to_log(f"Error detecting proxy chains: {e}")

    def create_map(self, ip_addresses, original_ip):
        try:
            initial_location = ip_addresses[0]
            map_object = folium.Map(location=initial_location, zoom_start=10)

            for ip_addr in ip_addresses:
                latitude, longitude = self.get_ip_geolocation(ip_addr)
                if latitude is not None and longitude is not None:
                    folium.Marker([latitude, longitude],
                                  popup=f"{ip_addr} - {latitude}, {longitude}").add_to(map_object)

            file_path = f"interactive_map_with_geolocation_{original_ip}.html"
            map_object.save(file_path)

            self.print_to_log("Interactive map with geolocation generated:", file_path)

            self.detect_proxy_chains(original_ip)

        except Exception as e:
            self.print_to_log(f"Error creating map: {e}")

    def print_to_log(self, *args, **kwargs):
        log_message = " ".join(map(str, args))
        self.log_text.insert(tk.END, log_message + "\n")
        self.log_text.see(tk.END)
        self.update_status_bar("Ready")

    def scan_target(self):
        target = self.target_entry.get()

        if target.lower() in ['exit', 'quit', 'bye']:
            self.exit_application()

        try:
            log_file_name = f'network_scanner_for_{target}.log'
            logging.basicConfig(filename=log_file_name, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
            logger = logging.getLogger()
            logger.addHandler(logging.StreamHandler())
            ip_addresses = self.resolve_target(target)
            if not ip_addresses: 
                logger.error("Unable to resolve target. Exiting.")
                return

            for ip_addr in ip_addresses:
                logger.info(f"Resolved IP address for the target: {ip_addr}")

                self.get_ip_geolocation(ip_addr)

                resp = simpledialog.askinteger("Select Scan Type", "Select the type of scan to run:\n"
                                                            "1. SYN ACK scan\n"
                                                            "2. UDP scan\n"
                                                            "3. Comprehensive scan\n")

                try:
                    logger = logging.getLogger()
                    # Multi-threaded scanning
                    scan_thread = threading.Thread(target=self.scan_ip, args=(ip_addr, str(resp)))
                    scan_thread.start()

                    # Monitor progress with progress bar
                    self.monitor_scan_progress(scan_thread)

                    while True:
                        port_choice = simpledialog.askinteger("Enter Port",
                                                              "Enter the port number to visit the discovered directory (or type '0' to finish): ")
                        if port_choice == 0:
                            break
                        discovered_directory = simpledialog.askstring("Enter Directory",
                                                                      "Enter the discovered directory to visit: ")
                        protocol = simpledialog.askstring("Enter Protocol", "Enter the protocol (http or https): ").lower()

                        self.visit_and_retrieve_directory(ip_addr, port_choice, discovered_directory, protocol)

                    latitude, longitude = self.get_ip_geolocation(ip_addr)
                    self.create_map([(latitude, longitude)], target)

                    self.detect_proxy_chains(ip_addr)

                    # Store scan result in history
                    self.scan_history.append({'ip': ip_addr, 'scan_type': resp, 'result': 'Successful'})

                except ValueError as e:
                    logger.error("Error: " + str(e))
                    # Store scan result in history with an error message
                    self.scan_history.append({'ip': ip_addr, 'scan_type': resp, 'result': 'Error - ' + str(e)})

        except socket.gaierror as e:
            logging.error("Error resolving the IP address or domain name: " + str(e))

    def monitor_scan_progress(self, scan_thread):
        def update_progress():
            while scan_thread.is_alive():
                self.progress_bar.step(1)
                self.master.update_idletasks()
                scan_thread.join(timeout=1)

        progress_thread = threading.Thread(target=update_progress)
        progress_thread.start()
   
    def clear_entry(self, event):
        if self.target_entry.get() == "Enter IP or Domain Name":
            self.target_entry.delete(0, tk.END)
            self.target_entry.configure(foreground='black')

    def restore_entry(self, event):
        if not self.target_entry.get():
            self.target_entry.insert(tk.END, "Enter IP or Domain Name")
            self.target_entry.configure(foreground='grey')

    def toggle_theme(self):
        self.dark_theme = not self.dark_theme
        self.update_theme()

    def update_theme(self):
        # Manually set background color and text color based on the dark theme flag
        background_color = "#333333" if self.dark_theme else "white"
        text_color = "white" if self.dark_theme else "black"

        # Apply theme changes to different elements
        self.master.config(bg=background_color)  # Set background color of the root window

        self.log_text.config(foreground=text_color, background=background_color)
        self.status_bar.config(background=background_color)
        self.target_entry.config(background=background_color, foreground=text_color)

    def scan_target(self):
        target = self.target_entry.get()

        if target.lower() in ['exit', 'quit', 'bye']:
            self.exit_application()

        try:
            log_file_name = f'network_scanner_for_{target}.log'
            logging.basicConfig(filename=log_file_name, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
            logger = logging.getLogger()
            logger.addHandler(logging.StreamHandler())
            ip_addresses = self.resolve_target(target)
            if not ip_addresses:
                logger.error("Unable to resolve target. Exiting.")
                return

            for ip_addr in ip_addresses:
                logger.info(f"Resolved IP address for the target: {ip_addr}")

                self.get_ip_geolocation(ip_addr)

                resp = simpledialog.askinteger("Select Scan Type", "Select the type of scan to run:\n"
                                                            "1. SYN ACK scan\n"
                                                            "2. UDP scan\n"
                                                            "3. Comprehensive scan\n")

                try:
                    logger = logging.getLogger()
                    self.scan_ip(ip_addr, str(resp))

                    while True:
                        port_choice = simpledialog.askinteger("Enter Port",
                                                              "Enter the port number to visit the discovered directory (or type '0' to finish): ")
                        if port_choice == 0:
                            break
                        discovered_directory = simpledialog.askstring("Enter Directory",
                                                                      "Enter the discovered directory to visit: ")
                        protocol = simpledialog.askstring("Enter Protocol", "Enter the protocol (http or https): ").lower()

                        self.visit_and_retrieve_directory(ip_addr, port_choice, discovered_directory, protocol)

                    latitude, longitude = self.get_ip_geolocation(ip_addr)
                    self.create_map([(latitude, longitude)], target)

                    self.detect_proxy_chains(ip_addr)

                except ValueError as e:
                    logger.error("Error: " + str(e))

        except socket.gaierror as e:
            logging.error("Error resolving the IP address or domain name: " + str(e))

def main():
    root = tk.Tk()
    
    # Set ThemedStyle for the whole application
    style = ThemedStyle(root)
    style.set_theme("clam")  # Choose a modern theme

    app = NetProbeGUI(root)
    app.print_banner()
    app.print_welcome_banner()

    root.mainloop()

if __name__ == "__main__":
    main()
