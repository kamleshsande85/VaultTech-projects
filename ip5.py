import tkinter as tk
from tkinter import messagebox
import threading
import socket
from scapy.all import ARP, Ether, srp


# Create a lock object to prevent simultaneous writes
lock = threading.Lock()


# ========================================ip scanner============================================================
def scan_ip(ip):
    try:
        hostname = socket.gethostbyaddr(ip)
        listbox.insert(tk.END, f"{ip}: {hostname[0]}")
        content = f"IP: {ip} - hostname : {hostname[0]}\n"

        # Write to file in a thread-safe manner
        with lock:  # Ensures only one thread can write at a time
            with open('ip.txt', 'a') as file:
                file.write(content)

    except socket.herror:
        listbox2.insert(tk.END, f"IP: {ip} - hostname : unknown")


def ipscanner2(address, start_ip, end_ip):
    listbox.insert(tk.END, "Range ip scanner")
    for last_octet in range(start_ip, end_ip + 1):  # Include end_ip
        ip = f"{address}.{last_octet}"
        thread = threading.Thread(target=scan_ip, args=(ip,))
        thread.start()


def ipscanner():
    entry_text = ipAddres.get()
    entry_text3 = int(startRange.get())
    entry_text2 = int(endrange.get())
    ipscanner2(entry_text, entry_text3, entry_text2)


def clear():
    listbox.delete(0, tk.END)
    listbox2.delete(0, tk.END)


# ========================================Mac Address============================================================
def macAdddess(ip_address):
    listbox.insert(tk.END, "Mac address detection")
    # Create an ARP request
    arp = ARP(pdst=ip_address)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    packet = ether / arp

    # Send the packet and capture the response
    result = srp(packet, timeout=2, verbose=False)[0]

    # Check if any response was received
    if result:
        for sent, received in result:
            content = f"IP: {received.psrc}, MAC: {received.hwsrc}"
            listbox.insert(tk.END, content)
    else:
        messagebox.showinfo(
            "No Response", "No response received from the IP address.")


def HostDetection():
    ip = ipAddres.get()  # Get the IP address from the Entry widget
    macAdddess(ip)  # Call the function to get MAC address

# ========================================single port============================================================


def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)  # Set a timeout for the connection attempt
    result = sock.connect_ex((ip, port))  # Attempt to connect to the port
    if result == 0:  # Port is open
        listbox.insert(tk.END, f"Port {port} is open")
    else:
        listbox2.insert(tk.END, f"Port {port} is off")

    sock.close()


def portScanning():
    ip = ipAddres.get()
    start_port = int(startRange.get())
    end_port = int(endrange.get())

    # Clear previous results
    listbox.delete(0, tk.END)

    # Scan ports
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(ip, port))
        thread.start()

# ======================================tcp==============================================================

# Function to scan a single port


def scan_tcp_port(ip, port):
    # listbox.insert(tk.END, "Port scan")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            with lock:
                listbox.insert(tk.END, f"Port {port} is open (TCP)")
        sock.close()
    except socket.error:
        pass

# Function to initiate the TCP scan over a range of ports


def tcp_scan():
    ip = ipAddres.get()
    start_port = int(startRange.get())
    end_port = int(endrange.get())

    # Clear previous results
    listbox.delete(0, tk.END)
    listbox.insert(tk.END, "TCP scan")

    # Scan each port in the specified range
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_tcp_port, args=(ip, port))
        thread.start()

# ====================================UDP port================================================================
# Function to scan a single UDP port


def scan_udp_port(ip, port):
    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)

        # Send a dummy message (empty) to the target port
        sock.sendto(b'', (ip, port))

        # Try to receive a response
        try:
            data, addr = sock.recvfrom(1024)
            with lock:
                listbox.insert(tk.END, f"Port {port} is open (UDP)")
        except socket.timeout:
            # If no response, port might be open or filtered
            with lock:
                listbox.insert(tk.END, f"Port {
                               port} is open or filtered (UDP)")
        except Exception as e:
            # Handle cases where the port is unreachable (ICMP message)
            with lock:
                listbox.insert(tk.END, f"Port {port} is closed (UDP)")
    except Exception as e:
        pass
    finally:
        sock.close()

# Function to initiate the UDP scan over a range of ports


def udp_scan():
    ip = ipAddres.get()
    start_port = int(startRange.get())
    end_port = int(endrange.get())

    # Clear previous results
    listbox.delete(0, tk.END)
    # listbox.delete(tk.END, "UDP scan")

    # Scan each port in the specified range
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_udp_port, args=(ip, port))
        thread.start()

# ====================================================================================================


# Create the main application window
root = tk.Tk()
root.title("IP Scanner")
root.geometry("800x700")
root.minsize(800, 700)
root.maxsize(800, 700)
root.config(bg="#2C302E")

# Create a menu bar
menu_bar = tk.Menu(root)
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Range IP Scanner", command=ipscanner)
file_menu.add_command(label="Port Scanning", command=portScanning)
file_menu.add_command(label="Host Detection", command=HostDetection)
file_menu.add_command(label="TCP", command=tcp_scan)
file_menu.add_command(label="UDP", command=udp_scan)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)
menu_bar.add_cascade(label="File", menu=file_menu)
root.config(menu=menu_bar)

# Create the input frame
inputFrame = tk.Frame(root, bg="#2C302E")
inputFrame.grid(row=0, padx=20, pady=10, sticky='ew')

# Labels and entries for IP address input
ipLabel = tk.Label(inputFrame, text="IP Address", bg="#2C302E", fg="white")
ipLabel.grid(row=0, column=0, padx=5, pady=5, sticky='e')
ipAddres = tk.Entry(inputFrame)
ipAddres.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
ipAddres.insert(0, "192.168.1")

startLabel = tk.Label(inputFrame, text="Start Range", bg="#2C302E", fg="white")
startLabel.grid(row=1, column=0, padx=5, pady=5, sticky='e')
startRange = tk.Entry(inputFrame)
startRange.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
startRange.insert(0, "1")

endLabel = tk.Label(inputFrame, text="End Range", bg="#2C302E", fg="white")
endLabel.grid(row=1, column=2, padx=5, pady=5, sticky='e')
endrange = tk.Entry(inputFrame)
endrange.grid(row=1, column=3, padx=5, pady=5, sticky='ew')
endrange.insert(0, "254")

# # Submit button
# subBtn = tk.Button(inputFrame, text="Range Ip scanner", command=ipscanner)
# subBtn.grid(row=2, column=0, pady=10)

buttonClear = tk.Button(inputFrame, text="Clear", width=5,
                        command=clear, bg='black', fg="white")
buttonClear.grid(row=2, column=1)

# Create Listboxes
listbox = tk.Listbox(root, width=30, height=30)
listbox.grid(row=1, column=0, padx=(20, 10), pady=10, sticky='nsew')

listbox2 = tk.Listbox(root, width=30, height=30)
listbox2.grid(row=1, column=1, padx=(10, 20), pady=10, sticky='nsew')

# Configure grid to expand
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_rowconfigure(1, weight=1)

root.mainloop()
