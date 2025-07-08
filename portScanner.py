import socket
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

# --- Port Scanning Logic ---
def scan_port(target, port, output_box):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        result = s.connect_ex((target, port))
        if result == 0:
            output_box.insert(tk.END, f"Port {port} is [open]\n")
            output_box.see(tk.END)

def start_scan(target_entry, output_box, scan_button):
    target = target_entry.get()
    if not target:
        messagebox.showerror("Error", "Please enter a target IP or hostname.")
        return

    # Disable button during scan
    scan_button.config(state=tk.DISABLED)
    output_box.delete(1.0, tk.END)

    def threaded_scan():
        try:
            ip = socket.gethostbyname(target)
            output_box.insert(tk.END, f"Scan target > {ip}\n")
            start_time = datetime.now()
            for port in range(1, 1025):
                scan_port(ip, port, output_box)
            end_time = datetime.now()
            duration = end_time - start_time
            output_box.insert(tk.END, f"\nScan completed in {duration}\n")
        except Exception as e:
            messagebox.showerror("Scan Error", str(e))
        finally:
            scan_button.config(state=tk.NORMAL)

    threading.Thread(target=threaded_scan).start()

# --- GUI Setup ---
def main():
    root = tk.Tk()
    root.title("Port Scanner")
    root.geometry("500x400")

    # Target input
    frame = ttk.Frame(root, padding=10)
    frame.pack(fill=tk.X)
    ttk.Label(frame, text="Target IP / Hostname:").pack(side=tk.LEFT)
    target_entry = ttk.Entry(frame, width=30)
    target_entry.pack(side=tk.LEFT, padx=5)

    # Scan button
    scan_button = ttk.Button(frame, text="Start Scan", command=lambda: start_scan(target_entry, output_box, scan_button))
    scan_button.pack(side=tk.LEFT)

    # Output box
    output_box = tk.Text(root, wrap=tk.WORD, height=20)
    output_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
