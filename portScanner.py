import socket
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_THREADS = 100

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")
        self.root.geometry("800x520")
        self.root.resizable(False, False)
        self.root.configure(bg="#fefefe")

        style = ttk.Style()
        style.theme_use("default")

        style.configure("TButton",
                        font=("Arial", 10),
                        background="#fefefe",
                        foreground="#222222",
                        borderwidth=0,
                        padding=6)
        style.map("TButton",
                  background=[("active", "#eaeaea")],
                  foreground=[("active", "#000000")])

        style.configure("TLabel",
                        background="#fefefe",
                        foreground="#222222",
                        font=("Arial", 10))
        style.configure("TEntry",
                        font=("Arial", 10))
        style.configure("Horizontal.TProgressbar",
                        thickness=15,
                        background="#4a90e2",
                        troughcolor="#ddd")

        self.stop_scan_flag = False
        self.scanned_count = 0
        self.open_count = 0

        self.build_ui()

    def build_ui(self):
        padx = 12
        pady = 10

        frame = ttk.Frame(self.root, padding=padx)
        frame.pack(fill=tk.X)

        ttk.Label(frame, text="Target(s):", width=8).grid(row=0, column=0, sticky=tk.W, pady=pady)
        self.target_entry = ttk.Entry(frame, width=40)
        self.target_entry.grid(row=0, column=1, sticky=tk.W, padx=(0, padx), pady=pady)

        ttk.Label(frame, text="Ports:", width=8).grid(row=0, column=2, sticky=tk.W, pady=pady)
        self.start_port_entry = ttk.Entry(frame, width=6)
        self.start_port_entry.insert(0, "1")
        self.start_port_entry.grid(row=0, column=3, sticky=tk.W, padx=(0, 5), pady=pady)

        ttk.Label(frame, text="to", width=3, anchor=tk.CENTER).grid(row=0, column=4, pady=pady)
        self.end_port_entry = ttk.Entry(frame, width=6)
        self.end_port_entry.insert(0, "1024")
        self.end_port_entry.grid(row=0, column=5, sticky=tk.W, padx=(0, padx), pady=pady)

        self.scan_button = ttk.Button(frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=6, sticky=tk.E, padx=(0, padx), pady=pady)

        self.stop_button = ttk.Button(frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=7, sticky=tk.E, pady=pady)

        count_frame = ttk.Frame(self.root, padding=(padx, 0))
        count_frame.pack(fill=tk.X)

        self.scanned_label = ttk.Label(count_frame, text="Ports scanned: 0")
        self.scanned_label.pack(side=tk.LEFT, padx=(0, 25), pady=(0, pady))

        self.open_label = ttk.Label(count_frame, text="Ports open: 0")
        self.open_label.pack(side=tk.LEFT, pady=(0, pady))

        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, length=610, mode='determinate', style="Horizontal.TProgressbar")
        self.progress.pack(padx=padx, pady=15)

        self.output_box = tk.Text(self.root, wrap=tk.WORD, height=20, font=("Consolas", 10), bg="#ffffff", fg="#111111", relief=tk.FLAT, bd=0)
        self.output_box.pack(fill=tk.BOTH, expand=True, padx=padx, pady=(0, padx))

        scrollbar = ttk.Scrollbar(self.output_box, command=self.output_box.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_box.config(yscrollcommand=scrollbar.set)

    def scan_port(self, ip, port):
        if self.stop_scan_flag:
            return None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "Unknown"
                    return (port, True, service)
        except:
            return (port, False, None)
        return (port, False, None)

    def start_scan(self):
        targets_raw = self.target_entry.get()
        targets = [t.strip() for t in targets_raw.replace(',', ' ').split() if t.strip()]
        if not targets:
            messagebox.showerror("Error", "Please enter at least one target IP or hostname.")
            return

        try:
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError
        except:
            messagebox.showerror("Error", "Please enter a valid port range (1-65535).")
            return

        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.output_box.delete(1.0, tk.END)
        total_ports = len(targets) * (end_port - start_port + 1)
        self.progress['maximum'] = total_ports
        self.progress['value'] = 0
        self.stop_scan_flag = False
        self.scanned_count = 0
        self.open_count = 0
        self.update_counts()

        def threaded_scan():
            try:
                for target in targets:
                    if self.stop_scan_flag:
                        break
                    try:
                        ip = socket.gethostbyname(target)
                    except socket.gaierror:
                        self.append_output(f"\nCould not resolve target: {target}\n")
                        continue

                    try:
                        reverse_name = socket.gethostbyaddr(ip)[0]
                        self.append_output(f"\nScanning {target} ({ip} - {reverse_name})\n")
                    except socket.herror:
                        self.append_output(f"\nScanning {target} ({ip}) - no reverse DNS\n")

                    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                        futures = {executor.submit(self.scan_port, ip, port): port for port in range(start_port, end_port + 1)}
                        for future in as_completed(futures):
                            if self.stop_scan_flag:
                                break
                            result = future.result()
                            if result is None:
                                continue
                            port, is_open, service = result
                            self.scanned_count += 1
                            if is_open:
                                self.open_count += 1
                                service_str = service if service else "Unknown"
                                self.append_output(f"Port {port} is [OPEN] ({service_str})\n")

                            self.update_counts()
                            self.progress.step(1)

                self.append_output("\nScan completed.\n")
            except Exception as e:
                messagebox.showerror("Scan Error", str(e))
            finally:
                self.scan_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)

        threading.Thread(target=threaded_scan, daemon=True).start()

    def update_counts(self):
        self.root.after(0, lambda: self.scanned_label.config(text=f"Ports scanned: {self.scanned_count}"))
        self.root.after(0, lambda: self.open_label.config(text=f"Ports open: {self.open_count}"))

    def stop_scan(self):
        self.stop_scan_flag = True
        self.append_output("\n[Scan stopped by user]\n")
        self.stop_button.config(state=tk.DISABLED)
        self.scan_button.config(state=tk.NORMAL)

    def append_output(self, text):
        self.output_box.insert(tk.END, text)
        self.output_box.see(tk.END)


def main():
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
