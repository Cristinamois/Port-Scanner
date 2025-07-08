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
        self.root.geometry("600x480")

        self.stop_scan_flag = False
        self.executor = None

        self.build_ui()

    def build_ui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.X)

        ttk.Label(frame, text="Target:").pack(side=tk.LEFT)
        self.target_entry = ttk.Entry(frame, width=25)
        self.target_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(frame, text="Ports:").pack(side=tk.LEFT)
        self.start_port_entry = ttk.Entry(frame, width=5)
        self.start_port_entry.insert(0, "1")
        self.start_port_entry.pack(side=tk.LEFT)

        ttk.Label(frame, text="to").pack(side=tk.LEFT)
        self.end_port_entry = ttk.Entry(frame, width=5)
        self.end_port_entry.insert(0, "1024")
        self.end_port_entry.pack(side=tk.LEFT)

        self.scan_button = ttk.Button(frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = ttk.Button(frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, length=580, mode='determinate')
        self.progress.pack(padx=10, pady=10)

        self.output_box = tk.Text(self.root, wrap=tk.WORD, height=20)
        self.output_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

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
                    except:
                        service = "Unknown"
                    return f"Port {port} is [OPEN] ({service})"
        except:
            return None
        return None

    def start_scan(self):
        target = self.target_entry.get()
        try:
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError
        except:
            messagebox.showerror("Error", "Please enter a valid port range (1-65535).")
            return

        if not target:
            messagebox.showerror("Error", "Please enter a target IP or hostname.")
            return

        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.output_box.delete(1.0, tk.END)
        self.progress['maximum'] = end_port - start_port + 1
        self.progress['value'] = 0
        self.stop_scan_flag = False

        def threaded_scan():
            try:
                ip = socket.gethostbyname(target)
                self.append_output(f"Scan target > {ip}\n")

                start_time = datetime.now()

                with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                    futures = {executor.submit(self.scan_port, ip, port): port for port in range(start_port, end_port + 1)}
                    for future in as_completed(futures):
                        if self.stop_scan_flag:
                            break
                        result = future.result()
                        if result:
                            self.append_output(result + '\n')
                        self.progress.step(1)
                end_time = datetime.now()
                self.append_output(f"\nScan completed in {end_time - start_time}\n")
            except Exception as e:
                messagebox.showerror("Scan Error", str(e))
            finally:
                self.scan_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)

        threading.Thread(target=threaded_scan, daemon=True).start()

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
