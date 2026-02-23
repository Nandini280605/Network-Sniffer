#!/usr/bin/env python3
"""
Packet Sniffer GUI with Real-time Bandwidth Chart
Requirements:
    pip install scapy matplotlib
Run with admin/root privileges.
"""

import sys
import time
import socket
import struct
import threading
import platform
import csv
from collections import deque

# Try importing Scapy
try:
    from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, Raw
    from scapy.utils import wrpcap, rdpcap
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer + Bandwidth Chart")
        self.root.geometry("1150x700")
        self.root.configure(bg="#f0f0f0")

        # Runtime flags
        self.running = False
        self.conn = None
        self.capture_thread = None

        # Packet storage
        self.packets = []
        self.packet_count = 0

        # Bandwidth tracking
        self.start_time = None
        self.total_bytes = 0
        self.rate_window = deque(maxlen=60)
        self.time_window = deque(maxlen=60)

        # --- Control frame ---
        control_frame = tk.Frame(root, bg="#f0f0f0")
        control_frame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)

        self.start_btn = tk.Button(control_frame, text="Start Capture", command=self.start_capture,
                                   bg="#4CAF50", fg="white", font=("Arial", 11), width=12)
        self.start_btn.pack(side=tk.LEFT, padx=4)

        self.stop_btn = tk.Button(control_frame, text="Stop Capture", command=self.stop_capture,
                                  bg="#f44336", fg="white", font=("Arial", 11), width=12, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)

        self.clear_btn = tk.Button(control_frame, text="Clear Packets", command=self.clear_packets,
                                   bg="#2196F3", fg="white", font=("Arial", 11), width=12)
        self.clear_btn.pack(side=tk.LEFT, padx=4)

        self.save_btn = tk.Button(control_frame, text="Save PCAP", command=self.save_pcap,
                                  bg="#FFC107", fg="black", font=("Arial", 11), width=12)
        self.save_btn.pack(side=tk.LEFT, padx=4)

        self.load_btn = tk.Button(control_frame, text="Load PCAP", command=self.load_pcap,
                                  bg="#9C27B0", fg="white", font=("Arial", 11), width=12)
        self.load_btn.pack(side=tk.LEFT, padx=4)

        self.csv_btn = tk.Button(control_frame, text="Export CSV", command=self.export_csv,
                                 bg="#FF5722", fg="white", font=("Arial", 11), width=12)
        self.csv_btn.pack(side=tk.LEFT, padx=4)

        # --- Filter & Search ---
        tk.Label(control_frame, text="Protocol Filter:", bg="#f0f0f0").pack(side=tk.LEFT, padx=6)
        self.filter_var = tk.StringVar(value="tcp,udp,icmp,arp,ipv4")
        self.filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var, width=25)
        self.filter_entry.pack(side=tk.LEFT, padx=6)

        tk.Label(control_frame, text="Search:", bg="#f0f0f0").pack(side=tk.LEFT, padx=6)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(control_frame, textvariable=self.search_var, width=25)
        self.search_entry.pack(side=tk.LEFT, padx=6)
        self.search_btn = tk.Button(control_frame, text="Find", command=self.search_packets, width=8)
        self.search_btn.pack(side=tk.LEFT, padx=6)

        # --- Middle: Treeview and Chart ---
        middle_frame = tk.Frame(root, bg="#f0f0f0")
        middle_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # Treeview
        tree_frame = tk.Frame(middle_frame, bg="#f0f0f0")
        tree_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=24)
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120 if col != "Info" else 300, anchor=tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.tree.tag_configure("suspicious", background="#ffd1d1")
        self.tree.tag_configure("icmp", background="#fff0d1")
        self.tree.tag_configure("http", background="#d1ffd8")
        self.tree.tag_configure("default", background="#ffffff")

        self.tree.bind("<Double-1>", self.on_tree_double_click)
        self.tree.bind("<Button-3>", self.on_right_click)

        # Bandwidth Chart
        chart_frame = tk.Frame(middle_frame, bg="#f0f0f0")
        chart_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=6, pady=6)
        chart_frame.config(width=430)

        self.fig = Figure(figsize=(5, 4), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_title("Bandwidth (KB/s) — last samples")
        self.ax.set_xlabel("Time")
        self.ax.set_ylabel("KB/s")
        self.line, = self.ax.plot([], [], linewidth=1)
        self.ax.set_ylim(0, 10)
        self.ax.grid(True)

        self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Status bar
        self.status = tk.Label(root, text="Idle", anchor="w", bg="#e9e9e9")
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

        # Schedule chart updates
        self.root.after(1000, self.update_chart)

    # ------------------------- Capture control -------------------------
    def start_capture(self):
        if self.running:
            return
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.clear_btn.config(state=tk.DISABLED)
        self.packet_count = 0
        self.packets.clear()
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.total_bytes = 0
        self.start_time = time.time()
        self.update_status("Starting capture...")
        self.capture_thread = threading.Thread(target=self._capture_thread, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        if not self.running:
            return
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.clear_btn.config(state=tk.NORMAL)
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None
        self.update_status("Capture stopped.")

    def clear_packets(self):
        self.packets.clear()
        self.packet_count = 0
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.total_bytes = 0
        self.update_status("Cleared captured packets.")

    # ------------------------- Save & Load -------------------------
    def save_pcap(self):
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to save.")
            return
        file = filedialog.asksaveasfilename(defaultextension=".pcap",
                                            filetypes=[("PCAP files", "*.pcap")])
        if not file:
            return
        try:
            if SCAPY_AVAILABLE:
                wrpcap(file, [pkt[-1] for pkt in self.packets])
                self.update_status(f"Saved {len(self.packets)} packets to {file}")
            else:
                messagebox.showerror("Error", "Scapy not available, cannot save PCAP.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PCAP: {e}")

    def load_pcap(self):
        file = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if not file:
            return
        try:
            if not SCAPY_AVAILABLE:
                messagebox.showerror("Error", "Scapy not available, cannot load PCAP.")
                return
            packets = rdpcap(file)
            self.clear_packets()
            for pkt in packets:
                self._scapy_packet_handler(pkt)
            self.update_status(f"Loaded {len(packets)} packets from {file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load PCAP: {e}")

    def export_csv(self):
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to export.")
            return
        file = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV files", "*.csv")])
        if not file:
            return
        try:
            with open(file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["No.", "Time", "Source", "Destination",
                                 "Protocol", "Length", "Info"])
                for idx, (ts, src, dst, proto, length, info, tag, raw) in enumerate(self.packets, start=1):
                    writer.writerow([idx, ts, src, dst, proto, length, info])
            self.update_status(f"Exported {len(self.packets)} packets to {file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV: {e}")

    # ------------------------- Capture Thread -------------------------
    def _capture_thread(self):
        system = platform.system().lower()
        if SCAPY_AVAILABLE and system in ("windows", "darwin"):
            sniff(prn=self._scapy_packet_handler, store=False, stop_filter=lambda x: not self.running)
        elif system == "linux":
            self._linux_raw_capture()
        else:
            messagebox.showerror("Error", f"Unsupported platform: {system}")

    def _scapy_packet_handler(self, pkt):
        if not self.running:
            return
        self.packet_count += 1
        ts = f"{time.time()-self.start_time:.2f}"
        proto = self._get_protocol_name_from_scapy(pkt)
        src, dst = self._get_src_dst_from_scapy(pkt)
        length = len(pkt)
        info = self._scapy_info_short(pkt)
        tag = self._determine_tag(pkt)
        self.packets.append((ts, src, dst, proto, length, info, tag, pkt))
        self._insert_tree_row(self.packet_count, ts, src, dst, proto, length, info, tag)
        self.total_bytes += length

    def _linux_raw_capture(self):
        try:
            self.conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except PermissionError:
            messagebox.showerror("Error", "Root privileges required on Linux.")
            self.stop_capture()
            return
        while self.running:
            raw_data, addr = self.conn.recvfrom(65535)
            self.packet_count += 1
            ts = f"{time.time()-self.start_time:.2f}"
            eth_proto = struct.unpack("!6s6sH", raw_data[:14])[2]
            proto = "IPv4" if eth_proto == 0x0800 else f"EthType {eth_proto}"
            src = dst = "-"
            length = len(raw_data)
            info = f"Raw packet, Eth proto {eth_proto}"
            tag = "default"
            self.packets.append((ts, src, dst, proto, length, info, tag, raw_data))
            self._insert_tree_row(self.packet_count, ts, src, dst, proto, length, info, tag)
            self.total_bytes += length

    # ------------------------- Helpers -------------------------
    def _insert_tree_row(self, no, ts, src, dst, proto, length, info, tag):
        self.tree.insert("", tk.END, values=(no, ts, src, dst, proto, length, info), tags=(tag,))

    def _get_protocol_name_from_scapy(self, pkt):
        if pkt.haslayer(TCP): return "TCP"
        if pkt.haslayer(UDP): return "UDP"
        if pkt.haslayer(ICMP): return "ICMP"
        if pkt.haslayer(ARP): return "ARP"
        if pkt.haslayer(IP): return "IP"
        return "Other"

    def _get_src_dst_from_scapy(self, pkt):
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(ARP):
            return pkt[ARP].psrc, pkt[ARP].pdst
        else:
            return "-", "-"

    def _scapy_info_short(self, pkt):
        if pkt.haslayer(TCP):
            return f"TCP sport={pkt[TCP].sport}, dport={pkt[TCP].dport}"
        if pkt.haslayer(UDP):
            return f"UDP sport={pkt[UDP].sport}, dport={pkt[UDP].dport}"
        if pkt.haslayer(ICMP):
            return f"ICMP type={pkt[ICMP].type}"
        if pkt.haslayer(ARP):
            return f"ARP {pkt[ARP].psrc}->{pkt[ARP].pdst}"
        if pkt.haslayer(IP):
            return f"IP {pkt[IP].src}->{pkt[IP].dst}"
        return pkt.summary()

    def _determine_tag(self, pkt):
        if pkt.haslayer(ICMP):
            return "icmp"
        if pkt.haslayer(TCP) and (pkt[TCP].sport == 80 or pkt[TCP].dport == 80):
            return "http"
        return "default"

    # ------------------------- Chart Update -------------------------
    def update_chart(self):
        if self.start_time:
            elapsed = time.time() - self.start_time
            rate = (self.total_bytes / 1024) / elapsed if elapsed > 0 else 0
            self.rate_window.append(rate)
            self.time_window.append(len(self.time_window))
            self.line.set_data(self.time_window, self.rate_window)
            self.ax.set_xlim(0, max(60, len(self.time_window)))
            self.ax.set_ylim(0, max(10, max(self.rate_window) * 1.2 if self.rate_window else 10))
            self.canvas.draw()
        self.root.after(1000, self.update_chart)

    # ------------------------- Misc -------------------------
    def update_status(self, text):
        self.status.config(text=text)

    def search_packets(self):
        term = self.search_var.get().lower()
        if not term:
            return
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            if any(term in str(v).lower() for v in vals):
                self.tree.selection_set(iid)
                self.tree.see(iid)
                break

    def on_tree_double_click(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        iid = selected[0]
        idx = int(self.tree.item(iid, "values")[0]) - 1
        if idx < 0 or idx >= len(self.packets):
            return
        pkt = self.packets[idx][-1]
        detail = str(pkt.show(dump=True)) if SCAPY_AVAILABLE else str(pkt)
        win = tk.Toplevel(self.root)
        win.title("Packet Details")
        txt = tk.Text(win, wrap="word")
        txt.insert("1.0", detail)
        txt.pack(fill=tk.BOTH, expand=True)

    def on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Save Selected to PCAP", command=self.save_selected)
        menu.post(event.x_root, event.y_root)

    def save_selected(self):
        selected = self.tree.selection()
        if not selected:
            return
        idx = int(self.tree.item(selected[0], "values")[0]) - 1
        if idx < 0 or idx >= len(self.packets):
            return
        pkt = self.packets[idx][-1]
        file = filedialog.asksaveasfilename(defaultextension=".pcap",
                                            filetypes=[("PCAP files", "*.pcap")])
        if not file:
            return
        try:
            if SCAPY_AVAILABLE:
                wrpcap(file, [pkt])
                self.update_status(f"Saved packet {idx+1} to {file}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save packet: {e}")


# ------------------------- Run -------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()