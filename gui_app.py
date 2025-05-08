import customtkinter as ctk
import threading
import json
import datetime
import os
import networkx as nx
import matplotlib.pyplot as plt
from tkinter import messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from HSNAT.audit_tool import full_audit, scan_network, generate_html_report

all_scan_results = []
offline_mode = False
scan_thread = None
stop_scan_flag = False

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class NetworkAuditApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Home Network Security Audit Tool")
        self.geometry("1200x800")

        self.previous_scan = None
        self.scan_mode = ctk.StringVar(value="default")
        self.current_tabs = {}  # To keep track of open tabs
        self.current_active_tab = None

        self.create_widgets()

    def get_scan_files(self):
        if not os.path.exists("scan_data"):
            os.makedirs("scan_data")
        return [f for f in os.listdir("scan_data") if f.endswith('.json')]

    def load_previous_scan(self):
        scan_files = self.get_scan_files()
        if not scan_files:
            self.status_label.configure(text="❌ No previous scans found")
            return
            
        # Create a new top-level window for scan selection
        scan_window = ctk.CTkToplevel(self)
        scan_window.title("Select Previous Scan")
        scan_window.geometry("400x200")
        
        # Add label
        label = ctk.CTkLabel(scan_window, text="Select a scan to load:")
        label.pack(pady=10)
        
        # Create dropdown menu
        self.scan_var = ctk.StringVar(value=scan_files[0])
        scan_dropdown = ctk.CTkOptionMenu(
            scan_window, 
            variable=self.scan_var,
            values=scan_files
        )
        scan_dropdown.pack(pady=10)
        
        # Add load button
        load_btn = ctk.CTkButton(
            scan_window,
            text="Load Selected Scan",
            command=lambda: self.load_selected_scan(scan_window)
        )
        load_btn.pack(pady=10)

    def load_selected_scan(self, window):
        selected_file = self.scan_var.get()
        try:
            with open(os.path.join("scan_data", selected_file), "r") as f:
                self.previous_scan = json.load(f)
                self.status_label.configure(text=f"📂 Loaded: {selected_file}")
                
                # Create or update Previous Scans tab
                self.add_tab("Previous Scans")
                self.clear_tab_content("Previous Scans")
                frame = self.current_tabs["Previous Scans"]
                
                # Add a label showing this is the selected scan
                scan_label = ctk.CTkLabel(
                    frame, 
                    text=f"Scan Results: {selected_file}",
                    font=("Arial", 16, "bold")
                )
                scan_label.pack(pady=10, padx=10, anchor="w")
                
                # Display the loaded scan data
                self.display_result(self.previous_scan, "Previous Scans")
                
        except Exception as e:
            self.status_label.configure(text=f"❌ Error loading scan: {e}")
        finally:
            window.destroy()

    def create_widgets(self):
        self.create_sidebar()
        self.create_main_area()

    def set_scan_mode(self, mode):
        self.scan_mode.set(mode)
        self.status_label.configure(text=f"Selected Scan Mode: {mode.capitalize()}")

    def create_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=200)
        sidebar.pack(side="left", fill="y")

        title_label = ctk.CTkLabel(sidebar, text="🛡️ HNSAT", font=("Arial", 24, "bold"))
        title_label.pack(pady=20)

        self.ip_entry = ctk.CTkEntry(sidebar, placeholder_text="Enter Target IP or Subnet")
        self.ip_entry.pack(pady=10, padx=10)

        self.offline_switch = ctk.CTkSwitch(sidebar, text="Mode: ", command=self.toggle_mode)
        self.offline_switch.pack(pady=5, padx=15)

        self.mode_label = ctk.CTkLabel(sidebar, text="Online", font=("Arial", 12))
        self.mode_label.pack(pady=0, padx=10)

        self.quick_scan_button = ctk.CTkButton(sidebar, text="⚡ Quick Scan", command=lambda: self.set_scan_mode("quick"))
        self.quick_scan_button.pack(pady=5, padx=10)

        self.aggressive_scan_button = ctk.CTkButton(sidebar, text="🔥 Aggressive Scan", command=lambda: self.set_scan_mode("aggressive"))
        self.aggressive_scan_button.pack(pady=10, padx=10)

        self.scan_button = ctk.CTkButton(sidebar, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=5, padx=10)

        self.stop_button = ctk.CTkButton(
            sidebar,
            text="Stop Scan",
            command=self.stop_scan,
            fg_color="#8a211e",
            hover_color="#c9302c"
        )
        self.stop_button.pack(pady=5, padx=10)
        self.stop_button.configure(state="disabled")

        self.progress = ctk.CTkProgressBar(sidebar)
        self.progress.pack(pady=10, padx=10)
        self.progress.set(0)

        self.status_label = ctk.CTkLabel(
            sidebar,
            text="Idle",
            font=("Arial", 12),
            width=180,
            wraplength=180,
            anchor="w",
            justify="left"
        )
        self.status_label.pack(pady=10, padx=10)

        # Moved Network Map button here (below status label)
        self.map_button = ctk.CTkButton(sidebar, text="🗺️ Show Network Map", command=lambda: self.create_new_tab("Network Map", self.show_network_map))
        self.map_button.pack(pady=5, padx=10)

        self.save_button = ctk.CTkButton(sidebar, text="Save Report", command=self.save_report)
        self.save_button.pack(pady=10, padx=10)
        self.save_button.configure(state="disabled")

        self.load_button = ctk.CTkButton(sidebar, text="Load Previous Scan", command=self.load_previous_scan)
        self.load_button.pack(pady=5, padx=10)

    def create_main_area(self):
        # Create tabview for main area
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Add default tab
        self.add_tab("Scan Results")
        self.current_active_tab = "Scan Results"

    def add_tab(self, tab_name):
        if tab_name not in self.current_tabs:
            self.tabview.add(tab_name)
            scroll_frame = ctk.CTkScrollableFrame(self.tabview.tab(tab_name))
            scroll_frame.pack(expand=True, fill="both")
            self.current_tabs[tab_name] = scroll_frame
        self.tabview.set(tab_name)

    def create_new_tab(self, tab_name, content_func):
        self.add_tab(tab_name)
        self.clear_tab_content(tab_name)
        content_func(tab_name)

    def clear_tab_content(self, tab_name):
        if tab_name in self.current_tabs:
            for widget in self.current_tabs[tab_name].winfo_children():
                widget.destroy()

    def toggle_mode(self):
        global offline_mode
        offline_mode = self.offline_switch.get()
        self.update_mode_label()

    def update_mode_label(self):
        mode_text = "Offline" if offline_mode else "Online"
        self.mode_label.configure(text=mode_text)

    def start_scan(self):
        global stop_scan_flag, scan_thread
        stop_scan_flag = False

        ip = self.ip_entry.get().strip()
        if not ip:
            self.status_label.configure(text="❗ Please enter an IP or Subnet")
            return

        self.scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.save_button.configure(state="disabled")
        self.status_label.configure(text="🔎 Scanning...")
        self.progress.set(0)
        self.clear_tab_content("Scan Results")
        global all_scan_results
        all_scan_results = []
        global offline_mode
        offline_mode = self.offline_switch.get()

        scan_thread = threading.Thread(target=self.run_audit, args=(ip, self.scan_mode.get()), daemon=True)
        scan_thread.start()

    def stop_scan(self):
        global stop_scan_flag
        stop_scan_flag = True
        self.status_label.configure(text="🛑 Stopping scan...")
        self.stop_button.configure(state="disabled")

    def run_audit(self, target, scan_mode):
        global stop_scan_flag, scan_thread
        try:
            if "/" in target:
                live_ips = scan_network(target)
                total = len(live_ips)
                if total == 0:
                    self.status_label.configure(text="❌ No live devices found.")
                    self.scan_button.configure(state="normal")
                    self.stop_button.configure(state="disabled")
                    return
            else:
                live_ips = [target]
                total = 1

            for idx, ip in enumerate(live_ips):
                if stop_scan_flag:
                    self.status_label.configure(text="⏹ Scan stopped by user")
                    break

                result = full_audit(ip, offline=offline_mode, previous_data=self.previous_scan, scan_mode=scan_mode)
                all_scan_results.append(result)
                self.display_result(result)

                percent = (idx + 1) / total
                self.progress.set(percent)
                self.status_label.configure(text=f"Scanning {idx+1}/{total} devices...")

            if not stop_scan_flag:
                self.status_label.configure(text="✅ Scan Complete!")
                self.save_button.configure(state="normal")
        except Exception as e:
            if not stop_scan_flag:
                self.status_label.configure(text=f"❌ Error: {e}")
        finally:
            self.scan_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            stop_scan_flag = False

    def display_result(self, result, tab_name="Scan Results"):
        if tab_name not in self.current_tabs:
            self.add_tab(tab_name)
        
        frame = self.current_tabs[tab_name]
        
        card = ctk.CTkFrame(frame, border_width=2, corner_radius=10)
        card.pack(padx=10, pady=10, fill="x", anchor="n")

        title = ctk.CTkLabel(card, text=f"💻 IP: {result['ip']}", font=("Arial", 18, "bold"))
        title.pack(pady=5)

        mac_vendor = ctk.CTkLabel(card, text=f"MAC: {result['mac']} ({result['vendor']})")
        mac_vendor.pack()

        geo = result["geo"]
        location = ctk.CTkLabel(card, text=f"🌍 {geo['city']}, {geo['region']}, {geo['country']} ({geo['org']})")
        location.pack()

        services_label = ctk.CTkLabel(card, text="📡 Open Ports & Services:", font=("Arial", 14, "underline"))
        services_label.pack(pady=(10, 0))

        for svc in result["services"]:
            svc_text = f"{svc['port']} - {svc['service']} ({svc['version']})"
            svc_label = ctk.CTkLabel(card, text=svc_text)
            svc_label.pack(anchor="w", padx=20)

            if svc.get("cves"):
                for cve in svc["cves"]:
                    cve_text = f"⚠️ {cve['id']}: {cve['description']} [{cve['severity']}]"
                    cve_label = ctk.CTkLabel(card, text=cve_text, wraplength=900, font=("Arial", 10))
                    cve_label.pack(anchor="w", padx=40, pady=(0, 5))
            else:
                cve_label = ctk.CTkLabel(card, text="No CVEs found.", font=("Arial", 10))
                cve_label.pack(anchor="w", padx=40)

        if result.get("enumeration"):
            enum_label = ctk.CTkLabel(card, text="🔍 Enumerated Services:", font=("Arial", 14, "underline"))
            enum_label.pack(pady=(10, 0))
            for item in result["enumeration"]:
                lbl = ctk.CTkLabel(card, text=f"- {item}")
                lbl.pack(anchor="w", padx=20)

        weak_label = ctk.CTkLabel(card, text="🔑 Weak Credentials:", font=("Arial", 14, "underline"))
        weak_label.pack(pady=(10, 0))

        if result["weak_creds"]:
            for cred in result["weak_creds"]:
                cred_label = ctk.CTkLabel(card, text=cred)
                cred_label.pack(anchor="w", padx=20)
        else:
            no_weak = ctk.CTkLabel(card, text="No weak credentials found.")
            no_weak.pack(anchor="w", padx=20)

        if result.get("delta"):
            delta_label = ctk.CTkLabel(card, text="🆕 Changes Detected:", font=("Arial", 14, "underline"))
            delta_label.pack(pady=(10, 0))
            for kind, items in result["delta"].items():
                if items:
                    lbl = ctk.CTkLabel(card, text=f"{kind}: {len(items)} item(s)")
                    lbl.pack(anchor="w", padx=20)

    def show_network_map(self, tab_name=None):
        if not all_scan_results:
            self.status_label.configure(text="❌ No scan results to map.")
            return

        if not tab_name:
            tab_name = "Network Map"
            
        self.clear_tab_content(tab_name)
        frame = self.current_tabs[tab_name]
        
        # Create figure with dark background
        plt.style.use('dark_background')  # This sets a dark theme for all elements
        fig = plt.figure(figsize=(8, 6), facecolor='#2b2b2b')
        ax = fig.add_subplot(111, facecolor='#2b2b2b')
        
        # Create the graph
        G = nx.Graph()

        for device in all_scan_results:
            ip = device['ip']
            G.add_node(ip, label=ip)

        # Simple: connect all nodes to a central router node
        G.add_node("Router")
        for device in all_scan_results:
            G.add_edge("Router", device['ip'])

        pos = nx.spring_layout(G)
        
        # Draw with appropriate colors for dark background
        nx.draw(
            G, 
            pos, 
            with_labels=True, 
            node_color="blue", 
            node_size=1000, 
            font_size=10, 
            ax=ax,
            font_color="white",
            edge_color="lightgray"
        )

        # Force dark background by setting figure and axes properties
        fig.set_facecolor('#2b2b2b')
        ax.set_facecolor('#2b2b2b')
        
        # Adjust spines (borders) if needed
        for spine in ax.spines.values():
            spine.set_edgecolor('lightgray')

        # Create canvas and embed in Tkinter
        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Explicitly set the background color of the canvas
        canvas.get_tk_widget().configure(bg='#2b2b2b')

    def save_report(self):
        if all_scan_results:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            json_filename = f"scan_{timestamp}.json"
            with open(os.path.join("scan_data", json_filename), "w") as f:
                json.dump(all_scan_results[0], f, indent=2)
            
            # This line generates AND saves the HTML report
            html_filename = generate_html_report(all_scan_results)
            
            self.status_label.configure(text=f"📄 Reports saved: {json_filename} and {html_filename}")

if __name__ == "__main__":
    app = NetworkAuditApp()
    app.mainloop()