import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import os
import webbrowser
from tkinter.font import Font
import time
from threading import Thread

class VaultGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔒 LOCKNTRUST")
        self.geometry("900x650")
        self.minsize(800, 600)
        self.configure(bg="white")
        
        # Vault state management
        self.vault_state = "locked"  # 'locked' or 'unlocked'
        self.current_vault_path = None
        self.current_password = None
        
        # Load custom theme
        self.setup_theme()
        
        # Application icon
        try:
            self.iconbitmap(default="securevault.ico")
        except:
            pass
            
        # Main container
        self.container = tk.Frame(self, bg="white")
        self.container.pack(fill="both", expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self, textvariable=self.status_var, 
                                  style="Status.TLabel")
        self.status_bar.pack(fill="x", side="bottom", ipady=5)
        self.update_status("Ready")
        
        # Initialize frames
        self.frames = {}
        for F in (LoginFrame, VaultFrame, LoadingFrame):
            frame = F(self.container, self)
            self.frames[F.__name__] = frame
        
        self.show_frame("LoginFrame")
        
        # Bind keyboard shortcuts
        self.bind("<F1>", lambda e: webbrowser.open("https://lockntrust.help"))
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_theme(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        self.style.configure(".", background="white", foreground="black")
        self.style.configure("TFrame", background="white")
        self.style.configure("TLabel", background="white", foreground="black", 
                           font=("Segoe UI", 11))
        self.style.configure("TButton", font=("Segoe UI", 11, "bold"), 
                           background="#6200ee", foreground="white",
                           borderwidth=0, relief="flat", padding=8)
        self.style.map("TButton",
                      background=[("active", "#3700b3"), ("pressed", "#000000")],
                      foreground=[("pressed", "#ffffff")])
        
        self.style.configure("Custom.TEntry", fieldbackground="#f0f0f0", 
                           foreground="black", insertcolor="black",
                           bordercolor="#6200ee", lightcolor="#6200ee",
                           darkcolor="#6200ee", padding=8)
        
        self.style.configure("Status.TLabel", background="#e0e0e0", 
                           foreground="#000000", font=("Segoe UI", 9))
        
        self.style.configure("Treeview", background="white", 
                           fieldbackground="white", foreground="black",
                           rowheight=25)
        self.style.map("Treeview", background=[("selected", "#6200ee")])
        self.style.configure("Treeview.Heading", background="#e0e0e0", 
                           foreground="black", font=("Segoe UI", 10, "bold"))

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        if page_name == "VaultFrame":
            frame.refresh_file_list()
        frame.tkraise()
        frame.pack(fill="both", expand=True)
        self.update_idletasks()
        
        if page_name != "LoadingFrame":
            frame.animate_in()

    def update_status(self, message, error=False):
        self.status_var.set(message)
        self.status_bar.configure(foreground="red" if error else "black")
        if error:
            self.after(5000, lambda: self.update_status("Ready"))

    def show_loading(self, message="Processing..."):
        self.frames["LoadingFrame"].set_message(message)
        self.show_frame("LoadingFrame")

    def hide_loading(self):
        for frame in self.frames.values():
            if isinstance(frame, LoadingFrame):
                frame.pack_forget()

    def on_close(self):
        if messagebox.askokcancel("Quit", "Do you want to exit LOCKNTRUST?"):
            # Clear sensitive data before closing
            self.current_vault_path = None
            self.current_password = None
            self.vault_state = "locked"
            self.destroy()

class LoadingFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, style="TFrame")
        self.controller = controller
        
        self.message_var = tk.StringVar(value="Processing...")
        
        container = ttk.Frame(self, style="TFrame")
        container.place(relx=0.5, rely=0.5, anchor="center")
        
        self.loading_label = ttk.Label(container, textvariable=self.message_var, 
                                    font=("Segoe UI", 14), style="TLabel")
        self.loading_label.pack(pady=20)
        
        self.canvas = tk.Canvas(container, width=60, height=60, bg="white",
                              highlightthickness=0)
        self.canvas.pack()
        
        self.angle = 0
        self.arc = self.canvas.create_arc(10, 10, 50, 50, start=0, extent=20,
                                        outline="#6200ee", width=3, style="arc")
        self.animate_loading()

    def set_message(self, message):
        self.message_var.set(message)

    def animate_loading(self):
        self.angle += 10
        self.canvas.itemconfig(self.arc, start=self.angle)
        self.after(50, self.animate_loading)

class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, style="TFrame")
        self.controller = controller
        
        container = ttk.Frame(self, style="TFrame")
        container.pack(expand=True, padx=50, pady=50)
        
        logo_font = Font(family="Segoe UI", size=24, weight="bold")
        ttk.Label(container, text="🔒 LOCKNTRUST", font=logo_font, 
                 foreground="#6200ee").pack(pady=(0, 30))
        
        path_frame = ttk.Frame(container, style="TFrame")
        path_frame.pack(fill="x", pady=5)
        
        ttk.Label(path_frame, text="Vault Path:").pack(anchor="w")
        
        self.vault_path_var = tk.StringVar()
        path_entry = ttk.Entry(path_frame, textvariable=self.vault_path_var, 
                              style="Custom.TEntry", width=40)
        path_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        browse_btn = ttk.Button(path_frame, text="Browse...", 
                              command=self.browse_vault_file, width=10)
        browse_btn.pack(side="right")
        
        ttk.Label(container, text="Password:").pack(anchor="w", pady=(15, 5))
        
        self.password_var = tk.StringVar()
        pass_entry = ttk.Entry(container, textvariable=self.password_var, 
                              show="•", style="Custom.TEntry", width=40)
        pass_entry.pack(fill="x")
        
        self.show_pass_var = tk.BooleanVar()
        show_pass = ttk.Checkbutton(container, text="Show password", 
                                  variable=self.show_pass_var,
                                  command=lambda: pass_entry.config(
                                      show="" if self.show_pass_var.get() else "•"
                                  ))
        show_pass.pack(anchor="w", pady=5)
        
        btn_frame = ttk.Frame(container, style="TFrame")
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Create Vault", 
                  command=self.create_vault).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Open Vault", 
                  command=self.open_vault).grid(row=0, column=1, padx=5)
        
        self.recent_vaults = self.get_recent_vaults()
        if self.recent_vaults:
            recent_frame = ttk.Frame(container, style="TFrame")
            recent_frame.pack(fill="x", pady=10)
            
            ttk.Label(recent_frame, text="Recent vaults:").pack(side="left")
            
            self.recent_var = tk.StringVar()
            recent_menu = ttk.OptionMenu(recent_frame, self.recent_var, 
                                        self.recent_vaults[0], *self.recent_vaults,
                                        command=self.select_recent_vault)
            recent_menu.pack(side="left", padx=5)
            
            ttk.Button(recent_frame, text="Refresh", 
                      command=self.refresh_recent_vaults).pack(side="left")

    def animate_in(self):
        self.controller.update_status("Ready")

    def get_recent_vaults(self):
        vaults = [f for f in os.listdir() if f.lower().endswith('.vault')]
        return vaults[:5]

    def refresh_recent_vaults(self):
        self.recent_vaults = self.get_recent_vaults()
        if hasattr(self, 'recent_var'):
            menu = self.recent_var.tk.call(
                f"{self.recent_var._name}","menu")
            self.recent_var.tk.call(menu, "delete", 0, "end")
            for vault in self.recent_vaults:
                self.recent_var.tk.call(menu, "add", "command", 
                                      label=vault, 
                                      command=tk._setit(self.recent_var, vault))

    def select_recent_vault(self, vault_path):
        self.vault_path_var.set(vault_path)

    def browse_vault_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Vault File",
            filetypes=[("LOCKNTRUST Vault", "*.vault"), ("All Files", "*.*")],
            defaultextension=".vault"
        )
        if file_path:
            self.vault_path_var.set(file_path)

    def create_vault(self):
        vault_path = self.vault_path_var.get().strip()
        password = self.password_var.get().strip()
        
        if not vault_path or not password:
            self.controller.update_status("Vault path & password required", error=True)
            return

        try:
            if not vault_path.lower().endswith('.vault'):
                vault_path += '.vault'
                self.vault_path_var.set(vault_path)
            
            self.controller.show_loading("Creating vault...")
            
            Thread(target=self._create_vault_thread, 
                  args=(vault_path, password)).start()
            
        except Exception as e:
            self.controller.update_status(f"Error: {str(e)}", error=True)
            self.controller.hide_loading()

    def _create_vault_thread(self, vault_path, password):
        try:
            time.sleep(2)
            
            # Set vault state
            self.controller.current_vault_path = vault_path
            self.controller.current_password = password
            self.controller.vault_state = "unlocked"
            
            self.controller.after(0, lambda: 
                self.controller.update_status(f"Vault created: {vault_path}"))
            self.controller.after(0, lambda: 
                self.controller.show_frame("VaultFrame"))
        except Exception as e:
            self.controller.after(0, lambda: 
                self.controller.update_status(f"Error: {str(e)}", error=True))
        finally:
            self.controller.after(0, self.controller.hide_loading)

    def open_vault(self):
        vault_path = self.vault_path_var.get().strip()
        password = self.password_var.get().strip()
        
        if not vault_path or not password:
            self.controller.update_status("Vault path & password required", error=True)
            return

        try:
            if not vault_path.lower().endswith('.vault'):
                vault_path += '.vault'
                self.vault_path_var.set(vault_path)
            
            if not os.path.exists(vault_path):
                raise FileNotFoundError(f"Vault file not found: {vault_path}")
            
            self.controller.show_loading("Opening vault...")
            
            Thread(target=self._open_vault_thread, 
                  args=(vault_path, password)).start()
            
        except Exception as e:
            self.controller.update_status(str(e), error=True)
            self.controller.hide_loading()

    def _open_vault_thread(self, vault_path, password):
        try:
            time.sleep(2)
            
            # Set vault state
            self.controller.current_vault_path = vault_path
            self.controller.current_password = password
            self.controller.vault_state = "unlocked"
            
            self.controller.after(0, lambda: 
                self.controller.update_status(f"Vault opened: {vault_path}"))
            self.controller.after(0, lambda: 
                self.controller.show_frame("VaultFrame"))
        except Exception as e:
            self.controller.after(0, lambda: 
                self.controller.update_status(f"Error: {str(e)}", error=True))
        finally:
            self.controller.after(0, self.controller.hide_loading)

class VaultFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, style="TFrame")
        self.controller = controller
        
        header = ttk.Frame(self, style="TFrame")
        header.pack(fill="x", pady=10)
        
        ttk.Label(header, text="🔓 Vault Contents", 
                 font=("Segoe UI", 18, "bold"),
                 foreground="#6200ee").pack(side="left", padx=20)
        
        lock_btn = ttk.Button(header, text="Lock Vault", 
                            command=self.lock_vault)
        lock_btn.pack(side="right", padx=20)
        
        main_content = ttk.Frame(self, style="TFrame")
        main_content.pack(fill="both", expand=True, padx=20, pady=10)
        
        action_frame = ttk.Frame(main_content, style="TFrame")
        action_frame.pack(fill="x", pady=10)
        
        actions = [
            ("📤 Add File", self.add_file),
            ("📋 Refresh", self.refresh_file_list),
            ("📥 Extract File", self.extract_file),
            ("🗑️ Remove File", self.remove_file)
        ]
        
        for i, (text, cmd) in enumerate(actions):
            btn = ttk.Button(action_frame, text=text, command=cmd)
            btn.grid(row=i//2, column=i%2, padx=5, pady=5, sticky="nsew")
            action_frame.grid_columnconfigure(i%2, weight=1)
        
        self.tree_frame = ttk.Frame(main_content, style="TFrame")
        self.tree_frame.pack(fill="both", expand=True, pady=10)
        
        self.tree = ttk.Treeview(self.tree_frame, columns=("Size", "Type"), 
                               selectmode="extended")
        self.tree.heading("#0", text="Filename", anchor="w")
        self.tree.heading("Size", text="Size", anchor="w")
        self.tree.heading("Type", text="Type", anchor="w")
        
        self.tree.column("#0", width=300, stretch=tk.YES)
        self.tree.column("Size", width=100, stretch=tk.NO)
        self.tree.column("Type", width=100, stretch=tk.NO)
        
        scroll_y = ttk.Scrollbar(self.tree_frame, orient="vertical", 
                               command=self.tree.yview)
        scroll_x = ttk.Scrollbar(self.tree_frame, orient="horizontal", 
                               command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll_y.set, 
                           xscrollcommand=scroll_x.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        
        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)
        
        self.file_count_var = tk.StringVar(value="0 files")
        status_frame = ttk.Frame(self, style="TFrame")
        status_frame.pack(fill="x", side="bottom", pady=5)
        
        ttk.Label(status_frame, textvariable=self.file_count_var, 
                style="Status.TLabel").pack(side="left", padx=10)
        
        self.tree.bind("<Button-1>", self.on_tree_select)
        self.tree.bind("<Double-1>", self.on_tree_double_click)
        self.tree.bind("<Delete>", self.on_delete_press)
        
        self.refresh_file_list()

    def animate_in(self):
        self.refresh_file_list()
        self.controller.update_status("Vault unlocked and ready")

    def lock_vault(self):
        if messagebox.askyesno("Lock Vault", "Are you sure you want to lock the vault?"):
            # Clear all sensitive data
            self.controller.current_vault_path = None
            self.controller.current_password = None
            self.controller.vault_state = "locked"
            
            # Clear the file list
            self.tree.delete(*self.tree.get_children())
            self.file_count_var.set("0 files")
            
            # Show login frame
            self.controller.show_frame("LoginFrame")
            self.controller.update_status("Vault locked successfully")

    def refresh_file_list(self):
        self.tree.delete(*self.tree.get_children())
        
        if self.controller.vault_state == "unlocked":
            files = [
                ("document.pdf", "2.4 MB", "PDF"),
                ("image.png", "1.8 MB", "Image"),
                ("data.csv", "345 KB", "CSV")
            ]
            
            for file in files:
                self.tree.insert("", "end", text=file[0], 
                               values=(file[1], file[2]))
            
            self.file_count_var.set(f"{len(files)} files in vault")

    def add_file(self):
        files = filedialog.askopenfilenames(title="Select files to add")
        if files:
            self.controller.show_loading(f"Adding {len(files)} files...")
            Thread(target=self._add_files_thread, args=(files,)).start()

    def _add_files_thread(self, files):
        try:
            for i, file_path in enumerate(files):
                time.sleep(0.5)
                self.controller.after(0, lambda f=file_path: 
                    self.controller.update_status(f"Adding {os.path.basename(f)}...")))
            
            self.controller.after(0, self.refresh_file_list)
            self.controller.after(0, lambda: 
                self.controller.update_status(f"Added {len(files)} files"))
        except Exception as e:
            self.controller.after(0, lambda: 
                self.controller.update_status(f"Error: {str(e)}", error=True))
        finally:
            self.controller.after(0, self.controller.hide_loading)

    def extract_file(self):
        selected = self.tree.selection()
        if not selected:
            self.controller.update_status("No files selected", error=True)
            return
        
        folder = filedialog.askdirectory(title="Select extraction folder")
        if folder:
            self.controller.show_loading(f"Extracting {len(selected)} files...")
            Thread(target=self._extract_files_thread, args=(selected, folder)).start()

    def _extract_files_thread(self, items, folder):
        try:
            for i, item in enumerate(items):
                file_name = self.tree.item(item, "text")
                time.sleep(0.5)
                self.controller.after(0, lambda f=file_name: 
                    self.controller.update_status(f"Extracting {f}...")))
            
            self.controller.after(0, lambda: 
                self.controller.update_status(f"Extracted {len(items)} files to {folder}"))
        except Exception as e:
            self.controller.after(0, lambda: 
                self.controller.update_status(f"Error: {str(e)}", error=True))
        finally:
            self.controller.after(0, self.controller.hide_loading)

    def remove_file(self):
        selected = self.tree.selection()
        if not selected:
            self.controller.update_status("No files selected", error=True)
            return
        
        if messagebox.askyesno("Confirm Removal", 
                             f"Delete {len(selected)} selected files?"):
            self.controller.show_loading(f"Removing {len(selected)} files...")
            Thread(target=self._remove_files_thread, args=(selected,)).start()

    def _remove_files_thread(self, items):
        try:
            for item in items:
                file_name = self.tree.item(item, "text")
                time.sleep(0.3)
                self.controller.after(0, lambda f=file_name: 
                    self.controller.update_status(f"Removing {f}...")))
            
            self.controller.after(0, self.refresh_file_list)
            self.controller.after(0, lambda: 
                self.controller.update_status(f"Removed {len(items)} files"))
        except Exception as e:
            self.controller.after(0, lambda: 
                self.controller.update_status(f"Error: {str(e)}", error=True))
        finally:
            self.controller.after(0, self.controller.hide_loading)

    def on_tree_select(self, event):
        selected = len(self.tree.selection())
        self.file_count_var.set(f"{selected} selected" if selected else self.file_count_var.get())

    def on_tree_double_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            file_name = self.tree.item(item, "text")
            self.controller.update_status(f"Double-clicked: {file_name}")

    def on_delete_press(self, event):
        self.remove_file()

def main():
    app = VaultGUI()
    app.mainloop()

if __name__ == "__main__":
    main()