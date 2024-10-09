import customtkinter as ctk
import json
import hashlib
import os
from tkinter import messagebox
import re
from typing import Dict, List, Optional
from datetime import datetime

class PasswordManager:
    def __init__(self):
        self.current_user = None
        self.window = ctk.CTk()
        self.window.title("SecurePass Manager")
        self.window.geometry("1000x600")
        
        # Set theme and colors
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize data file
        self.data_file = "password_data.json"
        self.initialize_data_file()
        
        # Create and show login frame
        self.show_login_page()
        
    def initialize_data_file(self):
        if not os.path.exists(self.data_file):
            initial_data = {
                "users": {
                    "admin": {
                        "password": self.hash_password("admin123"),
                        "is_admin": True,
                        "credentials": [],
                        "last_login": None
                    }
                }
            }
            with open(self.data_file, 'w') as f:
                json.dump(initial_data, f)

    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def load_data(self) -> Dict:
        with open(self.data_file, 'r') as f:
            return json.load(f)

    def save_data(self, data: Dict):
        with open(self.data_file, 'w') as f:
            json.dump(data, f)

    def show_status_indicator(self, parent, success: bool):
        status_label = ctk.CTkLabel(parent, text="✓" if success else "✗", 
                                   text_color="green" if success else "red",
                                   font=("Roboto", 20))
        status_label.pack(side="right", padx=5)
        self.window.after(2000, status_label.destroy)

    def show_login_page(self):
        self.clear_window()
        
        frame = ctk.CTkFrame(self.window)
        frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        logo_label = ctk.CTkLabel(frame, text="🔒", font=("Roboto", 48))
        logo_label.pack(pady=10)
        
        ctk.CTkLabel(frame, text="SecurePass Manager", font=("Roboto", 24, "bold")).pack(pady=10)
        
        username_entry = ctk.CTkEntry(frame, placeholder_text="Username", width=300)
        username_entry.pack(pady=10)
        
        password_entry = ctk.CTkEntry(frame, placeholder_text="Password", show="*", width=300)
        password_entry.pack(pady=10)
        
        button_frame = ctk.CTkFrame(frame)
        button_frame.pack(pady=10)
        
        login_button = ctk.CTkButton(
            button_frame, 
            text="Login",
            command=lambda: self.login(username_entry.get(), password_entry.get())
        )
        login_button.pack(side="left", padx=5)
        
        signup_button = ctk.CTkButton(
            button_frame,
            text="Sign Up",
            command=self.show_signup_page
        )
        signup_button.pack(side="left", padx=5)

        footer_label = ctk.CTkLabel(self.window, text="Your Secure Password Vault", font=("Roboto", 14), fg_color="#333")
        footer_label.pack(pady=10)

    def show_signup_page(self):
        self.clear_window()
        
        frame = ctk.CTkFrame(self.window)
        frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        ctk.CTkLabel(frame, text="Create Account", font=("Roboto", 24, "bold")).pack(pady=20)
        
        username_entry = ctk.CTkEntry(frame, placeholder_text="Username", width=300)
        username_entry.pack(pady=10)
        
        password_entry = ctk.CTkEntry(frame, placeholder_text="Password", show="*", width=300)
        password_entry.pack(pady=10)
        
        confirm_password_entry = ctk.CTkEntry(frame, placeholder_text="Confirm Password", show="*", width=300)
        confirm_password_entry.pack(pady=10)
        
        button_frame = ctk.CTkFrame(frame)
        button_frame.pack(pady=10)
        
        signup_button = ctk.CTkButton(
            button_frame,
            text="Sign Up",
            command=lambda: self.signup(
                username_entry.get(),
                password_entry.get(),
                confirm_password_entry.get(),
                button_frame
            )
        )
        signup_button.pack(side="left", padx=5)
        
        back_button = ctk.CTkButton(
            button_frame,
            text="Back to Login",
            command=self.show_login_page
        )
        back_button.pack(side="left", padx=5)

    def login(self, username: str, password: str):
        data = self.load_data()
        if username in data["users"] and data["users"][username]["password"] == self.hash_password(password):
            self.current_user = username
            data["users"][username]["last_login"] = datetime.now().isoformat()
            self.save_data(data)
            self.show_main_page()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def signup(self, username: str, password: str, confirm_password: str, button_frame):
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            self.show_status_indicator(button_frame, False)
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            self.show_status_indicator(button_frame, False)
            return
        
        data = self.load_data()
        if username in data["users"]:
            messagebox.showerror("Error", "Username already exists")
            self.show_status_indicator(button_frame, False)
            return
        
        data["users"][username] = {
            "password": self.hash_password(password),
            "is_admin": False,
            "credentials": [],
            "last_login": None
        }
        self.save_data(data)
        self.show_status_indicator(button_frame, True)
        self.window.after(2000, self.show_login_page)

    def show_main_page(self):
        self.clear_window()
        
        # Create navigation frame
        nav_frame = ctk.CTkFrame(self.window, width=200)
        nav_frame.pack(side="left", fill="y", padx=10, pady=10)
        
        user_frame = ctk.CTkFrame(nav_frame)
        user_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(user_frame, text=f"👤 {self.current_user}", font=("Roboto", 16, "bold")).pack(side="left", pady=5)
        
        # Add colorful icons for buttons
        buttons = [
            ("➕ Add Credentials", self.show_add_credentials),
            ("👁️ View Credentials", self.show_view_credentials),
            ("✏️ Edit Credentials", self.show_edit_credentials),
            ("🔑 Change Password", self.show_change_password),
        ]
        
        for text, command in buttons:
            button = ctk.CTkButton(nav_frame, text=text, command=command)
            button.pack(pady=5, padx=5, fill="x")
        
        if self.is_admin():
            ctk.CTkButton(nav_frame, text="⚙️ Admin Panel", command=self.show_admin_panel).pack(pady=5, padx=5, fill="x")
        
        ctk.CTkButton(nav_frame, text="🚪 Logout", command=self.logout, fg_color="red").pack(pady=20, padx=5, fill="x")
        
        # Create main content frame
        self.content_frame = ctk.CTkFrame(self.window)
        self.content_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # Show welcome dashboard
        self.show_dashboard()

    def show_dashboard(self):
        self.clear_content_frame()
        
        data = self.load_data()
        user_data = data["users"][self.current_user]
        
        ctk.CTkLabel(self.content_frame, text="Dashboard", font=("Roboto", 24, "bold")).pack(pady=10)
        
        stats_frame = ctk.CTkFrame(self.content_frame)
        stats_frame.pack(fill="x", padx=20, pady=10)
        
        # Statistics
        num_credentials = len(user_data["credentials"])
        last_login = user_data["last_login"]
        last_login_str = "Never" if last_login is None else datetime.fromisoformat(last_login).strftime("%Y-%m-%d %H:%M")
        
        stats = [
            ("🔑 Total Credentials", str(num_credentials)),
            ("🕒 Last Login", last_login_str),
            ("🛡️ Account Type", "Admin" if user_data["is_admin"] else "User"),
        ]
        
        for title, value in stats:
            stat_frame = ctk.CTkFrame(stats_frame)
            stat_frame.pack(side="left", expand=True, padx=5, pady=5)
            
            ctk.CTkLabel(stat_frame, text=title, font=("Roboto", 14)).pack()
            ctk.CTkLabel(stat_frame, text=value, font=("Roboto", 16, "bold")).pack()

    def show_change_password(self):
        self.clear_content_frame()
        
        ctk.CTkLabel(self.content_frame, text="Change Password", font=("Roboto", 20, "bold")).pack(pady=10)
        
        current_password = ctk.CTkEntry(self.content_frame, placeholder_text="Current Password", show="*", width=300)
        current_password.pack(pady=10)
        
        new_password = ctk.CTkEntry(self.content_frame, placeholder_text="New Password", show="*", width=300)
        new_password.pack(pady=10)
        
        confirm_password = ctk.CTkEntry(self.content_frame, placeholder_text="Confirm New Password", show="*", width=300)
        confirm_password.pack(pady=10)
        
        button_frame = ctk.CTkFrame(self.content_frame)
        button_frame.pack(pady=10)
        
        change_button = ctk.CTkButton(
            button_frame,
            text="Change Password",
            command=lambda: self.change_password(
                current_password.get(),
                new_password.get(),
                confirm_password.get(),
                button_frame
            )
        )
        change_button.pack()

    def change_password(self, current_password: str, new_password: str, confirm_password: str, button_frame):
        data = self.load_data()
        user_data = data["users"][self.current_user]
        
        if self.hash_password(current_password) != user_data["password"]:
            self.show_status_indicator(button_frame, False)
            messagebox.showerror("Error", "Current password is incorrect")
            return
        
        if new_password != confirm_password:
            self.show_status_indicator(button_frame, False)
            messagebox.showerror("Error", "New passwords do not match")
            return
        
        data["users"][self.current_user]["password"] = self.hash_password(new_password)
        self.save_data(data)
        self.show_status_indicator(button_frame, True)

    def show_credential_password(self, credential: Dict):
        dialog = ctk.CTkInputDialog(text="Enter your password to view:", title="Password Required")
        password = dialog.get_input()
        
        if password is None:
            return
        
        data = self.load_data()
        if self.hash_password(password) == data["users"][self.current_user]["password"]:
            messagebox.showinfo("Password", f"Password for {credential['service']}: {credential['password']}")
        else:
            messagebox.showerror("Error", "Incorrect password")

    def show_view_credentials(self):
        self.clear_content_frame()
        
        ctk.CTkLabel(self.content_frame, text="View Credentials", font=("Roboto", 20, "bold")).pack(pady=10)
        
        search_frame = ctk.CTkFrame(self.content_frame)
        search_frame.pack(fill="x", pady=10)
        
        search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search by service name")
        search_entry.pack(side="left", padx=5, expand=True, fill="x")
        
        ctk.CTkButton(
            search_frame,
            text="🔍 Search",
            command=lambda: self.update_credentials_list(search_entry.get())
        ).pack(side="right", padx=5)
        
        self.credentials_frame = ctk.CTkScrollableFrame(self.content_frame)
        self.credentials_frame.pack(fill="both", expand=True)
        
        self.update_credentials_list()

    def update_credentials_list(self, search_term: str = ""):
        for widget in self.credentials_frame.winfo_children():
            widget.destroy()
        
        data = self.load_data()
        credentials = data["users"][self.current_user]["credentials"]
        
        if search_term:
            credentials = [cred for cred in credentials if search_term.lower() in cred["service"].lower()]
        
        if not credentials:
            ctk.CTkLabel(self.credentials_frame, text="No credentials found").pack(pady=10)
            return
        
        for cred in credentials:
            cred_frame = ctk.CTkFrame(self.credentials_frame)
            cred_frame.pack(fill="x", pady=5, padx=10)
            
            info_frame = ctk.CTkFrame(cred_frame)
            info_frame.pack(side="left", fill="x", expand=True)
            
            ctk.CTkLabel(info_frame, text=f"Service: {cred['service']}", anchor="w").pack(fill="x")
            ctk.CTkLabel(info_frame, text=f"Email: {cred['email']}", anchor="w").pack(fill="x")
            password_frame = ctk.CTkFrame(info_frame)
            password_frame.pack(fill="x")
            ctk.CTkLabel(password_frame, text="Password: ", anchor="w").pack(side="left")
            ctk.CTkLabel(password_frame, text="*" * 8).pack(side="left")
            
            ctk.CTkButton(
                cred_frame,
                text="👁️",
                width=30,
                command=lambda c=cred: self.show_credential_password(c)
            ).pack(side="right", padx=5)

    def show_add_credentials(self):
        self.clear_content_frame()
        
        ctk.CTkLabel(self.content_frame, text="Add New Credentials", font=("Roboto", 20, "bold")).pack(pady=10)
        
        form_frame = ctk.CTkFrame(self.content_frame)
        form_frame.pack(pady=20, padx=20)
        
        service_entry = ctk.CTkEntry(form_frame, placeholder_text="Service Name", width=300)
        service_entry.pack(pady=10)
        
        email_entry = ctk.CTkEntry(form_frame, placeholder_text="Email", width=300)
        email_entry.pack(pady=10)
        
        password_entry = ctk.CTkEntry(form_frame, placeholder_text="Password", show="*", width=300)
        password_entry.pack(pady=10)
        
        button_frame = ctk.CTkFrame(form_frame)
        button_frame.pack(pady=10)
        
        add_button = ctk.CTkButton(
            button_frame,
            text="Add Credentials",
            command=lambda: self.add_credentials(
                service_entry.get(),
                email_entry.get(),
                password_entry.get(),
                button_frame
            )
        )
        add_button.pack()

    def add_credentials(self, service: str, email: str, password: str, button_frame):
        if not service or not email or not password:
            self.show_status_indicator(button_frame, False)
            messagebox.showerror("Error", "All fields are required")
            return
        
        data = self.load_data()
        new_credential = {
            "service": service,
            "email": email,
            "password": password
        }
        data["users"][self.current_user]["credentials"].append(new_credential)
        self.save_data(data)
        self.show_status_indicator(button_frame, True)
        self.window.after(2000, self.show_view_credentials)

    def show_edit_credentials(self):
        self.clear_content_frame()
        
        ctk.CTkLabel(self.content_frame, text="Edit Credentials", font=("Roboto", 20, "bold")).pack(pady=10)
        
        search_frame = ctk.CTkFrame(self.content_frame)
        search_frame.pack(fill="x", pady=10)
        
        search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search by service name")
        search_entry.pack(side="left", padx=5, expand=True, fill="x")
        
        ctk.CTkButton(
            search_frame,
            text="🔍 Search",
            command=lambda: self.update_edit_credentials_list(search_entry.get())
        ).pack(side="right", padx=5)
        
        self.edit_credentials_frame = ctk.CTkScrollableFrame(self.content_frame)
        self.edit_credentials_frame.pack(fill="both", expand=True)
        
        self.update_edit_credentials_list()

    def update_edit_credentials_list(self, search_term: str = ""):
        for widget in self.edit_credentials_frame.winfo_children():
            widget.destroy()
        
        data = self.load_data()
        credentials = data["users"][self.current_user]["credentials"]
        
        if search_term:
            credentials = [cred for cred in credentials if search_term.lower() in cred["service"].lower()]
        
        if not credentials:
            ctk.CTkLabel(self.edit_credentials_frame, text="No credentials found").pack(pady=10)
            return
        
        for cred in credentials:
            cred_frame = ctk.CTkFrame(self.edit_credentials_frame)
            cred_frame.pack(fill="x", pady=5, padx=10)
            
            info_frame = ctk.CTkFrame(cred_frame)
            info_frame.pack(side="left", fill="x", expand=True)
            
            ctk.CTkLabel(info_frame, text=f"Service: {cred['service']}", anchor="w").pack(fill="x")
            ctk.CTkLabel(info_frame, text=f"Email: {cred['email']}", anchor="w").pack(fill="x")
            
            button_frame = ctk.CTkFrame(cred_frame)
            button_frame.pack(side="right")
            
            ctk.CTkButton(
                button_frame,
                text="Edit",
                command=lambda c=cred: self.show_edit_credential_form(c)
            ).pack(side="left", padx=2)
            
            ctk.CTkButton(
                button_frame,
                text="Delete",
                fg_color="red",
                command=lambda c=cred: self.delete_credential(c)
            ).pack(side="left", padx=2)

    def show_edit_credential_form(self, credential: Dict):
        edit_window = ctk.CTkToplevel(self.window)
        edit_window.title(f"Edit {credential['service']}")
        edit_window.geometry("400x300")
        
        ctk.CTkLabel(edit_window, text=f"Editing {credential['service']}", font=("Roboto", 16, "bold")).pack(pady=10)
        
        service_entry = ctk.CTkEntry(edit_window, placeholder_text="Service Name", width=300)
        service_entry.insert(0, credential['service'])
        service_entry.pack(pady=10)
        
        email_entry = ctk.CTkEntry(edit_window, placeholder_text="Email", width=300)
        email_entry.insert(0, credential['email'])
        email_entry.pack(pady=10)
        
        password_entry = ctk.CTkEntry(edit_window, placeholder_text="Password", show="*", width=300)
        password_entry.insert(0, credential['password'])
        password_entry.pack(pady=10)
        
        button_frame = ctk.CTkFrame(edit_window)
        button_frame.pack(pady=10)
        
        save_button = ctk.CTkButton(
            button_frame,
            text="Save Changes",
            command=lambda: self.save_credential_changes(
                credential,
                service_entry.get(),
                email_entry.get(),
                password_entry.get(),
                edit_window,
                button_frame
            )
        )
        save_button.pack(side="left", padx=5)
        
        cancel_button = ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=edit_window.destroy
        )
        cancel_button.pack(side="left", padx=5)

    def save_credential_changes(self, old_cred: Dict, service: str, email: str, password: str, window, button_frame):
        if not service or not email or not password:
            self.show_status_indicator(button_frame, False)
            messagebox.showerror("Error", "All fields are required")
            return
        
        data = self.load_data()
        credentials = data["users"][self.current_user]["credentials"]
        
        for i, cred in enumerate(credentials):
            if cred == old_cred:
                credentials[i] = {
                    "service": service,
                    "email": email,
                    "password": password
                }
                break
        
        self.save_data(data)
        self.show_status_indicator(button_frame, True)
        self.window.after(2000, window.destroy)
        self.show_edit_credentials()

    def delete_credential(self, credential: Dict):
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the credential for {credential['service']}?"):
            data = self.load_data()
            data["users"][self.current_user]["credentials"] = [
                cred for cred in data["users"][self.current_user]["credentials"] if cred != credential
            ]
            self.save_data(data)
            self.show_edit_credentials()

    def show_admin_panel(self):
        if not self.is_admin():
            messagebox.showerror("Error", "Access denied")
            return
        
        self.clear_content_frame()
        
        ctk.CTkLabel(self.content_frame, text="Admin Panel", font=("Roboto", 20, "bold")).pack(pady=10)
        
        tabs = ctk.CTkTabview(self.content_frame)
        tabs.pack(fill="both", expand=True)
        
        # User Management Tab
        user_tab = tabs.add("User Management")
        self.show_user_management(user_tab)
        
        # Credentials Management Tab
        cred_tab = tabs.add("All Credentials")
        self.show_all_credentials(cred_tab)

    def show_user_management(self, parent):
        data = self.load_data()
        for username, user_data in data["users"].items():
            if username != "admin":
                user_frame = ctk.CTkFrame(parent)
                user_frame.pack(fill="x", pady=5, padx=10)
                
                info_frame = ctk.CTkFrame(user_frame)
                info_frame.pack(side="left", fill="x", expand=True)
                
                ctk.CTkLabel(info_frame, text=f"Username: {username}").pack(anchor="w")
                ctk.CTkLabel(info_frame, text=f"Credentials: {len(user_data['credentials'])}").pack(anchor="w")
                
                button_frame = ctk.CTkFrame(user_frame)
                button_frame.pack(side="right")
                
                ctk.CTkButton(
                    button_frame,
                    text="Reset Password",
                    command=lambda u=username: self.admin_reset_password(u)
                ).pack(side="left", padx=2)
                
                ctk.CTkButton(
                    button_frame,
                    text="Delete User",
                    fg_color="red",
                    command=lambda u=username: self.delete_user(u)
                ).pack(side="left", padx=2)

    def show_all_credentials(self, parent):
        data = self.load_data()
        
        for username, user_data in data["users"].items():
            if username != "admin" and user_data["credentials"]:
                ctk.CTkLabel(parent, text=f"User: {username}", font=("Roboto", 16, "bold")).pack(anchor="w", pady=5)
                
                for cred in user_data["credentials"]:
                    cred_frame = ctk.CTkFrame(parent)
                    cred_frame.pack(fill="x", pady=2, padx=10)
                    
                    info_frame = ctk.CTkFrame(cred_frame)
                    info_frame.pack(side="left", fill="x", expand=True)
                    
                    ctk.CTkLabel(info_frame, text=f"Service: {cred['service']}").pack(anchor="w")
                    ctk.CTkLabel(info_frame, text=f"Email: {cred['email']}").pack(anchor="w")
                    
                    button_frame = ctk.CTkFrame(cred_frame)
                    button_frame.pack(side="right")
                    
                    ctk.CTkButton(
                        button_frame,
                        text="Edit",
                        command=lambda u=username, c=cred: self.admin_edit_credential(u, c)
                    ).pack(side="left", padx=2)

    def admin_reset_password(self, username: str):
        dialog = ctk.CTkInputDialog(text=f"Enter new password for {username}:", title="Reset Password")
        new_password = dialog.get_input()
        
        if new_password:
            data = self.load_data()
            data["users"][username]["password"] = self.hash_password(new_password)
            self.save_data(data)
            messagebox.showinfo("Success", f"Password reset for {username}")

    def admin_edit_credential(self, username: str, credential: Dict):
        dialog = ctk.CTkToplevel(self.window)
        dialog.title(f"Edit Credential - {username}")
        dialog.geometry("400x300")
        
        ctk.CTkLabel(dialog, text=f"Editing {credential['service']} for {username}").pack(pady=10)
        
        service_entry = ctk.CTkEntry(dialog, placeholder_text="Service Name")
        service_entry.insert(0, credential['service'])
        service_entry.pack(pady=10)
        
        email_entry = ctk.CTkEntry(dialog, placeholder_text="Email")
        email_entry.insert(0, credential['email'])
        email_entry.pack(pady=10)
        
        password_entry = ctk.CTkEntry(dialog, placeholder_text="Password")
        password_entry.insert(0, credential['password'])
        password_entry.pack(pady=10)
        
        button_frame = ctk.CTkFrame(dialog)
        button_frame.pack(pady=10)
        
        ctk.CTkButton(
            button_frame,
            text="Save Changes",
            command=lambda: self.save_admin_credential_changes(
                username, credential,
                service_entry.get(),
                email_entry.get(),
                password_entry.get(),
                dialog, button_frame
            )
        ).pack(side="left", padx=5)

    def save_admin_credential_changes(self, username: str, old_cred: Dict, 
                                    service: str, email: str, password: str, 
                                    dialog, button_frame):
        data = self.load_data()
        user_credentials = data["users"][username]["credentials"]
        
        for i, cred in enumerate(user_credentials):
            if cred == old_cred:
                user_credentials[i] = {
                    "service": service,
                    "email": email,
                    "password": password
                }
                break
        
        self.save_data(data)
        self.show_status_indicator(button_frame, True)
        self.window.after(2000, dialog.destroy)
        self.show_admin_panel()

    def delete_user(self, username: str):
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete user {username}?"):
            data = self.load_data()
            del data["users"][username]
            self.save_data(data)
            self.show_admin_panel()

    def is_admin(self) -> bool:
        data = self.load_data()
        return data["users"][self.current_user]["is_admin"]

    def clear_window(self):
        for widget in self.window.winfo_children():
            widget.destroy()

    def clear_content_frame(self):
        if hasattr(self, 'content_frame'):
            for widget in self.content_frame.winfo_children():
                widget.destroy()

    def clear_content_frame(self):
        if hasattr(self, 'content_frame'):
            for widget in self.content_frame.winfo_children():
                widget.destroy()

    def logout(self):
        self.current_user = None
        self.show_login_page()

    def run(self):
        self.window.mainloop()

    def generate_password(self, length=12):
        import string
        import random
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

    def show_password_generator(self):
        self.clear_content_frame()
        
        ctk.CTkLabel(self.content_frame, text="Password Generator", font=("Roboto", 20, "bold")).pack(pady=10)
        
        length_frame = ctk.CTkFrame(self.content_frame)
        length_frame.pack(pady=10)
        
        ctk.CTkLabel(length_frame, text="Password Length:").pack(side="left", padx=5)
        length_entry = ctk.CTkEntry(length_frame, width=50)
        length_entry.insert(0, "12")
        length_entry.pack(side="left", padx=5)
        
        password_var = ctk.StringVar()
        password_label = ctk.CTkEntry(self.content_frame, textvariable=password_var, width=300, state="readonly")
        password_label.pack(pady=10)
        
        def generate():
            try:
                length = int(length_entry.get())
                password = self.generate_password(length)
                password_var.set(password)
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid number for password length")
        
        generate_button = ctk.CTkButton(self.content_frame, text="Generate Password", command=generate)
        generate_button.pack(pady=10)
        
        copy_button = ctk.CTkButton(self.content_frame, text="Copy to Clipboard", command=lambda: self.window.clipboard_clear() or self.window.clipboard_append(password_var.get()))
        copy_button.pack(pady=10)

if __name__ == "__main__":
    app = PasswordManager()
    app.run()