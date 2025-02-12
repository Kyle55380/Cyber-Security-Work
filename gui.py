import socket
import threading
import struct
import tkinter as tk
from tkinter import scrolledtext, messagebox
from tkinter import ttk  # Import ttk for styling
from encryption import generate_rsa_keys, encrypt_message, decrypt_message, encrypt_aes_key, decrypt_aes_key
import rsa
import os

# Generate RSA keys
public_key, private_key = generate_rsa_keys()
public_partner = None
aes_key = None  # Symmetric key for encryption
BUFFER_SIZE = 4096

class SecureChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        self.root.geometry("700x550")  # Increased window size
        
        self.style = ttk.Style()
        self.style.theme_use("clam")  # Use a modern theme
        self.style.configure("TButton", font=("Arial", 12), padding=5)
        self.style.configure("TEntry", font=("Arial", 12), padding=5)
        self.style.configure("TLabel", font=("Arial", 12), padding=5)

        self.client = None
        self.create_login_window()

    def create_login_window(self):
        self.login_frame = ttk.Frame(self.root, padding=20)
        self.login_frame.pack(expand=True)

        ttk.Label(self.login_frame, text="Enter IP Address:", font=("Arial", 14)).pack(pady=5)
        self.ip_entry = ttk.Entry(self.login_frame, font=("Arial", 12))
        self.ip_entry.pack()

        ttk.Label(self.login_frame, text="Choose mode:", font=("Arial", 14)).pack(pady=5)
        self.choice_var = tk.StringVar(value="1")
        ttk.Radiobutton(self.login_frame, text="Host", variable=self.choice_var, value="1").pack()
        ttk.Radiobutton(self.login_frame, text="Connect", variable=self.choice_var, value="2").pack()

        ttk.Button(self.login_frame, text="Start Chat", command=self.start_chat).pack(pady=15)

    def start_chat(self):
        global aes_key, public_partner
        ip = self.ip_entry.get().strip() or "127.0.0.1"
        choice = self.choice_var.get()
        
        try:
            if choice == "1":  # Host
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.bind((ip, 9999))
                server.listen()
                self.client, addr = server.accept()

                self.client.send(public_key.save_pkcs1("PEM"))
                public_partner = rsa.PublicKey.load_pkcs1(self.client.recv(4096))
                
                aes_key = os.urandom(32)
                encrypted_aes_key = encrypt_aes_key(aes_key, public_partner)
                self.client.send(struct.pack("!I", len(encrypted_aes_key)) + encrypted_aes_key)
            else:  # Connect
                self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client.connect((ip, 9999))
                
                public_partner = rsa.PublicKey.load_pkcs1(self.client.recv(4096))
                self.client.send(public_key.save_pkcs1("PEM"))
                
                data_length = struct.unpack("!I", self.client.recv(4))[0]
                encrypted_aes_key = self.client.recv(data_length)
                aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
            
            self.show_chat_window()
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    def show_chat_window(self):
        self.login_frame.destroy()
        
        self.chat_frame = ttk.Frame(self.root, padding=20)
        self.chat_frame.pack(expand=True)

        self.chat_area = scrolledtext.ScrolledText(self.chat_frame, state='disabled', height=18, width=75, font=("Arial", 12))
        self.chat_area.pack(pady=10)

        entry_frame = ttk.Frame(self.chat_frame)
        entry_frame.pack()

        self.msg_entry = ttk.Entry(entry_frame, width=60, font=("Arial", 12))
        self.msg_entry.pack(side=tk.LEFT, padx=5)

        ttk.Button(entry_frame, text="Send", command=self.send_message).pack(side=tk.RIGHT)

    def send_message(self):
        message = self.msg_entry.get().strip()
        if not message:
            return
        
        try:
            encrypted = encrypt_message(message, aes_key)
            self.client.send(struct.pack("!I", len(encrypted)))
            self.client.sendall(encrypted)
            
            self.update_chat("You: " + message)
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", str(e))
    
    def receive_messages(self):
        while True:
            try:
                length_data = self.client.recv(4)
                if not length_data:
                    self.update_chat("[Connection closed by peer]")
                    break
                
                data_length = struct.unpack("!I", length_data)[0]
                encrypted_data = self.client.recv(data_length)
                decrypted = decrypt_message(encrypted_data, aes_key)
                
                self.update_chat("Partner: " + decrypted)
            except Exception as e:
                self.update_chat("[Error receiving message]")
                break
    
    def update_chat(self, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + '\n')
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatGUI(root)
    root.mainloop()
