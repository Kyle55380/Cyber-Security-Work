import socket
import threading
import struct
import tkinter as tk
from tkinter import scrolledtext, messagebox
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
        self.root.geometry("600x500")  # Increased window size
        self.client = None
        
        self.create_login_window()

    def create_login_window(self):
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(padx=20, pady=20)

        tk.Label(self.login_frame, text="Enter IP Address:").pack()
        self.ip_entry = tk.Entry(self.login_frame)
        self.ip_entry.pack()
        
        tk.Label(self.login_frame, text="Choose mode:").pack()
        self.choice_var = tk.StringVar(value="1")
        tk.Radiobutton(self.login_frame, text="Host", variable=self.choice_var, value="1").pack()
        tk.Radiobutton(self.login_frame, text="Connect", variable=self.choice_var, value="2").pack()
        
        tk.Button(self.login_frame, text="Start Chat", command=self.start_chat).pack(pady=10)

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
        
        self.chat_frame = tk.Frame(self.root)
        self.chat_frame.pack(padx=20, pady=20)
        
        self.chat_area = scrolledtext.ScrolledText(self.chat_frame, state='disabled', height=20, width=70)
        self.chat_area.pack()
        
        self.msg_entry = tk.Entry(self.chat_frame, width=50)
        self.msg_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Button(self.chat_frame, text="Send", command=self.send_message).pack(side=tk.RIGHT)
    
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
