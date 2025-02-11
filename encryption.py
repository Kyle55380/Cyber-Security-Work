import socket
import threading
import getpass
import rsa
# 192.168.1.39
public_key, private_key = rsa.newkeys(1024)
public_partner = None

choice = input("Do you want to host(1) or connect(2)? ")

if choice == "1":
    IP = getpass.getpass("What is your IP to bind to? ")

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((IP, 9999))
        server.listen()
        print(f"Server listening on {IP}:9999...")

        client, addr = server.accept()
        print(f"Accepted connection from {addr}")
        
        client.send(public_key.save_pkcs1("PEM"))
        public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))

    except socket.gaierror:
        print(f"Invalid IP address: {IP}")
        exit(1)
    except OSError as e:
        print(f"OS error occurred: {e}")
        exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while hosting: {e}")
        exit(1)

elif choice == "2":
    IP = getpass.getpass("What IP do you want to connect to? ")

    try: 
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((IP, 9999))  
        print(f"Connected to {IP}:9999")

        public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
        client.send(public_key.save_pkcs1("PEM"))

    except socket.gaierror:
        print(f"Invalid IP address or hostname: {IP}")
        exit(1)
    except ConnectionRefusedError:
        print(f"Connection refused by the server at {IP}:9999. Is it running?")
        exit(1)
    except socket.timeout:
        print(f"Connection to {IP}:9999 timed out.")
        exit(1)
    except OSError as e:
        print(f"OS error occurred: {e}")
        exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while connecting: {e}")
        exit(1)
else:
    print("Invalid choice. Exiting.")
    exit(0)

def send_messages(c):
    while True:
        message = input("You: ")
        if not message:
            continue
        try: 
            encrypted = rsa.encrypt(message.encode(), public_partner)
            c.send(encrypted)

        except Exception as e:
            print(f"Error sending message: {e}")
            break

def receive_messages(c):
    while True:
        data = c.recv(1024)
        if not data:
            print("Connection closed by peer.")
            break
            
        decrypted = rsa.decrypt(data, private_key)
        print("Partner:", decrypted.decode())
        
if choice == "1":
    threading.Thread(target=send_messages, args=(client,)).start()
    threading.Thread(target=receive_messages, args=(client,)).start()
elif choice == "2":
    threading.Thread(target=send_messages, args=(client,)).start()
    threading.Thread(target=receive_messages, args=(client,)).start()
