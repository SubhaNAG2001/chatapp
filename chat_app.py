import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import socket
import threading
from cryptography.fernet import Fernet
import requests

class ChatServer:
    def __init__(self, host='0.0.0.0', port=12345):
        self.host = host
        self.port = port
        self.server = None
        self.clients = {}  # Store clients with their names: {socket: name}
        self.room_id = ""
        self.room_password = ""
        self.host_name = "Host"
        self.running = False
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        
    def start(self, room_id, room_password, host_name):
        self.room_id = room_id
        self.room_password = room_password
        self.host_name = host_name
        self.running = True
        
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind((self.host, self.port))
            self.server.listen(5)
            print(f"Server started on {self.host}:{self.port}")
            
            accept_thread = threading.Thread(target=self.accept_clients)
            accept_thread.daemon = True
            accept_thread.start()
            return True
        except Exception as e:
            print(f"Server error: {e}")
            return False
            
    def accept_clients(self):
        while self.running:
            try:
                client, addr = self.server.accept()
                print(f"Connection from {addr}")
                
                # Send encryption key to client
                client.send(self.encryption_key)
                
                # First receive client name
                name_data = client.recv(1024)
                client_name = self.cipher.decrypt(name_data).decode()
                
                # Then receive credentials
                credentials = client.recv(1024)
                decrypted_credentials = self.cipher.decrypt(credentials).decode()
                room_id, password = decrypted_credentials.split(':')
                
                if room_id == self.room_id and password == self.room_password:
                    client.send(self.cipher.encrypt(b"SUCCESS"))
                    self.clients[client] = client_name
                    
                    # Notify everyone about new user
                    join_msg = f"[SYSTEM] {client_name} joined the chat"
                    self.broadcast(join_msg, exclude=client)
                    
                    threading.Thread(target=self.handle_client, args=(client,)).start()
                else:
                    client.send(self.cipher.encrypt(b"FAIL"))
                    client.close()
            except Exception as e:
                if self.running:
                    print(f"Accept error: {e}")
                    
    def handle_client(self, client):
        client_name = self.clients[client]
        try:
            while self.running:
                data = client.recv(1024)
                if not data:
                    break
                    
                decrypted_msg = self.cipher.decrypt(data).decode()
                # Broadcast message to all clients including host
                self.broadcast(f"[USER] {client_name}: {decrypted_msg}")
        except:
            pass
            
        # Handle client disconnection
        if client in self.clients:
            leave_msg = f"[SYSTEM] {self.clients[client]} left the chat"
            del self.clients[client]
            self.broadcast(leave_msg)
        client.close()
        
    def broadcast(self, message, exclude=None):
        """Send message to all clients, optionally excluding one"""
        encrypted_msg = self.cipher.encrypt(message.encode())
        for client in list(self.clients.keys()):
            if client != exclude:
                try:
                    client.send(encrypted_msg)
                except:
                    # Remove disconnected client
                    if client in self.clients:
                        del self.clients[client]
    
    def send_host_message(self, message):
        """Special method for host to send messages"""
        self.broadcast(f"[HOST] {self.host_name}: {message}")
        
    def stop(self):
        self.running = False
        for client in list(self.clients.keys()):
            client.close()
        if self.server:
            self.server.close()

class ChatClient:
    def __init__(self, host, port=12345):
        self.host = host
        self.port = port
        self.client = None
        self.cipher = None
        self.running = False
        self.user_name = "User"
        
    def connect(self, room_id, password, user_name):
        self.user_name = user_name
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.settimeout(10)  # Timeout for public IP connections
            
            try:
                self.client.connect((self.host, self.port))
            except socket.timeout:
                return "timeout"
            except ConnectionRefusedError:
                return "refused"
                
            # Receive encryption key
            encryption_key = self.client.recv(1024)
            self.cipher = Fernet(encryption_key)
            
            # First send user name
            encrypted_name = self.cipher.encrypt(self.user_name.encode())
            self.client.send(encrypted_name)
            
            # Then send credentials
            credentials = f"{room_id}:{password}".encode()
            encrypted_credentials = self.cipher.encrypt(credentials)
            self.client.send(encrypted_credentials)
            
            # Check if credentials were accepted
            response = self.client.recv(1024)
            decrypted_response = self.cipher.decrypt(response).decode()
            
            return "success" if decrypted_response == "SUCCESS" else "auth_fail"
        except Exception as e:
            print(f"Connection error: {e}")
            return str(e)
            
    def send_message(self, message):
        if self.client and self.running:
            encrypted_msg = self.cipher.encrypt(message.encode())
            self.client.send(encrypted_msg)
            
    def receive_messages(self, callback):
        self.running = True
        while self.running:
            try:
                data = self.client.recv(1024)
                if not data:
                    break
                    
                decrypted_msg = self.cipher.decrypt(data).decode()
                callback(decrypted_msg)
            except:
                break
                
    def disconnect(self):
        self.running = False
        if self.client:
            self.client.close()

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Public Chat Rooms")
        self.set_window_icon()
        self.root.geometry("750x600")
        self.root.resizable(True, True)
        
        self.server = None
        self.client = None
        self.public_ip = self.get_public_ip()
        
        self.create_welcome_screen()
        
    def set_window_icon(self):
        try:
            self.root.iconbitmap('chat_icon.ico')  # Place your icon file in the same directory
        except:
            pass  # Icon file not found, use default
            
    def get_public_ip(self):
        try:
            return requests.get('https://api.ipify.org').text
        except:
            return "Could not detect public IP"
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def create_welcome_screen(self):
        self.clear_frame()
        
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Public Chat Rooms", font=("Arial", 16, "bold")).pack(pady=10)
        
        # Network information panel
        info_frame = ttk.LabelFrame(frame, text="Your Network Information", padding=10)
        info_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(info_frame, text=f"Public IP: {self.public_ip}", font=("Arial", 10)).pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Local IP: {self.get_local_ip()}", font=("Arial", 10)).pack(anchor=tk.W)
        ttk.Label(info_frame, text="Port: 12345", font=("Arial", 10)).pack(anchor=tk.W)
        ttk.Label(info_frame, 
                 text="Note: For public connections, port 12345 must be forwarded on your router",
                 font=("Arial", 9, "italic"), foreground="blue").pack(anchor=tk.W, pady=5)
        
        ttk.Separator(frame, orient='horizontal').pack(fill=tk.X, pady=20)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Create Room", 
                  command=self.create_room_screen, width=20).pack(pady=10)
        ttk.Button(button_frame, text="Join Room", 
                  command=self.join_room_screen, width=20).pack(pady=10)
        
        ttk.Button(frame, text="Exit", command=self.root.destroy).pack(pady=10)
        
    def create_room_screen(self):
        self.clear_frame()
        
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Create Chat Room", font=("Arial", 14)).pack(pady=10)
        
        # Network info reminder
        info_frame = ttk.LabelFrame(frame, text="Important Information", padding=10)
        info_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(info_frame, text="1. Share your PUBLIC IP with friends: " + self.public_ip, 
                 font=("Arial", 9)).pack(anchor=tk.W)
        ttk.Label(info_frame, text="2. Make sure port 12345 is forwarded in your router", 
                 font=("Arial", 9)).pack(anchor=tk.W)
        
        form_frame = ttk.Frame(frame)
        form_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(form_frame, text="Room ID:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.room_id_entry = ttk.Entry(form_frame, width=30)
        self.room_id_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.room_pw_entry = ttk.Entry(form_frame, width=30, show="*")
        self.room_pw_entry.grid(row=1, column=1, padx=5, pady=5)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Create Room", 
                  command=self.start_server, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Back", 
                  command=self.create_welcome_screen, width=15).pack(side=tk.LEFT, padx=5)
    
    def join_room_screen(self):
        self.clear_frame()
        
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Join Chat Room", font=("Arial", 14)).pack(pady=10)
        
        form_frame = ttk.Frame(frame)
        form_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(form_frame, text="Host Public IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.server_ip_entry = ttk.Entry(form_frame, width=30)
        self.server_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Room ID:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.join_room_id_entry = ttk.Entry(form_frame, width=30)
        self.join_room_id_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.join_room_pw_entry = ttk.Entry(form_frame, width=30, show="*")
        self.join_room_pw_entry.grid(row=2, column=1, padx=5, pady=5)
        
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Join Room", 
                  command=self.join_room, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Back", 
                  command=self.create_welcome_screen, width=15).pack(side=tk.LEFT, padx=5)
    
    def chat_screen(self, is_host=False):
        self.clear_frame()
        
        frame = ttk.Frame(self.root)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Chat display area
        chat_frame = ttk.Frame(frame)
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = ttk.Scrollbar(chat_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.chat_display = tk.Text(chat_frame, yscrollcommand=scrollbar.set, state=tk.DISABLED,
                                  wrap=tk.WORD, font=("Arial", 10))
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        
        # Configure message tags
        self.chat_display.tag_config("host", foreground="blue")
        self.chat_display.tag_config("user", foreground="green")
        self.chat_display.tag_config("system", foreground="red")
        self.chat_display.tag_config("error", foreground="orange")
        
        scrollbar.config(command=self.chat_display.yview)
        
        # Message entry area
        entry_frame = ttk.Frame(frame)
        entry_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.message_entry = ttk.Entry(entry_frame, font=("Arial", 10))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_chat_message)
        self.message_entry.focus_set()
        
        send_button = ttk.Button(entry_frame, text="Send", command=self.send_chat_message)
        send_button.pack(side=tk.RIGHT)
        
        # Status bar
        status_text = "Host" if is_host else "User"
        self.status_bar = ttk.Label(frame, 
                                  text=f"Status: {status_text} | Room: {self.room_id} | IP: {self.public_ip}",
                                  relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Start message receiving thread if client
        if not is_host and self.client:
            receive_thread = threading.Thread(target=self.client.receive_messages, args=(self.display_message,))
            receive_thread.daemon = True
            receive_thread.start()
        elif is_host:
            # Display welcome message for host
            self.display_message(f"[SYSTEM] You are hosting room: {self.room_id}", "system")
            self.display_message(f"[SYSTEM] Your public IP: {self.public_ip}", "system")
            self.display_message("[SYSTEM] Share this IP and room details with others", "system")
            
    def display_message(self, message, tag=None):
        """Display a message in the chat with appropriate formatting"""
        if not tag:
            if message.startswith("[HOST]"):
                tag = "host"
            elif message.startswith("[USER]"):
                tag = "user"
            elif message.startswith("[ERROR]"):
                tag = "error"
            elif message.startswith("[SYSTEM]"):
                tag = "system"
            else:
                tag = ""
                
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n", tag)
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def send_chat_message(self, event=None):
        message = self.message_entry.get().strip()
        if message:
            if self.client:  # Client sending message
                self.client.send_message(message)
                self.display_message(f"[USER] You: {message}", "user")
            elif self.server:  # Host sending message
                self.display_message(f"[HOST] You: {message}", "host")
                self.server.send_host_message(message)
            self.message_entry.delete(0, tk.END)
    
    def start_server(self):
        room_id = self.room_id_entry.get().strip()
        password = self.room_pw_entry.get().strip()
        
        if not room_id or not password:
            messagebox.showerror("Error", "Room ID and password are required")
            return
            
        self.room_id = room_id
        
        # Ask for host name
        host_name = simpledialog.askstring(
            "Host Name", 
            "Enter your display name:", 
            initialvalue="Host",
            parent=self.root
        )
        
        if not host_name:
            host_name = "Host"
        
        try:
            self.server = ChatServer()
            if self.server.start(room_id, password, host_name):
                self.chat_screen(is_host=True)
            else:
                messagebox.showerror("Error", "Failed to start server")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}")
    
    def join_room(self):
        server_ip = self.server_ip_entry.get().strip()
        room_id = self.join_room_id_entry.get().strip()
        password = self.join_room_pw_entry.get().strip()
        
        if not server_ip or not room_id or not password:
            messagebox.showerror("Error", "All fields are required")
            return
            
        self.room_id = room_id
        
        # Ask for user name
        user_name = simpledialog.askstring(
            "User Name", 
            "Enter your display name:", 
            initialvalue="User",
            parent=self.root
        )
        
        if not user_name:
            user_name = "User"
        
        # Show connecting window
        connecting_window = tk.Toplevel(self.root)
        connecting_window.title("Connecting")
        tk.Label(connecting_window, text="Attempting to connect...").pack(pady=20)
        connecting_window.update()
        
        try:
            self.client = ChatClient(server_ip)
            result = self.client.connect(room_id, password, user_name)
            
            if result == "success":
                connecting_window.destroy()
                self.chat_screen(is_host=False)
                self.display_message(f"[SYSTEM] Joined chat room as '{user_name}'", "system")
            elif result == "timeout":
                connecting_window.destroy()
                messagebox.showerror("Error", "Connection timed out. Check the IP and port forwarding.")
            elif result == "refused":
                connecting_window.destroy()
                messagebox.showerror("Error", "Connection refused. Server may not be running.")
            elif result == "auth_fail":
                connecting_window.destroy()
                messagebox.showerror("Error", "Invalid room ID or password.")
            else:
                connecting_window.destroy()
                messagebox.showerror("Error", f"Connection failed: {result}")
        except Exception as e:
            connecting_window.destroy()
            messagebox.showerror("Error", f"Connection failed: {str(e)}")
    
    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def on_closing(self):
        if self.server:
            self.server.stop()
        if self.client:
            self.client.disconnect()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()