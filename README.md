Chat Application Documentation
(With Tailscale VPN Support)

📌 Overview
A secure, peer-to-peer chat application that works over LAN or the internet without port forwarding using Tailscale VPN. Features include:
✅ End-to-end encrypted messaging
✅ Room-based chat with passwords
✅ No port forwarding required (when using Tailscale)
✅ Cross-platform (Windows, macOS, Linux)

🚀 Features
Core Functionality
Create/join password-protected chat rooms

Real-time messaging with username display

Automatic IP detection (local/public/Tailscale)

Security
Fernet encryption for all messages

Password-protected rooms

Optional Tailscale VPN for secure connections

Networking Options
Traditional (Port Forwarding)

Share your public IP + port 12345

Requires router configuration

Tailscale VPN (Recommended)

No port forwarding needed

Works behind NAT/firewalls

Encrypted peer-to-peer tunnels

⚙️ Setup
1. Prerequisites
Python 3.6+

Required packages:

bash
pip install tkinter cryptography requests pyinstaller
(Optional) Tailscale for VPN mode

2. Running the Application
bash
python chat_app.py
3. Building an Executable
bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon=chat_icon.ico chat_app.py
(Output: dist/chat_app.exe)

🖥️ Usage
1. Hosting a Room
Click "Create Room"

Enter:

Room ID

Password

Your display name

Share:

Tailscale IP (if using VPN) OR

Public IP (if using port forwarding)

2. Joining a Room
Click "Join Room"

Enter:

Host's IP (Tailscale or public)

Room ID & password

Your display name

🔧 Technical Details
Code Structure
File/Class	Purpose
ChatServer	Handles incoming connections, room management, and message broadcasting
ChatClient	Connects to rooms, sends/receives encrypted messages
ChatApp (GUI)	Tkinter-based interface for user interaction
Encryption
Uses Fernet (AES-128) with unique keys per session

Keys are exchanged securely upon connection

Networking Modes
Mode	Requirements	Pros	Cons
Tailscale	Tailscale installed on both ends	No port forwarding, secure	Requires Tailscale setup
Public IP	Port 12345 forwarded	No extra software	Requires router configuration
📂 Repository Structure
text
chat-app/
├── chat_app.py          # Main application code
├── chat_icon.ico       # Application icon
├── requirements.txt    # Python dependencies
├── README.md           # This documentation
└── dist/               # (Generated) Contains executable
⚠️ Troubleshooting
Common Issues
"Connection Failed"

Check if:

Tailscale is running (if using VPN)

Port 12345 is forwarded (if using public IP)

Firewall allows Python/chat_app.exe

Tailscale Not Working

Run tailscale up --reset in terminal

Ensure all peers are in the same Tailscale network

PyInstaller Errors

Try:

bash
pyinstaller --onefile --add-data "chat_icon.ico;." chat_app.py
📜 License
MIT License - Free for personal and commercial use

📬 Contact
For bugs/suggestions, open a GitHub issue or contact:
nag2001.tss@gmail.com | SubhaNAG2001

🎉 Enjoy Secure Chatting!
No more port forwarding headaches! 🚀

*(Documentation last updated: 2023-10-15)*

🔗 Links
Tailscale Official Site

PyInstaller Documentation

Fernet Encryption Docs

