# Secure Group Chat System with Forward Secrecy

## 📋 Project Description
A secure real-time chat system implementing modern cryptographic protocols for end-to-end encrypted communication. Developed for the CCY3002 Introduction to Cryptography course at AAST-CCIT.

## 🎯 Key Features
- **Mutual Authentication**: X.509 self-signed certificates containing RSA public keys
- **Forward Secrecy**: Diffie-Hellman key exchange for session establishment
- **Message Confidentiality**: DES in CFB mode for encrypted messaging
- **Replay Protection**: Sequence numbers and timestamps in all messages
- **Encrypted Logging**: Chat histories saved as encrypted files

## 🚀 Quick Start
## Screenshot
<img width="2343" height="1365" alt="Screenshot 2025-12-21 134925" src="https://github.com/user-attachments/assets/b4e4cec1-b6e7-42a1-bc2f-ee1caaaea8e1" />


### Installation
```bash
# Install dependencies
pip install -r requirements.txt

