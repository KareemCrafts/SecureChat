import socket, json, threading
from crypto_utils import *
from cert_utils import *
from chat_utils import *
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization

SERVER_IP = "192.168.1.17"  # User A's IP
PORT = 5001

print("=" * 60)
print("🔐 USER B - CLIENT")
print("=" * 60)

# RSA + X.509
print("\n🔑 Generating RSA keys and certificate...")
private_key, cert = generate_rsa_cert("UserB")

# Generate RSA key pair for encryption
rsa_private, rsa_public = generate_rsa_keys()

# Connect to server
client = socket.socket()
print(f"\n🌐 Connecting to {SERVER_IP}:{PORT}...")
client.connect((SERVER_IP, PORT))
print("✅ Connected to A")

# Receive certificate
a_cert_bytes = client.recv(2048)
print("✅ Received A certificate")

# Send our certificate
client.send(cert.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
))

# Receive User A's RSA public key
a_rsa_key_data = client.recv(4096)
a_rsa_public = RSA.import_key(a_rsa_key_data)

# Send our RSA public key
client.send(rsa_public.export_key())

# Receive DH parameters (may be encrypted)
encrypted_dh = client.recv(1024)

try:
    # Try to decrypt with RSA
    dh_data_json = rsa_decrypt(rsa_private, encrypted_dh).decode()
    dh_data = json.loads(dh_data_json)
    print("✅ Received encrypted DH parameters")
except:
    # Fallback: plain text
    dh_data = json.loads(encrypted_dh.decode())
    print("✅ Received plain DH parameters")

q = dh_data["q"]
alpha = dh_data["alpha"]
a_public = dh_data["public"]

# Generate our DH values
private = dh_generate_private_key()
public = dh_generate_public_key(alpha, private, q)

# Send our public key (try to encrypt)
try:
    public_data = str(public).encode()
    encrypted_public = rsa_encrypt(a_rsa_public, public_data)
    client.send(encrypted_public)
    print("✅ Sent encrypted DH response")
except:
    # Fallback: plain text
    client.send(str(public).encode())
    print("✅ Sent plain DH response")

# Compute shared secret
shared_secret = dh_shared_secret(a_public, private, q)
print(f"🔑 Shared secret: {shared_secret}")

# DES-CFB
des_key = derive_des_key(shared_secret)
iv = client.recv(8)

print(f"🔐 DES Key: {des_key.hex()}")
print("\n" + "=" * 60)
print("💬 ENCRYPTED CHAT STARTED!")
print("=" * 60)

seq_num = 0
last_seq_received = 0

# ---------- Receiving thread ----------
def receive_messages():
    global last_seq_received
    while True:
        try:
            data = client.recv(1024)
            if not data:
                break

            decrypted = des_decrypt(des_key, iv, data)
            parsed = json.loads(decrypted.decode())

            seq = parsed.get("seq", 0)

            # 🔐 Replay attack protection
            if seq <= last_seq_received:
                print("⚠️ Replay attack detected. Message ignored.")
                continue

            last_seq_received = seq
            print(f"\n📥 A[{seq}]: {parsed.get('message', '')}")

        except Exception as e:
            print(f"Receive error: {e}")
            break


# ---------- Sending thread ----------
def send_messages():
    global seq_num
    while True:
        msg = input("B: ")
        seq_num += 1
        message_bytes = create_message("B", msg, seq_num)
        encrypted = des_encrypt(des_key, iv, message_bytes.decode())
        client.send(encrypted)
        save_log("chat_B", encrypted)

# Start threads
threading.Thread(target=receive_messages, daemon=True).start()
threading.Thread(target=send_messages, daemon=True).start()

# Keep main thread alive
while True:
    pass