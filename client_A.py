import socket, json, threading
from crypto_utils import *
from cert_utils import *
from chat_utils import *
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization

HOST, PORT = "0.0.0.0", 5001

print("=" * 60)
print("🔐 USER A - SERVER")
print("=" * 60)

# RSA + X.509
print("\n🔑 Generating RSA keys and certificate...")
private_key, cert = generate_rsa_cert("UserA")

# Generate RSA key pair for encryption
rsa_private, rsa_public = generate_rsa_keys()

server = socket.socket()
server.bind((HOST, PORT))
server.listen(1)
print(f"\n🌐 Server listening on port {PORT}...")
conn, addr = server.accept()
print(f"✅ Connected to B from {addr}")

# Send certificate
conn.send(cert.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
))

# Receive User B's certificate
b_cert_bytes = conn.recv(2048)
print("✅ Received B certificate")

# Send our RSA public key (for encryption)
conn.send(rsa_public.export_key())

# Receive User B's RSA public key
b_rsa_key_data = conn.recv(4096)
b_rsa_public = RSA.import_key(b_rsa_key_data)

# Diffie-Hellman
print("\n🤝 Performing Diffie-Hellman key exchange...")
q, alpha = dh_generate_params()
private = dh_generate_private_key()
public = dh_generate_public_key(alpha, private, q)

# BONUS B2: Encrypt DH params with RSA
dh_params = {"q": q, "alpha": alpha, "public": public}
try:
    encrypted_dh = rsa_encrypt(b_rsa_public, json.dumps(dh_params).encode())
    conn.send(encrypted_dh)
    print("✅ DH parameters encrypted and sent")
except Exception as e:
    print(f"⚠️  RSA encryption failed, sending plain text: {e}")
    # Fallback: send plain text
    conn.send(json.dumps(dh_params).encode())

# Receive User B's public key (encrypted)
try:
    encrypted_b_public = conn.recv(1024)
    b_public_data = rsa_decrypt(rsa_private, encrypted_b_public)
    b_public = int(b_public_data.decode())
    print("✅ Received encrypted DH response")
except:
    # Fallback: plain text
    b_public = int(conn.recv(1024).decode())
    print("✅ Received plain DH response")

# Compute shared secret
shared_secret = dh_shared_secret(b_public, private, q)
print(f"🔑 Shared secret: {shared_secret}")

# DES-CFB
des_key = derive_des_key(shared_secret)
iv = get_random_bytes(8)
conn.send(iv)

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
            data = conn.recv(1024)
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
            print(f"\n📥 B[{seq}]: {parsed.get('message', '')}")

        except Exception as e:
            print(f"Receive error: {e}")
            break


# ---------- Sending thread ----------
def send_messages():
    global seq_num
    while True:
        msg = input("A: ")
        seq_num += 1
        message_bytes = create_message("A", msg, seq_num)
        encrypted = des_encrypt(des_key, iv, message_bytes.decode())
        conn.send(encrypted)
        save_log("chat_A", encrypted)

# Start threads
threading.Thread(target=receive_messages, daemon=True).start()
threading.Thread(target=send_messages, daemon=True).start()

# Keep main thread alive
while True:
    pass