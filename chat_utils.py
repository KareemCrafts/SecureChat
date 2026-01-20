import json
import time
import os

# ---------- MESSAGE STRUCTURE ----------
def create_message(sender, msg, seq_num):
    return json.dumps({
        "sender": sender,
        "timestamp": int(time.time()),
        "seq": seq_num,
        "message": msg
    }).encode()  # convert to bytes for socket

def parse_message(msg_bytes):
    return json.loads(msg_bytes.decode())

# ---------- LOGGING ----------
def save_log(filename, data_bytes):
    os.makedirs("logs", exist_ok=True)
    with open(f"logs/{filename}.log", "ab") as f:  # append encrypted
        f.write(data_bytes + b"\n")
