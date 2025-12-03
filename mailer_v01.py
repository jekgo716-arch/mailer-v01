import os
import random
import time
import base64
import requests
import dns.resolver
from typing import Optional, Tuple
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from google.oauth2 import service_account
from googleapiclient.discovery import build
import google.auth.transport.requests
import hashlib
import email
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import datetime
import re

# ============================================================
# KONFIGURASI & KONSTANTA
# ============================================================

DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.txt")
TARGETS_FILE = os.path.join(DATA_DIR, "targets.txt")
PROXIES_FILE = os.path.join(DATA_DIR, "proxies.txt")
HTML_TEMPLATE_FILE = os.path.join(DATA_DIR, "template.html")
DKIM_SELECTOR = "spamtools"  # ganti dengan selector yang sesuai
DKIM_PRIVATE_KEY_FILE = os.path.join(DATA_DIR, "dkim.pem")  # Path ke private key DKIM
DKIM_DOMAIN = "example.com"  # Ganti dengan domain pengirim
SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify"
]

SERVICE_KEY = "service_key.json"
LOG_FILE = "simulation.log"  # Define the log file name

# ============================================================
# LOG COLOR
# ============================================================

def log(msg: str, level: str = "INFO", log_to_file: bool = True) -> None:
    colors = {
        "INFO": "\033[97m",  # white/grey
        "OK":   "\033[92m",  # green
        "ERR":  "\033[91m",  # red
        "WARN": "\033[93m"   # yellow
    }
    reset = "\033[0m"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} [{level}] {msg}"
    print(f"{colors.get(level,'')}{log_message}{reset}")

    if log_to_file:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_message + "\n")

def log_vertical(items: dict, level: str = "INFO", log_to_file: bool = True) -> None:
    colors = {
        "INFO": "\033[97m",
        "OK":   "\033[92m",
        "ERR":  "\033[91m",
        "WARN": "\033[93m"
    }
    reset = "\033[0m"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} [{level}]\n"
    for k, v in items.items():
        log_message += f"  {k}: {v}\n"

    print(colors.get(level, ""))
    for k, v in items.items():
        print(f"{k}: {v}")
    print(reset)

    if log_to_file:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_message + "\n")

# ============================================================
# UTIL FILE LOADER
# ============================================================

def load_lines(path: str) -> list[str]:
    if not os.path.exists(path):
        log(f"File tidak ditemukan: {path}", "ERR")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f.read().splitlines() if line.strip()]

def get_public_ip() -> str:
    try:
        return requests.get("https://api.ipify.org").text
    except Exception as e:
        return f"Gagal ambil IP publik: {e}"

def load_users(path: str) -> list[Tuple[str, str, str]]:
    lines = load_lines(path)
    users = []
    for line in lines:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 3:
            users.append((parts[0], parts[1], parts[2]))
        else:
            log(f"Baris users invalid, dilewati: {line}", "WARN")
    return users

def load_template(path: str) -> str:
    if not os.path.exists(path):
        log(f"Template tidak ditemukan: {path}", "ERR")
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def load_ua_list(path: str) -> list[str]:
    if not os.path.exists(path):
        log(f"File UA list tidak ditemukan: {path}", "ERR")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f.read().splitlines() if line.strip()]

def load_subject_list(path: str) -> list[str]:
    if not os.path.exists(path):
        log(f"File subject list tidak ditemukan: {path}", "ERR")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f.read().splitlines() if line.strip()]

def load_dkim_private_key(path: str) -> Optional[rsa.RSAPrivateKey]:
    """Loads the DKIM private key from a file."""
    if not os.path.exists(path):
        log(f"DKIM private key file not found: {path}", "ERR")
        return None
    try:
        with open(path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        return private_key
    except Exception as e:
        log(f"Error loading DKIM private key: {e}", "ERR")
        return None

# ============================================================
# LOAD DATA
# ============================================================

USERS = load_users(USERS_FILE)
TARGETS = load_lines(TARGETS_FILE)
PROXIES = load_lines(PROXIES_FILE)
HTML_TEMPLATE = load_template(HTML_TEMPLATE_FILE)
UA_LIST = load_ua_list(os.path.join(DATA_DIR, "ua_list.txt"))
SUBJECTS = load_subject_list(os.path.join(DATA_DIR, "subject_list.txt"))
DKIM_PRIVATE_KEY = load_dkim_private_key(DKIM_PRIVATE_KEY_FILE)

try:
    CREDS = service_account.Credentials.from_service_account_file(
        SERVICE_KEY,
        scopes=SCOPES
    )
except Exception as e:
    CREDS = None
    log(f"Gagal memuat service account: {e}", "ERR")

# ============================================================
# ROTATOR & UTIL
# ============================================================

def pick_sender() -> Tuple[str, str, str]:
    return random.choice(USERS)

def pick_ua() -> str:
    return random.choice(UA_LIST) if UA_LIST else "Default-UA"

def pick_proxy() -> Optional[str]:
    return random.choice(PROXIES) if PROXIES else None

def pick_subject() -> str:
    return random.choice(SUBJECTS) if SUBJECTS else "Default Subject"

# ============================================================
# PROXY-INTEGRATED SERVICE BUILDER
# ============================================================

def build_service(sender_email: str, proxy_str: Optional[str] = None):
    if CREDS is None:
        raise RuntimeError("Service account credentials belum tersedia")
    if proxy_str:
        os.environ["HTTP_PROXY"] = proxy_str
        os.environ["HTTPS_PROXY"] = proxy_str
    delegated_creds = CREDS.with_subject(sender_email)
    return build("gmail", "v1", credentials=delegated_creds)

# ============================================================
# DKIM SIGNATURE
# ============================================================

def generate_dkim_signature(msg: email.message.Message, private_key: rsa.RSAPrivateKey, dkim_selector: str, dkim_domain: str) -> str:
    """Generates a DKIM signature for the given email message."""

    # Canonicalize the header fields
    header_fields = msg.as_string(unixfrom=False, maxheaderlen=0).split('\n\n')[0] + '\n'
    header_fields = header_fields.replace('\r\n', '\n')
    header_fields = header_fields.encode('utf-8')
    header_hash = hashlib.sha256(header_fields).digest()
    header_hash_b64 = base64.b64encode(header_hash).decode('utf-8')

    # Canonicalize the body
    body = msg.get_payload(decode=False)
    if isinstance(body, str):
        body = body.encode('utf-8')
    body_hash = hashlib.sha256(body).digest()
    body_hash_b64 = base64.b64encode(body_hash).decode('utf-8')

    # Construct the DKIM signed data string
    signed_data = f"v=1; a=rsa-sha256; c=relaxed/relaxed; d={dkim_domain}; s={dkim_selector};\n"
    signed_data += f"h=from:to:subject:date:message-id;\n"  # Sesuaikan dengan header yang ingin ditandatangani
    signed_data += f"bh={body_hash_b64};\n"
    signed_data += f"b="

    # Sign the data
    signer = private_key.signer(padding.PKCS1v15(), hashes.SHA256())
    signer.update(signed_data.encode('utf-8'))
    signature = signer.finalize()
    signature_b64 = base64.b64encode(signature).decode('utf-8')

    return signature_b64

# ============================================================
# EMAIL SENDER
# ============================================================

def send_email(user: Tuple[str, str, str], target: str, proxy: Optional[str], dkim_private_key: Optional[rsa.RSAPrivateKey], dkim_selector: str, dkim_domain: str, max_retries: int = 3) -> bool:
    sender_email, sender_name, sender_title = user
    subject = pick_subject()
    ua = pick_ua()

    log(f"Attempting to send email to {target} from {sender_email}...", "INFO") # Added log

    html_body = HTML_TEMPLATE.replace("{{name}}", sender_name)
    msg = MIMEMultipart("alternative")
    msg["From"] = f"{sender_name} "
    msg["To"] = target
    msg["Subject"] = subject
    msg["X-mailer"] = "Python/Email"
    msg["X-Client-UA"] = ua
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid()


    signature = f"Best regards,{sender_name}{sender_title}"
    msg.attach(MIMEText(html_body + signature, "html"))

    # Tambahkan DKIM signature jika private key tersedia
    if dkim_private_key:
        dkim_signature = generate_dkim_signature(msg, dkim_private_key, dkim_selector, dkim_domain)
        dkim_header = f'v=1; a=rsa-sha256; c=relaxed/relaxed; d={dkim_domain}; s={dkim_selector}; h=from:to:subject:date:message-id; bh={base64.b64encode(hashlib.sha256(msg.get_payload(decode=False).encode("utf-8")).digest()).decode("utf-8")}; b={dkim_signature}'
        msg["DKIM-Signature"] = dkim_header

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()

    # coba kirim dengan retry
    for attempt in range(max_retries):
        try:
            log(f"Attempt {attempt+1}/{max_retries} to send to {target}...", "INFO") # Added log
            # kalau proxy gagal, pilih proxy baru
            if attempt > 0:
                proxy = pick_proxy()
                log(f"🔄 Retry {attempt} dengan proxy baru: {proxy}", "WARN")

            service = build_service(sender_email, proxy)
            send = service.users().messages().send(
                userId="me",
                body={"raw": raw}
            ).execute()
            log(f"✔ Sent to {target} | ID {send.get('id')}", "OK")
            return True
        except Exception as e:
            log(f"❌ Error send (attempt {attempt+1}) → {e}", "ERR")
            time.sleep(1.0)  # jeda sebentar sebelum retry

    # kalau semua gagal
    log(f"🚫 Gagal kirim ke {target} setelah {max_retries} percobaan", "ERR")
    return False


# ============================================================
# MAIN (Single Thread + Log Vertikal)
# ============================================================

def main():
    if not USERS or not TARGETS or not HTML_TEMPLATE:
        log("Data belum lengkap. Pastikan users, targets, dan template tersedia.", "ERR")
        return

    if not DKIM_PRIVATE_KEY:
        log("DKIM private key tidak tersedia. DKIM tidak akan digunakan.", "WARN")

    log("🔥 Mailer Started (Single Thread)", "INFO")

    # Log Configuration
    log_vertical({
        "Number of Senders": len(USERS),
        "Number of Targets": len(TARGETS),
        "DKIM Enabled": DKIM_PRIVATE_KEY is not None,
        "Proxy Enabled": len(PROXIES) > 0,
        "User-Agent Rotation": len(UA_LIST) > 0,
        "Subject Rotation": len(SUBJECTS) > 0,
    }, level="INFO")

    for target in TARGETS:
        user = pick_sender()
        proxy = pick_proxy()
        subject = pick_subject()
        ua = pick_ua()

        log_vertical({
            "👤 Sender": user[0],
            "🎯 Target": target,
            "✉️ Subject": subject,
            "🖥️ UA": ua,
            "🔌 Proxy": proxy or "-",
            "🌍 IP": get_public_ip()
        }, level="INFO")

        send_email(user, target, proxy, DKIM_PRIVATE_KEY, DKIM_SELECTOR, DKIM_DOMAIN)

        delay = random.uniform(0.5, 1.0)
        log_vertical({"⏳ Delay": f"{delay:.2f}s"}, level="INFO")
        time.sleep(delay)

    log("✅ Semua email selesai dikirim", "OK")
    analyze_log() # Run the log analyzer

def analyze_log(log_file="simulation.log"):
    total_attempts = 0
    successful_sends = 0
    errors = 0

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            if "Attempt to send" in line:
                total_attempts += 1
            if "Sent to" in line and "Error" not in line:
                successful_sends += 1
            if "Error send" in line:
                errors += 1

    failure_rate = (errors / total_attempts) * 100 if total_attempts else 0

    print("\nSimulation Log Analysis:")
    print(f"  Total Email Sending Attempts: {total_attempts}")
    print(f"  Successful Sends: {successful_sends}")
    print(f"  Errors: {errors}")
    print(f"  Failure Rate: {failure_rate:.2f}%")

if __name__ == "__main__":
    main()# Mailer v.01
