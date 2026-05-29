"""
Password Manager - Full Featured
Uses: Flask, cryptography library
Encryption: AES-256-GCM (passwords), AES-256-CBC (file), PBKDF2-HMAC-SHA256 (user passwords)
"""

from flask import Flask, request, jsonify, session, send_from_directory
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import os, csv, base64, json, secrets, string, io, hashlib

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

# ─── Crypto Helpers ────────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256: derives a 32-byte AES key from a password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def hash_password(password: str) -> str:
    """Hash a user's master password for storage (salt + PBKDF2)."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    return base64.b64encode(salt + key).decode()

def verify_password(password: str, stored: str) -> bool:
    decoded = base64.b64decode(stored.encode())
    salt, stored_key = decoded[:16], decoded[16:]
    return derive_key(password, salt) == stored_key

def encrypt_password_entry(plaintext: str, key: bytes) -> str:
    """AES-256-GCM encryption for individual password entries."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def decrypt_password_entry(ciphertext_b64: str, key: bytes) -> str:
    """AES-256-GCM decryption for individual password entries."""
    data = base64.b64decode(ciphertext_b64.encode())
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode()

def encrypt_file(filepath: str, key: bytes):
    """AES-256-CBC file encryption (used on logout/close)."""
    if not os.path.exists(filepath):
        return
    with open(filepath, 'rb') as f:
        plaintext = f.read()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    with open(filepath + '.enc', 'wb') as f:
        f.write(iv + ct)
    os.remove(filepath)

def decrypt_file(filepath_enc: str, key: bytes):
    """AES-256-CBC file decryption (used on login)."""
    if not os.path.exists(filepath_enc):
        return
    with open(filepath_enc, 'rb') as f:
        data = f.read()
    iv, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    plain_path = filepath_enc[:-4]  # remove .enc
    with open(plain_path, 'wb') as f:
        f.write(plaintext)
    os.remove(filepath_enc)

def get_file_key() -> bytes:
    """Derive a stable file encryption key from the user's master password."""
    pwd = session.get('master_password', '')
    salt = session.get('username', 'default').encode()
    salt = salt.ljust(16, b'0')[:16]
    return derive_key(pwd, salt)

def get_entry_key() -> bytes:
    """Derive a stable entry encryption key (different from file key)."""
    pwd = session.get('master_password', '') + '_entries'
    salt = session.get('username', 'default').encode()
    salt = salt.ljust(16, b'x')[:16]
    return derive_key(pwd, salt)

# ─── Data File Helpers ─────────────────────────────────────────────────────────

USERS_FILE = os.path.join(DATA_DIR, "users.json")

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE) as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

def get_csv_path(username):
    return os.path.join(DATA_DIR, f"{username}_passwords.csv")

def get_enc_path(username):
    return get_csv_path(username) + '.enc'

def ensure_csv(username):
    path = get_csv_path(username)
    enc_path = get_enc_path(username)
    # Decrypt if encrypted version exists
    if os.path.exists(enc_path):
        decrypt_file(enc_path, get_file_key())
    # Create if doesn't exist
    if not os.path.exists(path):
        with open(path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Title', 'EncryptedPassword', 'URL', 'Notes'])

def read_entries(username):
    path = get_csv_path(username)
    if not os.path.exists(path):
        return []
    with open(path, newline='') as f:
        return list(csv.DictReader(f))

def write_entries(username, entries):
    path = get_csv_path(username)
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['Title','EncryptedPassword','URL','Notes'])
        writer.writeheader()
        writer.writerows(entries)

# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify(error="Username and password required"), 400
    users = load_users()
    if username in users:
        return jsonify(error="Username already exists"), 400
    users[username] = hash_password(password)
    save_users(users)
    return jsonify(ok=True)

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    users = load_users()
    if username not in users or not verify_password(password, users[username]):
        return jsonify(error="Invalid credentials"), 401
    session['username'] = username
    session['master_password'] = password
    ensure_csv(username)
    return jsonify(ok=True)

@app.route('/api/logout', methods=['POST'])
def logout():
    username = session.get('username')
    if username:
        csv_path = get_csv_path(username)
        if os.path.exists(csv_path):
            encrypt_file(csv_path, get_file_key())
    session.clear()
    return jsonify(ok=True)

@app.route('/api/entries', methods=['GET'])
def list_entries():
    if 'username' not in session:
        return jsonify(error="Not logged in"), 401
    entries = read_entries(session['username'])
    # Return entries without decrypting passwords
    safe = [{'Title': e['Title'], 'URL': e['URL'], 'Notes': e['Notes']} for e in entries]
    return jsonify(entries=safe)

@app.route('/api/entries', methods=['POST'])
def add_entry():
    if 'username' not in session:
        return jsonify(error="Not logged in"), 401
    data = request.json
    title = data.get('title', '').strip()
    password = data.get('password', '')
    url = data.get('url', '')
    notes = data.get('notes', '')
    if not title or not password:
        return jsonify(error="Title and password required"), 400
    entries = read_entries(session['username'])
    if any(e['Title'].lower() == title.lower() for e in entries):
        return jsonify(error="Entry with this title already exists"), 400
    key = get_entry_key()
    enc_pwd = encrypt_password_entry(password, key)
    entries.append({'Title': title, 'EncryptedPassword': enc_pwd, 'URL': url, 'Notes': notes})
    write_entries(session['username'], entries)
    return jsonify(ok=True)

@app.route('/api/entries/<title>', methods=['GET'])
def get_entry(title):
    if 'username' not in session:
        return jsonify(error="Not logged in"), 401
    entries = read_entries(session['username'])
    for e in entries:
        if e['Title'].lower() == title.lower():
            key = get_entry_key()
            pwd = decrypt_password_entry(e['EncryptedPassword'], key)
            return jsonify(entry={**e, 'Password': pwd})
    return jsonify(error="Not found"), 404

@app.route('/api/entries/<title>', methods=['PUT'])
def update_entry(title):
    if 'username' not in session:
        return jsonify(error="Not logged in"), 401
    data = request.json
    entries = read_entries(session['username'])
    key = get_entry_key()
    for e in entries:
        if e['Title'].lower() == title.lower():
            if 'password' in data and data['password']:
                e['EncryptedPassword'] = encrypt_password_entry(data['password'], key)
            if 'url' in data: e['URL'] = data['url']
            if 'notes' in data: e['Notes'] = data['notes']
            write_entries(session['username'], entries)
            return jsonify(ok=True)
    return jsonify(error="Not found"), 404

@app.route('/api/entries/<title>', methods=['DELETE'])
def delete_entry(title):
    if 'username' not in session:
        return jsonify(error="Not logged in"), 401
    entries = read_entries(session['username'])
    new_entries = [e for e in entries if e['Title'].lower() != title.lower()]
    if len(new_entries) == len(entries):
        return jsonify(error="Not found"), 404
    write_entries(session['username'], new_entries)
    return jsonify(ok=True)

@app.route('/api/generate-password', methods=['GET'])
def generate_password():
    length = int(request.args.get('length', 16))
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    pwd = ''.join(secrets.choice(chars) for _ in range(length))
    return jsonify(password=pwd)

@app.route('/api/search', methods=['GET'])
def search():
    if 'username' not in session:
        return jsonify(error="Not logged in"), 401
    query = request.args.get('q', '').lower()
    entries = read_entries(session['username'])
    results = [
        {'Title': e['Title'], 'URL': e['URL'], 'Notes': e['Notes']}
        for e in entries if query in e['Title'].lower()
    ]
    return jsonify(entries=results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
