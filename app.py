from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import bcrypt
import jwt
import datetime
from functools import wraps
from crypto_utils import encrypt_text, decrypt_text, generate_token, generate_ngrams

app = Flask(__name__)
CORS(app)

app.config["SECRET_KEY"] = "super_jwt_secret"

DATABASE = "secure.db"

from flask import render_template

@app.route("/")
def auth_page():
    return render_template("auth.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")
# ----------------- DATABASE SETUP -----------------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password BLOB
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ciphertext TEXT,
        nonce TEXT,
        tag TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS search_index (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        record_id INTEGER,
        token TEXT
    )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_token ON search_index(token)")
    conn.commit()
    conn.close()


init_db()

# ----------------- AUTH LAYER -----------------


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return jsonify({"message": "Token missing"}), 403

        try:
            token = auth_header.split(" ")[1]  # Remove 'Bearer'
            jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except Exception as e:
            return jsonify({"message": "Invalid or expired token"}), 403

        return f(*args, **kwargs)

    return decorated

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = data["password"]

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                   (username, hashed_pw))
    conn.commit()
    conn.close()

    return jsonify({"message": "User registered successfully"})


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode(), user["password"]):
        token = jwt.encode({
            "user": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config["SECRET_KEY"], algorithm="HS256")

        return jsonify({"token": token})

    return jsonify({"message": "Invalid credentials"}), 401


# ----------------- ENCRYPTION LAYER -----------------


@app.route("/AddRecord", methods=["POST"])
@token_required
def add_record():
    data = request.json
    text = data["text"]

    encrypted = encrypt_text(text)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("INSERT INTO records (ciphertext, nonce, tag) VALUES (?, ?, ?)",
                   (encrypted["ciphertext"], encrypted["nonce"], encrypted["tag"]))

    record_id = cursor.lastrowid

    ngrams = generate_ngrams(text)

    for gram in ngrams:
        token = generate_token(gram)
        cursor.execute("INSERT INTO search_index (record_id, token) VALUES (?, ?)",
                       (record_id, token))

    conn.commit()
    conn.close()

    return jsonify({"message": "Record stored securely"})


@app.route("/search", methods=["POST"])
@token_required
def search():
    data = request.json
    text = data["text"]

    ngrams = generate_ngrams(text)
    conn = get_db()
    cursor = conn.cursor()

    matched_ids = set()

    for gram in ngrams:
        token = generate_token(gram)
        cursor.execute("SELECT record_id FROM search_index WHERE token=?", (token,))
        rows = cursor.fetchall()
        for row in rows:
            matched_ids.add(row["record_id"])

    results = []

    for record_id in matched_ids:
        cursor.execute("SELECT * FROM records WHERE id=?", (record_id,))
        record = cursor.fetchone()

        decrypted = decrypt_text(record["ciphertext"], record["nonce"], record["tag"])

        results.append({
            "record_id": record_id,
            "decrypted_text": decrypted
        })

    conn.close()

    return jsonify({"results": results})


if __name__ == "__main__":
    app.run(debug=True)