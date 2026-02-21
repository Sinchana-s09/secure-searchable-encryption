from flask import Flask, request, jsonify
from db import get_connection, create_tables
from crypto_utils import encrypt_text, decrypt_text, generate_token
import re
from flask import render_template


app = Flask(__name__)

create_tables()


def extract_keywords(text):
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", "", text)
    words = text.split()

    stopwords = {"in", "on", "at", "the", "is", "and", "a", "an", "of", "to", "for"}
    keywords = [w for w in words if w not in stopwords]

    return list(set(keywords))


def generate_ngrams(word, n=3):
    word = word.lower()
    if len(word) < n:
        return [word]

    return [word[i:i+n] for i in range(len(word) - n + 1)]

@app.route("/")
def homes():
    return render_template("index.html")

@app.route("/")
def home():
    return jsonify({
        "message": "🏆 Secure Searchable Encryption API Running (AES-GCM + HMAC + N-Grams)"
    })

@app.route("/addRecord", methods=["POST"])
def add_record():
    data = request.json
    plain_text = data.get("text")

    if not plain_text:
        return jsonify({"error": "Text is required"}), 400

    encrypted_data = encrypt_text(plain_text)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO records(encrypted_text, nonce, tag)
        VALUES (?, ?, ?)
    """, (encrypted_data["ciphertext"], encrypted_data["nonce"], encrypted_data["tag"]))

    record_id = cursor.lastrowid

    keywords = extract_keywords(plain_text)

    all_tokens = set()

    for word in keywords:
        ngrams = generate_ngrams(word, n=3)  
        for ng in ngrams:
            token = generate_token(ng)
            all_tokens.add(token)

    for token in all_tokens:
        cursor.execute("""
            INSERT INTO search_index(record_id, token)
            VALUES (?, ?)
        """, (record_id, token))

    conn.commit()
    conn.close()

    return jsonify({
        "message": "✅ Record stored securely (AES-GCM encrypted + HMAC searchable tokens)",
        "record_id": record_id,
        "keywords": keywords,
        "token_count": len(all_tokens)
    })


@app.route("/search", methods=["POST"])
def search_record():
    data = request.json
    query = data.get("query")

    if not query:
        return jsonify({"error": "Query is required"}), 400

    query = query.lower().strip()

    query_ngrams = generate_ngrams(query, n=3)

    query_tokens = [generate_token(ng) for ng in query_ngrams]

    conn = get_connection()
    cursor = conn.cursor()

    record_ids = set()

    for token in query_tokens:
        cursor.execute("SELECT record_id FROM search_index WHERE token = ?", (token,))
        rows = cursor.fetchall()
        for row in rows:
            record_ids.add(row["record_id"])

    if not record_ids:
        conn.close()
        return jsonify({
            "message": "❌ No matches found",
            "results": []
        })

    results = []
    for rid in record_ids:
        cursor.execute("SELECT * FROM records WHERE id = ?", (rid,))
        rec = cursor.fetchone()

        decrypted = decrypt_text(rec["encrypted_text"], rec["nonce"], rec["tag"])

        results.append({
            "record_id": rid,
            "decrypted_text": decrypted
        })

    conn.close()

    return jsonify({
        "message": "✅ Matches found",
        "query": query,
        "ngrams_used": query_ngrams,
        "matched_count": len(results),
        "results": results
    })


@app.route("/viewEncrypted", methods=["GET"])
def view_encrypted():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM records")
    rows = cursor.fetchall()

    conn.close()

    return jsonify({
        "encrypted_records": [dict(row) for row in rows]
    })


if __name__ == "__main__":
    app.run(debug=True)