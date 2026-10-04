from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
from datetime import datetime

app = Flask(__name__)
CORS(app)

DATABASE = "camal.db"


# =========================
# DATABASE
# =========================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            balance REAL DEFAULT 0,
            token TEXT,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            product TEXT NOT NULL,
            phone TEXT,
            amount REAL NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


init_db()


# =========================
# HELPERS
# =========================

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def create_token():
    return secrets.token_hex(32)


def get_user():
    token = request.headers.get("Authorization")

    if not token:
        return None

    if token.startswith("Bearer "):
        token = token[7:]

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE token = ?",
        (token,)
    ).fetchone()

    conn.close()

    return user


# =========================
# HOME
# =========================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "success": True,
        "message": "Camal Data Backend is running"
    })


# =========================
# REGISTER
# =========================

@app.route("/api/register", methods=["POST"])
def register():

    data = request.get_json() or {}

    name = data.get("name", "").strip()
    phone = data.get("phone", "").strip()
    password = data.get("password", "").strip()

    if not name or not phone or not password:
        return jsonify({
            "success": False,
            "message": "All fields are required"
        }), 400

    if len(password) < 6:
        return jsonify({
            "success": False,
            "message": "Password must be at least 6 characters"
        }), 400

    conn = get_db()

    existing = conn.execute(
        "SELECT id FROM users WHERE phone = ?",
        (phone,)
    ).fetchone()

    if existing:
        conn.close()

        return jsonify({
            "success": False,
            "message": "Phone number already registered"
        }), 409

    token = create_token()

    conn.execute("""
        INSERT INTO users
        (name, phone, password, balance, token, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        name,
        phone,
        hash_password(password),
        0,
        token,
        datetime.utcnow().isoformat()
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Account created successfully",
        "token": token
    }), 201


# =========================
# LOGIN
# =========================

@app.route("/api/login", methods=["POST"])
def login():

    data = request.get_json() or {}

    phone = data.get("phone", "").strip()
    password = data.get("password", "").strip()

    if not phone or not password:
        return jsonify({
            "success": False,
            "message": "Phone and password are required"
        }), 400

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE phone = ?",
        (phone,)
    ).fetchone()

    if not user:
        conn.close()

        return jsonify({
            "success": False,
            "message": "Invalid phone number or password"
        }), 401

    if user["password"] != hash_password(password):
        conn.close()

        return jsonify({
            "success": False,
            "message": "Invalid phone number or password"
        }), 401

    token = create_token()

    conn.execute(
        "UPDATE users SET token = ? WHERE id = ?",
        (token, user["id"])
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "phone": user["phone"],
            "balance": user["balance"]
        }
    })


# =========================
# PROFILE
# =========================

@app.route("/api/me", methods=["GET"])
def profile():

    user = get_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Unauthorized"
        }), 401

    return jsonify({
        "success": True,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "phone": user["phone"],
            "balance": user["balance"]
        }
    })


# =========================
# WALLET
# =========================

@app.route("/api/wallet", methods=["GET"])
def wallet():

    user = get_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Unauthorized"
        }), 401

    return jsonify({
        "success": True,
        "balance": user["balance"]
    })


# =========================
# FUND WALLET
# DEVELOPMENT ONLY
# =========================

@app.route("/api/wallet/fund", methods=["POST"])
def fund_wallet():

    user = get_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Unauthorized"
        }), 401

    data = request.get_json() or {}

    try:
        amount = float(data.get("amount", 0))
    except:
        amount = 0

    if amount <= 0:
        return jsonify({
            "success": False,
            "message": "Invalid amount"
        }), 400

    conn = get_db()

    conn.execute(
        "UPDATE users SET balance = balance + ? WHERE id = ?",
        (amount, user["id"])
    )

    conn.execute("""
        INSERT INTO transactions
        (user_id, type, product, phone, amount, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        user["id"],
        "funding",
        "Wallet Funding",
        user["phone"],
        amount,
        "successful",
        datetime.utcnow().isoformat()
    ))

    conn.commit()

    new_user = conn.execute(
        "SELECT balance FROM users WHERE id = ?",
        (user["id"],)
    ).fetchone()

    conn.close()

    return jsonify({
        "success": True,
        "message": "Wallet funded",
        "balance": new_user["balance"]
    })


# =========================
# BUY DATA
# =========================

@app.route("/api/data/buy", methods=["POST"])
def buy_data():

    return process_purchase("data")


# =========================
# BUY AIRTIME
# =========================

@app.route("/api/airtime/buy", methods=["POST"])
def buy_airtime():

    return process_purchase("airtime")


# =========================
# BUY RECHARGE
# =========================

@app.route("/api/recharge/buy", methods=["POST"])
def buy_recharge():

    return process_purchase("recharge")


# =========================
# PURCHASE FUNCTION
# =========================

def process_purchase(purchase_type):

    user = get_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Unauthorized"
        }), 401

    data = request.get_json() or {}

    product = data.get("product", "").strip()
    phone = data.get("phone", "").strip()

    try:
        amount = float(data.get("amount", 0))
    except:
        amount = 0

    if not product or not phone or amount <= 0:
        return jsonify({
            "success": False,
            "message": "Invalid purchase details"
        }), 400

    if user["balance"] < amount:
        return jsonify({
            "success": False,
            "message": "Insufficient wallet balance"
        }), 400

    conn = get_db()

    # Deduct wallet
    conn.execute(
        "UPDATE users SET balance = balance - ? WHERE id = ?",
        (amount, user["id"])
    )

    # Create transaction
    conn.execute("""
        INSERT INTO transactions
        (user_id, type, product, phone, amount, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        user["id"],
        purchase_type,
        product,
        phone,
        amount,
        "pending",
        datetime.utcnow().isoformat()
    ))

    conn.commit()

    new_user = conn.execute(
        "SELECT balance FROM users WHERE id = ?",
        (user["id"],)
    ).fetchone()

    conn.close()

    return jsonify({
        "success": True,
        "message": "Order created successfully",
        "status": "pending",
        "product": product,
        "phone": phone,
        "amount": amount,
        "balance": new_user["balance"]
    })


# =========================
# TRANSACTIONS
# =========================

@app.route("/api/transactions", methods=["GET"])
def transactions():

    user = get_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Unauthorized"
        }), 401

    conn = get_db()

    rows = conn.execute("""
        SELECT id, type, product, phone, amount, status, created_at
        FROM transactions
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user["id"],)).fetchall()

    conn.close()

    result = []

    for row in rows:
        result.append({
            "id": row["id"],
            "type": row["type"],
            "product": row["product"],
            "phone": row["phone"],
            "amount": row["amount"],
            "status": row["status"],
            "date": row["created_at"]
        })

    return jsonify({
        "success": True,
        "transactions": result
    })


# =========================
# LOGOUT
# =========================

@app.route("/api/logout", methods=["POST"])
def logout():

    user = get_user()

    if not user:
        return jsonify({
            "success": False,
            "message": "Unauthorized"
        }), 401

    conn = get_db()

    conn.execute(
        "UPDATE users SET token = NULL WHERE id = ?",
        (user["id"],)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Logged out successfully"
    })


# =========================
# RUN
# =========================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
)
