from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
import os
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
            role TEXT DEFAULT 'user',
            created_at TEXT NOT NULL
        )
    """)

    # Upgrade old database
    columns = conn.execute(
        "PRAGMA table_info(users)"
    ).fetchall()

    if not any(column["name"] == "role" for column in columns):
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN role TEXT DEFAULT 'user'
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

    conn.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            network TEXT NOT NULL,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# =========================
# PASSWORD
# =========================

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def create_token():
    return secrets.token_hex(32)


# =========================
# OWNER ACCOUNT
# =========================

def create_owner_from_environment():

    phone = os.getenv("OWNER_PHONE", "").strip()
    password = os.getenv("OWNER_PASSWORD", "").strip()
    name = os.getenv("OWNER_NAME", "Camal Owner").strip()

    if not phone or not password:
        return

    conn = get_db()

    existing = conn.execute(
        "SELECT id FROM users WHERE phone = ?",
        (phone,)
    ).fetchone()

    if existing:

        conn.execute(
            """
            UPDATE users
            SET role = 'owner',
                name = ?
            WHERE id = ?
            """,
            (name, existing["id"])
        )

    else:

        conn.execute("""
            INSERT INTO users
            (
                name,
                phone,
                password,
                balance,
                token,
                role,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            name,
            phone,
            hash_password(password),
            0,
            None,
            "owner",
            datetime.utcnow().isoformat()
        ))

    conn.commit()
    conn.close()


# =========================
# GET USER
# =========================

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
# OWNER / ADMIN CHECK
# =========================

def require_owner():

    user = get_user()

    if not user:

        return None, (
            jsonify({
                "success": False,
                "message": "Unauthorized"
            }),
            401
        )

    if user["role"] not in ("owner", "admin"):

        return None, (
            jsonify({
                "success": False,
                "message": "Owner/Admin access required"
            }),
            403
        )

    return user, None


# Initialize database
init_db()
create_owner_from_environment()


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
        (
            name,
            phone,
            password,
            balance,
            token,
            role,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        name,
        phone,
        hash_password(password),
        0,
        token,
        "user",
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
            "balance": user["balance"],
            "role": user["role"]
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
            "balance": user["balance"],
            "role": user["role"]
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
# DEVELOPMENT WALLET FUND
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
    except (TypeError, ValueError):
        amount = 0

    if amount <= 0:

        return jsonify({
            "success": False,
            "message": "Invalid amount"
        }), 400

    conn = get_db()

    conn.execute(
        """
        UPDATE users
        SET balance = balance + ?
        WHERE id = ?
        """,
        (amount, user["id"])
    )

    conn.execute("""
        INSERT INTO transactions
        (
            user_id,
            type,
            product,
            phone,
            amount,
            status,
            created_at
        )
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
# PURCHASE
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
    except (TypeError, ValueError):
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

    conn.execute(
        """
        UPDATE users
        SET balance = balance - ?
        WHERE id = ?
        """,
        (amount, user["id"])
    )

    conn.execute("""
        INSERT INTO transactions
        (
            user_id,
            type,
            product,
            phone,
            amount,
            status,
            created_at
        )
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
# USER TRANSACTIONS
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
        SELECT
            id,
            type,
            product,
            phone,
            amount,
            status,
            created_at
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


# =========================================================
# OWNER / ADMIN
# =========================================================

@app.route("/api/admin/me", methods=["GET"])
def admin_me():

    user, error = require_owner()

    if error:
        return error

    return jsonify({
        "success": True,
        "admin": {
            "id": user["id"],
            "name": user["name"],
            "phone": user["phone"],
            "role": user["role"],
            "balance": user["balance"]
        }
    })


# =========================
# ADMIN USERS
# =========================

@app.route("/api/admin/users", methods=["GET"])
def admin_users():

    user, error = require_owner()

    if error:
        return error

    conn = get_db()

    rows = conn.execute("""
        SELECT
            id,
            name,
            phone,
            balance,
            role,
            created_at
        FROM users
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    users = []

    for row in rows:
        users.append(dict(row))

    return jsonify({
        "success": True,
        "users": users
    })


# =========================
# ADMIN CHANGE ROLE
# =========================

@app.route(
    "/api/admin/users/<int:user_id>/role",
    methods=["PUT"]
)
def admin_change_role(user_id):

    user, error = require_owner()

    if error:
        return error

    data = request.get_json() or {}

    role = data.get("role", "").strip().lower()

    if role not in ("user", "admin"):

        return jsonify({
            "success": False,
            "message": "Role must be user or admin"
        }), 400

    if user_id == user["id"] and role != "admin":

        return jsonify({
            "success": False,
            "message": "Owner cannot remove their own owner access"
        }), 400

    conn = get_db()

    target = conn.execute(
        """
        SELECT id, role
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    if not target:

        conn.close()

        return jsonify({
            "success": False,
            "message": "User not found"
        }), 404

    if target["role"] == "owner":

        conn.close()

        return jsonify({
            "success": False,
            "message": "Owner role cannot be changed here"
        }), 403

    conn.execute(
        """
        UPDATE users
        SET role = ?
        WHERE id = ?
        """,
        (role, user_id)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "User role updated"
    })


# =========================
# ADMIN TRANSACTIONS
# =========================

@app.route("/api/admin/transactions", methods=["GET"])
def admin_transactions():

    user, error = require_owner()

    if error:
        return error

    conn = get_db()

    rows = conn.execute("""
        SELECT
            transactions.id,
            transactions.user_id,
            users.name,
            users.phone AS user_phone,
            transactions.type,
            transactions.product,
            transactions.phone,
            transactions.amount,
            transactions.status,
            transactions.created_at
        FROM transactions
        JOIN users
        ON users.id = transactions.user_id
        ORDER BY transactions.id DESC
    """).fetchall()

    conn.close()

    result = []

    for row in rows:
        result.append(dict(row))

    return jsonify({
        "success": True,
        "transactions": result
    })


# =========================
# ADMIN TRANSACTION STATUS
# =========================

@app.route(
    "/api/admin/transactions/<int:transaction_id>/status",
    methods=["PUT"]
)
def admin_transaction_status(transaction_id):

    user, error = require_owner()

    if error:
        return error

    data = request.get_json() or {}

    status = data.get("status", "").strip().lower()

    allowed = (
        "pending",
        "successful",
        "failed",
        "refunded"
    )

    if status not in allowed:

        return jsonify({
            "success": False,
            "message": "Invalid transaction status"
        }), 400

    conn = get_db()

    transaction = conn.execute(
        """
        SELECT id
        FROM transactions
        WHERE id = ?
        """,
        (transaction_id,)
    ).fetchone()

    if not transaction:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Transaction not found"
        }), 404

    conn.execute(
        """
        UPDATE transactions
        SET status = ?
        WHERE id = ?
        """,
        (status, transaction_id)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Transaction status updated"
    })


# =========================
# ADMIN PRODUCTS
# =========================

@app.route("/api/admin/products", methods=["GET"])
def admin_products():

    user, error = require_owner()

    if error:
        return error

    conn = get_db()

    rows = conn.execute("""
        SELECT
            id,
            type,
            network,
            name,
            price,
            active,
            created_at
        FROM products
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return jsonify({
        "success": True,
        "products": [dict(row) for row in rows]
    })


# =========================
# CREATE PRODUCT
# =========================

@app.route("/api/admin/products", methods=["POST"])
def admin_create_product():

    user, error = require_owner()

    if error:
        return error

    data = request.get_json() or {}

    product_type = data.get("type", "").strip().lower()
    network = data.get("network", "").strip()
    name = data.get("name", "").strip()

    try:
        price = float(data.get("price", 0))
    except (TypeError, ValueError):
        price = 0

    if product_type not in (
        "data",
        "airtime",
        "recharge"
    ):

        return jsonify({
            "success": False,
            "message": "Invalid product type"
        }), 400

    if not network or not name or price <= 0:

        return jsonify({
            "success": False,
            "message": "Network, name and valid price are required"
        }), 400

    conn = get_db()

    cursor = conn.execute("""
        INSERT INTO products
        (
            type,
            network,
            name,
            price,
            active,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        product_type,
        network,
        name,
        price,
        1,
        datetime.utcnow().isoformat()
    ))

    conn.commit()

    product_id = cursor.lastrowid

    conn.close()

    return jsonify({
        "success": True,
        "message": "Product created",
        "product_id": product_id
    }), 201


# =========================
# UPDATE PRODUCT
# =========================

@app.route(
    "/api/admin/products/<int:product_id>",
    methods=["PUT"]
)
def admin_update_product(product_id):

    user, error = require_owner()

    if error:
        return error

    data = request.get_json() or {}

    name = data.get("name")
    network = data.get("network")
    price = data.get("price")
    active = data.get("active")

    conn = get_db()

    product = conn.execute(
        """
        SELECT *
        FROM products
        WHERE id = ?
        """,
        (product_id,)
    ).fetchone()

    if not product:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Product not found"
        }), 404

    new_name = (
        product["name"]
        if name is None
        else str(name).strip()
    )

    new_network = (
        product["network"]
        if network is None
        else str(network).strip()
    )

    try:
        new_price = (
            product["price"]
            if price is None
            else float(price)
        )
    except (TypeError, ValueError):

        conn.close()

        return jsonify({
            "success": False,
            "message": "Invalid price"
        }), 400

    try:
        new_active = (
            product["active"]
            if active is None
            else int(bool(active))
        )
    except (TypeError, ValueError):

        new_active = product["active"]

    if not new_name or not new_network or new_price <= 0:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Invalid product data"
        }), 400

    conn.execute("""
        UPDATE products
        SET
            name = ?,
            network = ?,
            price = ?,
            active = ?
        WHERE id = ?
    """, (
        new_name,
        new_network,
        new_price,
        new_active,
        product_id
    ))

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Product updated"
    })


# =========================
# DELETE PRODUCT
# =========================

@app.route(
    "/api/admin/products/<int:product_id>",
    methods=["DELETE"]
)
def admin_delete_product(product_id):

    user, error = require_owner()

    if error:
        return error

    conn = get_db()

    product = conn.execute(
        """
        SELECT id
        FROM products
        WHERE id = ?
        """,
        (product_id,)
    ).fetchone()

    if not product:

        conn.close()

        return jsonify({
            "success": False,
            "message": "Product not found"
        }), 404

    conn.execute(
        """
        DELETE FROM products
        WHERE id = ?
        """,
        (product_id,)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "message": "Product deleted"
    })


# =========================
# PUBLIC PRODUCTS
# =========================

@app.route("/api/products", methods=["GET"])
def public_products():

    conn = get_db()

    rows = conn.execute("""
        SELECT
            id,
            type,
            network,
            name,
            price
        FROM products
        WHERE active = 1
        ORDER BY id ASC
    """).fetchall()

    conn.close()

    return jsonify({
        "success": True,
        "products": [dict(row) for row in rows]
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
