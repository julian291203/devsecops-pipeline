
"""Modul backend autentikasi Flask dengan antarmuka web interaktif."""

import sqlite3
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "devsecops-secret-key-change-this"


def init_db():
    """Inisialisasi database dan membuat akun awal."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    cursor.execute(
        "SELECT username FROM users WHERE username = ?", ("admin",)
    )

    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users VALUES (?, ?)",
            ("admin", generate_password_hash("supersecret"))
        )

    conn.commit()
    conn.close()


@app.route("/", methods=["GET", "POST"])
def index():
    """Halaman login."""
    message = None
    status_class = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT username, password FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session["username"] = user[0]
            return redirect(url_for("dashboard"))

        message = "Login Gagal! Kredensial tidak valid."
        status_class = "danger"

    return render_template(
        "index.html", message=message, status_class=status_class
    )


# ROUTE BARU 1: REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    """Registrasi akun pengguna baru."""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username dan password wajib diisi.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password minimal 8 karakter.", "danger")
            return redirect(url_for("register"))

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )
            conn.commit()
            flash("Registrasi berhasil! Silakan login.", "success")
            return redirect(url_for("index"))

        except sqlite3.IntegrityError:
            flash("Username sudah digunakan.", "danger")

        finally:
            conn.close()

    return render_template("register.html")


# ROUTE BARU 2: DASHBOARD
@app.route("/dashboard")
def dashboard():
    """Dashboard khusus pengguna yang sudah login."""

    if "username" not in session:
        return redirect(url_for("index"))

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


@app.route("/logout")
def logout():
    """Mengakhiri sesi pengguna."""
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)  # nosemgrep
