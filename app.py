
import os
import sqlite3

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "devsecops-secret-key-change-this"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

csrf = CSRFProtect(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "users.db")


# ==========================================
# DATABASE
# ==========================================

def get_db_connection():
    """Membuat koneksi database SQLite."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Inisialisasi database dan akun admin awal."""

    conn = get_db_connection()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        admin = conn.execute(
            "SELECT username FROM users WHERE username = ?",
            ("admin",)
        ).fetchone()

        if admin is None:
            conn.execute(
                """
                INSERT INTO users (username, password)
                VALUES (?, ?)
                """,
                (
                    "admin",
                    generate_password_hash("supersecret")
                )
            )

        conn.commit()

    finally:
        conn.close()


# ==========================================
# CSRF ERROR HANDLING
# ==========================================

@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    """Menangani kegagalan validasi CSRF."""

    app.logger.warning(
        "CSRF validation failed: %s",
        error.description
    )

    return render_template(
        "error.html",
        error_code=400,
        error_message=error.description
    ), 400


# ==========================================
# LOGIN
# ==========================================

@app.route("/", methods=["GET", "POST"])
def index():
    """Halaman login pengguna."""

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        if not username or not password:
            flash(
                "Username dan password wajib diisi.",
                "danger"
            )

            return redirect(url_for("index"))

        conn = get_db_connection()

        try:
            user = conn.execute(
                """
                SELECT username, password
                FROM users
                WHERE username = ?
                """,
                (username,)
            ).fetchone()

        finally:
            conn.close()

        if user and check_password_hash(
            user["password"],
            password
        ):
            session.clear()
            session["username"] = user["username"]

            return redirect(url_for("dashboard"))

        flash(
            "Login gagal! Username atau password salah.",
            "danger"
        )

        return redirect(url_for("index"))

    return render_template("index.html")


# ==========================================
# REGISTER
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():
    """Registrasi akun pengguna baru."""

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        if not username or not password:
            flash(
                "Username dan password wajib diisi.",
                "danger"
            )

            return redirect(url_for("register"))

        if len(username) > 50:
            flash(
                "Username maksimal 50 karakter.",
                "danger"
            )

            return redirect(url_for("register"))

        if len(password) < 8:
            flash(
                "Password minimal 8 karakter.",
                "danger"
            )

            return redirect(url_for("register"))

        conn = get_db_connection()

        try:
            conn.execute(
                """
                INSERT INTO users (username, password)
                VALUES (?, ?)
                """,
                (
                    username,
                    generate_password_hash(password)
                )
            )

            conn.commit()

            flash(
                "Registrasi berhasil! Silakan login.",
                "success"
            )

            return redirect(url_for("index"))

        except sqlite3.IntegrityError:
            flash(
                "Username sudah digunakan.",
                "danger"
            )

        finally:
            conn.close()

    return render_template("register.html")


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Dashboard pengguna yang sudah login."""

    if "username" not in session:
        flash(
            "Silakan login terlebih dahulu.",
            "danger"
        )

        return redirect(url_for("index"))

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout", methods=["GET"])
def logout():
    """Mengakhiri sesi pengguna."""

    session.clear()

    flash(
        "Kamu berhasil logout.",
        "success"
    )

    return redirect(url_for("index"))


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

init_db()


# ==========================================
# APPLICATION ENTRY POINT
# ==========================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
