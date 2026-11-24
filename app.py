
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
    "dev-only-change-this-secret-key"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Aktifkan CSRF protection
csrf = CSRFProtect(app)

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "users.db"
)


# ==========================================
# DATABASE
# ==========================================

def get_db_connection():
    """Membuat koneksi database SQLite."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Membuat tabel pengguna dan akun admin awal."""

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

        if not admin:
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
# ERROR HANDLING
# ==========================================

@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    """Menangani kesalahan validasi CSRF."""

    app.logger.warning(
        "CSRF validation failed: %s",
        error.description
    )

    return render_template(
        "error.html",
        error_code=400,
        error_message=error.description
    ), 400


@app.errorhandler(404)
def page_not_found(error):
    return render_template(
        "error.html",
        error_code=404,
        error_message="Halaman yang kamu cari tidak ditemukan."
    ), 404


@app.errorhandler(500)
def internal_server_error(error):
    app.logger.exception("Internal server error")

    return render_template(
        "error.html",
        error_code=500,
        error_message="Terjadi kesalahan pada server."
    ), 500


# ==========================================
# LOGIN
# ==========================================

@app.route("/", methods=["GET", "POST"])
def index():
    """Halaman autentikasi pengguna."""

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

            return render_template("index.html"), 400

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

        return render_template("index.html"), 200

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
# APPLICATION STARTUP
# ==========================================

init_db()


if __name__ == "__main__":

    app.run(host="0.0.0.0",port=5000,)
