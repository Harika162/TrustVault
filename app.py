import os
import hashlib
import uuid
import html
import hmac
from functools import wraps
import secrets

from flask import (
    Flask, render_template_string, request, redirect,
    url_for, flash, send_from_directory, abort, session, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


# =========================================================
# TRUSTVAULT - FLASK CONFIGURATION
# =========================================================

app = Flask(__name__)
# Set TRUSTVAULT_SECRET_KEY in your environment before deploying.
# The local fallback is only for development; use a long random secret in production.
app.config["SECRET_KEY"] = os.environ.get(
    "TRUSTVAULT_SECRET_KEY",
    "dev-only-change-this-secret-before-deployment"
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Enable this only when serving the app over HTTPS:
app.config["SESSION_COOKIE_SECURE"] = os.environ.get(
    "TRUSTVAULT_HTTPS", "0"
) == "1"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///trustvault.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

UPLOAD_FOLDER = os.path.join(app.root_path, "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "txt", "png", "jpg", "jpeg"}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# =========================================================
# MODELS
# =========================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="employee", nullable=False)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(500), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=db.func.current_timestamp())


# Basic CSRF protection for all state-changing form submissions.
# Each HTML form that uses POST must include the hidden csrf_token field.
@app.before_request
def protect_post_requests():
    if request.method == "POST":
        # React calls the same-origin /api endpoints through the Vite proxy.
        # Keep CSRF protection on traditional HTML forms; API routes use
        # the session cookie (SameSite=Lax) and JSON responses instead.
        if request.path.startswith("/api/"):
            return

        submitted_token = request.form.get("csrf_token", "")
        saved_token = session.get("csrf_token", "")
        if not saved_token or not submitted_token or not hmac.compare_digest(
            submitted_token, saved_token
        ):
            abort(400, description="Invalid or missing CSRF token.")


@app.context_processor
def inject_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return {"csrf_token": token}


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    )
    return response


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


# =========================================================
# HELPERS / ACCESS CONTROL
# =========================================================

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def is_admin():
    return current_user.is_authenticated and current_user.role == "admin"


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not is_admin():
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def can_access_document(document):
    return is_admin() or document.owner_id == current_user.id


def calculate_sha256(file_path):
    """Calculate SHA-256 incrementally, without loading the whole file into RAM."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def document_is_intact(document):
    """Return False if the stored file is missing or its SHA-256 differs."""
    path = os.path.join(app.config["UPLOAD_FOLDER"], safe_file_path(document))
    if not os.path.isfile(path):
        return False
    try:
        return calculate_sha256(path) == document.sha256_hash
    except OSError:
        return False


def safe_file_path(document):
    # filepath is generated by this app; basename prevents path traversal.
    return os.path.basename(document.filepath)


# =========================================================
# SHARED PAGE / PROFESSIONAL RESPONSIVE UI
# =========================================================

BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title or "TrustVault" }}</title>
    <style>
        :root { --bg:#0b1220; --panel:#111c2f; --panel2:#18263d;
                --text:#e8eef8; --muted:#9fb0c8; --accent:#39d6bd;
                --line:#2b3b55; --danger:#ff7272; }
        * { box-sizing:border-box; }
        body { margin:0; min-height:100vh; font-family:Inter,Arial,sans-serif;
               color:var(--text); background:radial-gradient(ellipse at top,#172944,var(--bg) 65%); }
        .nav { display:flex; justify-content:space-between; align-items:center;
               gap:16px; padding:18px max(5vw,20px); border-bottom:1px solid var(--line); }
        .brand { color:var(--text); font-size:22px; font-weight:800; text-decoration:none; }
        .brand span { color:var(--accent); }
        .navlinks { display:flex; flex-wrap:wrap; gap:16px; align-items:center; }
        a { color:var(--accent); text-decoration:none; }
        a:hover { text-decoration:underline; }
        .navlinks a { color:var(--muted); }
        .wrap { width:min(1100px,92%); margin:38px auto; }
        .panel { background:rgba(17,28,47,.96); border:1px solid var(--line);
                 border-radius:18px; padding:28px; box-shadow:0 18px 45px #0003; }
        h1 { margin:0 0 10px; font-size:clamp(25px,4vw,34px); }
        h2 { margin-top:0; }
        p { color:var(--muted); line-height:1.6; }
        .sub { color:var(--muted); margin:6px 0 22px; }
        .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:16px; margin:22px 0; }
        .stat { padding:20px; border-radius:14px; background:var(--panel2); border:1px solid var(--line); }
        .stat strong { display:block; font-size:27px; margin-top:8px; color:var(--accent); }
        .btn { display:inline-flex; align-items:center; justify-content:center; gap:8px;
               padding:11px 16px; border:0; border-radius:9px; background:var(--accent);
               color:#08201d; font-weight:750; cursor:pointer; text-decoration:none; }
        .btn:hover { text-decoration:none; filter:brightness(1.05); }
        .btn.secondary { background:#263853; color:var(--text); border:1px solid #3b506d; }
        .btn.danger { background:#4b202b; color:#ffdede; border:1px solid #843a49; }
        .btn.small { padding:8px 11px; font-size:13px; }
        form { margin:0; }
        .form { max-width:500px; display:grid; gap:13px; }
        label { color:var(--muted); font-size:14px; }
        input, select { width:100%; padding:12px 13px; margin-top:6px; border:1px solid #3b506d;
                        border-radius:9px; background:#0b1527; color:var(--text); }
        input[type=file] { padding:10px; }
        .flash { padding:12px 15px; border:1px solid #356b66; background:#14332f;
                 color:#b7fff2; border-radius:10px; margin-bottom:15px; }
        .table-wrap { overflow-x:auto; margin-top:18px; }
        table { width:100%; border-collapse:collapse; min-width:680px; }
        th,td { text-align:left; padding:13px 12px; border-bottom:1px solid var(--line); vertical-align:middle; }
        th { color:#b9c9df; font-size:13px; text-transform:uppercase; letter-spacing:.04em; }
        td { color:#e2eaf5; font-size:14px; }
        .actions { display:flex; flex-wrap:wrap; gap:8px; }
        .badge { display:inline-block; padding:5px 9px; border-radius:99px; font-size:12px; font-weight:700; }
        .good { background:#123c34; color:#8af2d9; }
        .bad { background:#4a222a; color:#ffc0c0; }
        .neutral { background:#263853; color:#c9d7eb; }
        .search { max-width:360px; margin:16px 0 0; }
        .footer { color:#6f829e; text-align:center; padding:25px; font-size:12px; }
        .empty { text-align:center; padding:30px; color:var(--muted); }
        @media(max-width:650px) {
            .nav { align-items:flex-start; flex-direction:column; }
            .panel { padding:20px; }
            .wrap { margin:22px auto; }
        }
    </style>
</head>
<body>
    <nav class="nav">
        <a class="brand" href="{{ url_for('home') }}">Trust<span>Vault</span></a>
        <div class="navlinks">
            {% if current_user.is_authenticated %}
                <a href="{{ url_for('dashboard') }}">Dashboard</a>
                <a href="{{ url_for('documents') }}">Documents</a>
                {% if current_user.role == "admin" %}
                    <a href="{{ url_for('admin_users') }}">User Management</a>
                {% endif %}
                <a href="{{ url_for('logout') }}">Logout</a>
            {% else %}
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('register') }}">Register</a>
            {% endif %}
        </div>
    </nav>

    <main class="wrap">
        {% with messages = get_flashed_messages() %}
            {% for message in messages %}
                <div class="flash">{{ message }}</div>
            {% endfor %}
        {% endwith %}
        <section class="panel">
            {{ content|safe }}
        </section>
    </main>
    <div class="footer">TrustVault · Secure Document Sharing</div>
</body>
</html>
"""


def page(content, title="TrustVault"):
    # Content pages are embedded as trusted HTML; replace the CSRF placeholder
    # before inserting the page into the shared template.
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    content = content.replace(
        "{{ csrf_token }}", html.escape(token, quote=True)
    )
    return render_template_string(
        BASE_TEMPLATE,
        content=content,
        title=title
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    content = """
        <h1>Secure document sharing, made simple.</h1>
        <p class="sub">Upload, preview, download and verify your documents in one secure workspace.</p>
        <div class="grid">
            <div class="stat">Document storage<strong>Protected</strong></div>
            <div class="stat">Integrity checks<strong>SHA-256</strong></div>
            <div class="stat">Access control<strong>Role-based</strong></div>
        </div>
        <a class="btn" href="/register">Create account</a>
        <a class="btn secondary" href="/login">Login</a>
    """
    return page(content, "Welcome | TrustVault")


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or len(password) < 8:
            flash("Please enter your name and email, and use a password with at least 8 characters.")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("This email is already registered.")
            return redirect(url_for("register"))

        user = User(
            name=name,
            email=email,
            password=generate_password_hash(password),
            role="employee"
        )
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully. Please log in.")
        return redirect(url_for("login"))

    content = """
        <h1>Create account</h1>
        <p class="sub">Create your TrustVault employee account.</p>
        <form class="form" method="POST">\n            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label>Full name<input name="name" required maxlength="100"></label>
            <label>Email<input name="email" type="email" required maxlength="120"></label>
            <label>Password<input name="password" type="password" required minlength="8"></label>
            <button class="btn" type="submit">Register</button>
        </form>
        <p>Already registered? <a href="/login">Login here</a></p>
    """
    return page(content, "Register | TrustVault")


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Welcome back!")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")
        return redirect(url_for("login"))

    content = """
        <h1>Login</h1>
        <p class="sub">Access your secure workspace.</p>
        <form class="form" method="POST">\n            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label>Email<input name="email" type="email" required></label>
            <label>Password<input name="password" type="password" required></label>
            <button class="btn" type="submit">Login</button>
        </form>
        <p>New to TrustVault? <a href="/register">Create an account</a></p>
    """
    return page(content, "Login | TrustVault")


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():
    if is_admin():
        user_count = User.query.count()
        document_count = Document.query.count()
        content = f"""
            <h1>Admin Dashboard</h1>
            <p class="sub">Welcome, {html.escape(current_user.name)}. Manage users and documents.</p>
            <div class="grid">
                <div class="stat">Registered users<strong>{user_count}</strong></div>
                <div class="stat">Stored documents<strong>{document_count}</strong></div>
                <div class="stat">Account role<strong>Administrator</strong></div>
            </div>
            <a class="btn" href="/upload">Upload document</a>
            <a class="btn secondary" href="/documents">View documents</a>
            <a class="btn secondary" href="/admin/users">Manage users</a>
        """
    else:
        own_docs = Document.query.filter_by(owner_id=current_user.id).count()
        content = f"""
            <h1>Employee Dashboard</h1>
            <p class="sub">Welcome, {html.escape(current_user.name)}. Your secure workspace is ready.</p>
            <div class="grid">
                <div class="stat">Your documents<strong>{own_docs}</strong></div>
                <div class="stat">Account role<strong>Employee</strong></div>
            </div>
            <a class="btn" href="/upload">Upload document</a>
            <a class="btn secondary" href="/documents">View my documents</a>
        """
    return page(content, "Dashboard | TrustVault")


# =========================================================
# DOCUMENT UPLOAD
# =========================================================

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_document():
    if request.method == "POST":
        file = request.files.get("document")

        if not file or not file.filename:
            flash("Please select a document.")
            return redirect(url_for("upload_document"))

        if not allowed_file(file.filename):
            flash("Unsupported file type. Allowed: PDF, DOC, DOCX, TXT, PNG, JPG, JPEG.")
            return redirect(url_for("upload_document"))

        original_filename = secure_filename(file.filename)
        if not original_filename:
            flash("Invalid filename.")
            return redirect(url_for("upload_document"))

        unique_filename = f"{uuid.uuid4().hex}_{original_filename}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)

        try:
            file.save(filepath)
            sha256_hash = calculate_sha256(filepath)

            document = Document(
                filename=original_filename,
                filepath=unique_filename,
                owner_id=current_user.id,
                sha256_hash=sha256_hash
            )
            db.session.add(document)
            db.session.commit()
        except Exception:
            db.session.rollback()
            if os.path.exists(filepath):
                os.remove(filepath)
            app.logger.exception("Document upload failed")
            flash("Upload failed. Please try again.")
            return redirect(url_for("upload_document"))

        flash("Document uploaded successfully. SHA-256 integrity hash saved.")
        return redirect(url_for("documents"))

    content = """
        <h1>Upload document</h1>
        <p class="sub">Maximum file size: 16 MB. Allowed formats: PDF, DOC, DOCX, TXT, PNG, JPG, JPEG.</p>
        <form class="form" method="POST" enctype="multipart/form-data">\n            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label>Select a file<input type="file" name="document" accept=".pdf,.doc,.docx,.txt,.png,.jpg,.jpeg" required></label>
            <button class="btn" type="submit">Upload document</button>
        </form>
        <p><a href="/dashboard">Back to dashboard</a></p>
    """
    return page(content, "Upload | TrustVault")


# =========================================================
# DOCUMENT LIST + SEARCH
# =========================================================

@app.route("/documents")
@login_required
def documents():
    search_term = request.args.get("q", "").strip()

    query = Document.query
    if not is_admin():
        query = query.filter_by(owner_id=current_user.id)

    if search_term:
        query = query.filter(Document.filename.ilike(f"%{search_term}%"))

    document_list = query.order_by(Document.uploaded_at.desc()).all()

    csrf_token = session.get("csrf_token", "")
    rows = ""
    for doc in document_list:
        intact = document_is_intact(doc)
        status = (
            '<span class="badge good">Integrity OK</span>'
            if intact else
            '<span class="badge bad">Tampered / Missing</span>'
        )
        filename = html.escape(doc.filename)
        owner = db.session.get(User, doc.owner_id)
        owner_name = html.escape(owner.name if owner else "Unknown")
        owner_cell = f"<td>{owner_name}</td>" if is_admin() else ""

        rows += f"""
            <tr>
                <td>{filename}</td>
                {owner_cell}
                <td>{doc.uploaded_at}</td>
                <td>{status}</td>
                <td>
                    <div class="actions">
                        <a class="btn small secondary" target="_blank" href="/view/{doc.id}">View</a>
                        <a class="btn small" href="/download/{doc.id}">Download</a>
                        <a class="btn small secondary" href="/verify/{doc.id}">Verify</a>
                        <form method="POST" action="/delete/{doc.id}"
                              onsubmit="return confirm('Delete this document permanently?');">
                            <input type="hidden" name="csrf_token" value="{csrf_token}">
                            <button class="btn small danger" type="submit">Delete</button>
                        </form>
                    </div>
                </td>
            </tr>
        """

    owner_heading = "<th>Owner</th>" if is_admin() else ""
    if not rows:
        rows = f'<tr><td colspan="{5 if is_admin() else 4}" class="empty">No documents found.</td></tr>'

    content = f"""
        <h1>{"All documents" if is_admin() else "My documents"}</h1>
        <p class="sub">Preview, download, verify integrity, or delete your files.</p>
        <form class="search" method="GET">
            <input name="q" value="{html.escape(search_term, quote=True)}" placeholder="Search by filename...">
        </form>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>File name</th>
                        {owner_heading}
                        <th>Uploaded at</th>
                        <th>Integrity</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        <br>
        <a class="btn" href="/upload">Upload another document</a>
        <a class="btn secondary" href="/dashboard">Dashboard</a>
    """
    return page(content, "Documents | TrustVault")


# =========================================================
# DOCUMENT INTEGRITY VERIFICATION
# =========================================================

@app.route("/verify/<int:document_id>")
@login_required
def verify_document(document_id):
    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    if not can_access_document(document):
        abort(403)

    intact = document_is_intact(document)
    filename = html.escape(document.filename)

    if intact:
        status = """
            <span class="badge good">Verified - file is unchanged</span>
        """
        description = "The SHA-256 hash of the stored file matches the hash saved at upload time."
    else:
        status = """
            <span class="badge bad">Verification failed</span>
        """
        description = "The file is missing or its contents differ from the hash saved at upload time."

    content = f"""
        <h1>Document integrity check</h1>
        <p class="sub">File: <strong>{filename}</strong></p>
        <p>{status}</p>
        <p>{description}</p>
        <h3>Stored SHA-256</h3>
        <p style="overflow-wrap:anywhere">{html.escape(document.sha256_hash)}</p>
        <a class="btn secondary" href="/documents">Back to documents</a>
    """
    return page(content, "Integrity verification | TrustVault")


# =========================================================
# DOCUMENT VIEW / INLINE PREVIEW
# =========================================================

@app.route("/view/<int:document_id>")
@app.route("/api/documents/<int:document_id>/view")
@login_required
def view_document(document_id):
    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    if not can_access_document(document):
        abort(403)

    if not document_is_intact(document):
        abort(409, description="Integrity check failed. This document cannot be previewed.")

    extension = document.filename.rsplit(".", 1)[-1].lower()

    # Browser inline preview is generally supported for PDF and image files.
    # Other formats may be downloaded or may require an external application.
    if extension not in {"pdf", "png", "jpg", "jpeg", "txt"}:
        flash("This file type may not preview in your browser. Try Download.")
        return redirect(url_for("documents"))

    return send_from_directory(
        directory=app.config["UPLOAD_FOLDER"],
        path=safe_file_path(document),
        as_attachment=False,
        download_name=document.filename
    )


# =========================================================
# DOCUMENT DOWNLOAD
# =========================================================

@app.route("/download/<int:document_id>")
@app.route("/api/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    if not can_access_document(document):
        abort(403)

    if not document_is_intact(document):
        abort(409, description="Integrity check failed. Download blocked.")

    return send_from_directory(
        directory=app.config["UPLOAD_FOLDER"],
        path=safe_file_path(document),
        as_attachment=True,
        download_name=document.filename
    )


# =========================================================
# DELETE DOCUMENT
# =========================================================

@app.route("/delete/<int:document_id>", methods=["POST"])
@login_required
def delete_document(document_id):
    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    if not can_access_document(document):
        abort(403)

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        safe_file_path(document)
    )

    try:
        if os.path.isfile(file_path):
            os.remove(file_path)

        db.session.delete(document)
        db.session.commit()
        flash("Document deleted successfully.")
    except OSError:
        db.session.rollback()
        app.logger.exception("Could not delete document file")
        flash("Could not delete the file. Please check the uploads folder.")
    except Exception:
        db.session.rollback()
        app.logger.exception("Document deletion failed")
        flash("Document deletion failed.")

    return redirect(url_for("documents"))


# =========================================================
# ADMIN USER MANAGEMENT
# =========================================================

@app.route("/admin/users")
@admin_required
def admin_users():
    users = User.query.order_by(User.id.asc()).all()

    csrf_token = session.get("csrf_token", "")
    rows = ""
    for user in users:
        role_options = ""
        for role in ("employee", "admin"):
            selected = "selected" if user.role == role else ""
            role_options += f'<option value="{role}" {selected}>{role.title()}</option>'

        rows += f"""
            <tr>
                <td>{user.id}</td>
                <td>{html.escape(user.name)}</td>
                <td>{html.escape(user.email)}</td>
                <td>
                    <form class="actions" method="POST" action="/admin/users/{user.id}/role">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <select name="role">{role_options}</select>
                        <button class="btn small" type="submit">Save role</button>
                    </form>
                </td>
                <td>{Document.query.filter_by(owner_id=user.id).count()}</td>
            </tr>
        """

    content = f"""
        <h1>User management</h1>
        <p class="sub">View registered accounts and assign employee or administrator roles.</p>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>ID</th><th>Name</th><th>Email</th><th>Role</th><th>Documents</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        <br><a class="btn secondary" href="/dashboard">Back to dashboard</a>
    """
    return page(content, "User Management | TrustVault")


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@admin_required
def update_user_role(user_id):
    user = db.session.get(User, user_id)

    if user is None:
        abort(404)

    new_role = request.form.get("role", "").strip().lower()

    if new_role not in {"admin", "employee"}:
        flash("Invalid role selected.")
        return redirect(url_for("admin_users"))

    # Prevent the currently logged-in admin from accidentally removing
    # their own admin access.
    if user.id == current_user.id and new_role != "admin":
        flash("You cannot remove your own administrator role.")
        return redirect(url_for("admin_users"))

    user.role = new_role
    db.session.commit()

    flash(f"Role updated for {user.name}.")
    return redirect(url_for("admin_users"))


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("home"))



# =========================================================
# JSON API FOR THE REACT FRONTEND
# =========================================================

def api_user_payload(user):
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
    }


def api_error(message, status=400):
    return jsonify({"success": False, "message": message}), status


def api_login_required():
    if not current_user.is_authenticated:
        return api_error("Please log in to continue.", 401)
    return None


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or request.form
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not name or not email or len(password) < 8:
        return api_error("Name and email are required; password must be at least 8 characters.")

    if User.query.filter_by(email=email).first():
        return api_error("This email is already registered.", 409)

    user = User(
        name=name,
        email=email,
        password=generate_password_hash(password),
        role="employee",
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Account created successfully. Please log in.",
        "user": api_user_payload(user),
    }), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or request.form
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return api_error("Invalid email or password.", 401)

    login_user(user)
    return jsonify({
        "success": True,
        "message": "Login successful.",
        "user": api_user_payload(user),
    })


@app.route("/api/me", methods=["GET"])
def api_me():
    if not current_user.is_authenticated:
        return api_error("Not logged in.", 401)
    return jsonify({"success": True, "user": api_user_payload(current_user)})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    if not current_user.is_authenticated:
        return jsonify({"success": True, "message": "Already logged out."})
    logout_user()
    return jsonify({"success": True, "message": "Logged out successfully."})


@app.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    auth_error = api_login_required()
    if auth_error:
        return auth_error

    if is_admin():
        return jsonify({
            "success": True,
            "user": api_user_payload(current_user),
            "stats": {
                "users": User.query.count(),
                "documents": Document.query.count(),
            },
        })

    return jsonify({
        "success": True,
        "user": api_user_payload(current_user),
        "stats": {
            "documents": Document.query.filter_by(owner_id=current_user.id).count(),
        },
    })


@app.route("/api/documents", methods=["GET", "POST"])
def api_documents():
    auth_error = api_login_required()
    if auth_error:
        return auth_error

    if request.method == "POST":
        uploaded_file = request.files.get("document") or request.files.get("file")
        if not uploaded_file or not uploaded_file.filename:
            return api_error("Please select a document.")

        if not allowed_file(uploaded_file.filename):
            return api_error("Unsupported file type. Allowed: PDF, DOC, DOCX, TXT, PNG, JPG, JPEG.")

        original_filename = secure_filename(uploaded_file.filename)
        if not original_filename:
            return api_error("Invalid filename.")

        unique_filename = f"{uuid.uuid4().hex}_{original_filename}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)

        try:
            uploaded_file.save(filepath)
            sha256_hash = calculate_sha256(filepath)
            document = Document(
                filename=original_filename,
                filepath=unique_filename,
                owner_id=current_user.id,
                sha256_hash=sha256_hash,
            )
            db.session.add(document)
            db.session.commit()
        except Exception:
            db.session.rollback()
            if os.path.exists(filepath):
                os.remove(filepath)
            app.logger.exception("API document upload failed")
            return api_error("Upload failed. Please try again.", 500)

        return jsonify({
            "success": True,
            "message": "Document uploaded successfully.",
            "document": {
                "id": document.id,
                "filename": document.filename,
                "sha256": document.sha256_hash,
                "uploaded_at": document.uploaded_at.isoformat() if document.uploaded_at else None,
            },
        }), 201

    search_term = request.args.get("q", "").strip()
    query = Document.query
    if not is_admin():
        query = query.filter_by(owner_id=current_user.id)
    if search_term:
        query = query.filter(Document.filename.ilike(f"%{search_term}%"))

    documents = query.order_by(Document.uploaded_at.desc()).all()
    return jsonify({
        "success": True,
        "documents": [{
            "id": doc.id,
            "filename": doc.filename,
            "owner_id": doc.owner_id,
            "owner_name": (
                db.session.get(User, doc.owner_id).name
                if db.session.get(User, doc.owner_id) else "Unknown"
            ),
            "uploaded_at": doc.uploaded_at.isoformat() if doc.uploaded_at else None,
            "sha256": doc.sha256_hash,
            "integrity_ok": document_is_intact(doc),
            "view_url": f"/api/documents/{doc.id}/view",
            "download_url": f"/api/documents/{doc.id}/download",
            "verify_url": f"/api/documents/{doc.id}/verify",
        } for doc in documents],
    })


@app.route("/api/documents/<int:document_id>/verify", methods=["GET"])
def api_verify_document(document_id):
    auth_error = api_login_required()
    if auth_error:
        return auth_error

    document = db.session.get(Document, document_id)
    if document is None:
        return api_error("Document not found.", 404)
    if not can_access_document(document):
        return api_error("You do not have permission to access this document.", 403)

    intact = document_is_intact(document)
    return jsonify({
        "success": True,
        "document_id": document.id,
        "filename": document.filename,
        "integrity_ok": intact,
        "status": "Verified - file is unchanged" if intact else "Verification failed",
        "sha256": document.sha256_hash,
    })


@app.route("/api/documents/<int:document_id>", methods=["DELETE"])
def api_delete_document(document_id):
    auth_error = api_login_required()
    if auth_error:
        return auth_error

    document = db.session.get(Document, document_id)
    if document is None:
        return api_error("Document not found.", 404)
    if not can_access_document(document):
        return api_error("You do not have permission to delete this document.", 403)

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_file_path(document))
    try:
        if os.path.isfile(file_path):
            os.remove(file_path)
        db.session.delete(document)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("API document deletion failed")
        return api_error("Document deletion failed.", 500)

    return jsonify({"success": True, "message": "Document deleted successfully."})


@app.route("/api/admin/users", methods=["GET"])
def api_admin_users():
    auth_error = api_login_required()
    if auth_error:
        return auth_error
    if not is_admin():
        return api_error("Administrator access required.", 403)

    users = User.query.order_by(User.id.asc()).all()
    return jsonify({
        "success": True,
        "users": [{
            **api_user_payload(user),
            "document_count": Document.query.filter_by(owner_id=user.id).count(),
        } for user in users],
    })


@app.route("/api/admin/users/<int:user_id>/role", methods=["PATCH"])
def api_update_user_role(user_id):
    auth_error = api_login_required()
    if auth_error:
        return auth_error
    if not is_admin():
        return api_error("Administrator access required.", 403)

    user = db.session.get(User, user_id)
    if user is None:
        return api_error("User not found.", 404)

    data = request.get_json(silent=True) or {}
    new_role = str(data.get("role", "")).strip().lower()
    if new_role not in {"admin", "employee"}:
        return api_error("Role must be 'admin' or 'employee'.")
    if user.id == current_user.id and new_role != "admin":
        return api_error("You cannot remove your own administrator role.", 400)

    user.role = new_role
    db.session.commit()
    return jsonify({
        "success": True,
        "message": "Role updated.",
        "user": api_user_payload(user),
    })


# The React app can use these JSON endpoints while the original HTML routes
# above continue to work for direct browser access.

# =========================================================
# DATABASE INITIALIZATION
# =========================================================

with app.app_context():
    db.create_all()


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
