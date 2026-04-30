import os, re, io, base64, secrets, string, uuid, hashlib, hmac
from datetime import datetime, timedelta
from functools import wraps

import jwt, pyotp, qrcode, requests
from flask import Flask, request, jsonify, render_template, redirect, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# ---------------- PRODUCTION CONFIG ----------------
# V49: no secret is hardcoded. Configure these values in Render → Environment.
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-jwt-change-me")
FEDAPAY_PUBLIC_KEY = os.getenv("FEDAPAY_PUBLIC_KEY", "")
FEDAPAY_SECRET_KEY = os.getenv("FEDAPAY_SECRET_KEY", "")
FEDAPAY_WEBHOOK_SECRET = os.getenv("FEDAPAY_WEBHOOK_SECRET", "")
FEDAPAY_ENVIRONMENT = os.getenv("FEDAPAY_ENVIRONMENT") or os.getenv("FEDAPAY_ENV", "sandbox")
FEDAPAY_ENVIRONMENT = FEDAPAY_ENVIRONMENT.lower()
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://securepass-hzaa.onrender.com").rstrip("/")
SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "joelkpeto204@gmail.com")
SUPPORT_PHONE = os.getenv("SUPPORT_PHONE", "99424087")
APP_VERSION = "52"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///securepass_v52.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config.update(SESSION_COOKIE_SECURE=str(APP_BASE_URL).startswith("https://"), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
CORS(app, resources={r"/api/*": {"origins": "*"}, r"/public/*": {"origins": "*"}}, supports_credentials=False)
limiter = Limiter(get_remote_address, app=app, default_limits=[])
db = SQLAlchemy(app)

PLAN_LIMITS = {
    "free": {"monthly_generations": 10, "extension": False, "api": False, "audit": False, "vault": 10, "team": False, "price_usd": 0, "amount_xof": 0},
    "basic": {"monthly_generations": 50, "extension": False, "api": False, "audit": False, "vault": 50, "team": False, "price_usd": 5, "amount_xof": 3000},
    "pro": {"monthly_generations": None, "extension": True, "api": True, "audit": True, "vault": None, "team": False, "price_usd": 20, "amount_xof": 12000},
    "enterprise": {"monthly_generations": None, "extension": True, "api": True, "audit": True, "vault": None, "team": True, "price_usd": 50, "amount_xof": 30000},
}

# ---------------- MODELS ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), default="user")  # super_admin, org_admin, employee, user
    plan = db.Column(db.String(30), default="free")
    premium_until = db.Column(db.DateTime, nullable=True)
    twofa_secret = db.Column(db.String(64), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    blocked_until = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    browser_integration = db.Column(db.Boolean, default=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    api_key_hash = db.Column(db.String(128), nullable=True)
    master_password_hash = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    owner_id = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class GenerationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    month = db.Column(db.String(7), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Vault(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    organization_id = db.Column(db.Integer, nullable=True)
    site = db.Column(db.String(200), nullable=False)
    login = db.Column(db.String(200), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
    salt = db.Column(db.LargeBinary, nullable=False)
    source = db.Column(db.String(30), default="manual")  # manual, browser
    strength_score = db.Column(db.Integer, nullable=True)
    last_audited_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SharedVault(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vault_id = db.Column(db.Integer, nullable=False)
    owner_id = db.Column(db.Integer, nullable=False)
    target_user_id = db.Column(db.Integer, nullable=False)
    organization_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    provider = db.Column(db.String(30), default="fedapay")
    transaction_id = db.Column(db.String(100), nullable=True)
    reference = db.Column(db.String(80), unique=True, nullable=False)
    plan = db.Column(db.String(30), nullable=False)
    amount_xof = db.Column(db.Integer, nullable=False)
    amount_usd = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(30), default="pending")
    invoice_number = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    organization_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(255), nullable=False)
    ip = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- HELPERS ----------------
def clean_message(msg, status=400):
    return jsonify({"message": msg}), status

def log_event(action, user=None):
    db.session.add(SecurityLog(user_id=getattr(user, 'id', None), organization_id=getattr(user, 'organization_id', None), action=action, ip=request.remote_addr))
    db.session.commit()

def create_token(user):
    payload = {"user_id": user.id, "exp": datetime.utcnow() + timedelta(hours=12)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def get_user_from_token():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else auth
    if not token:
        return None
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return db.session.get(User, data["user_id"])
    except Exception:
        return None

def token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_user_from_token()
        if not user:
            return clean_message("Veuillez vous connecter", 401)
        check_premium(user)
        request.user = user
        return fn(*args, **kwargs)
    return wrapper

def twofa_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not request.user.is_2fa_enabled:
            return clean_message("Activez d'abord la double authentification", 403)
        return fn(*args, **kwargs)
    return wrapper

def super_admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.user.role != "super_admin":
            return clean_message("Accès refusé", 403)
        return fn(*args, **kwargs)
    return wrapper

def org_admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.user.role != "org_admin":
            return clean_message("Accès réservé à l'administrateur entreprise", 403)
        return fn(*args, **kwargs)
    return wrapper

def effective_plan(user):
    # Les employés Enterprise reçoivent les avantages Pro uniquement si leur organisation est active
    # et si l'administrateur entreprise possède encore un abonnement Enterprise actif.
    if user and user.role == "employee" and user.organization_id:
        org = db.session.get(Organization, user.organization_id)
        if org and org.is_active:
            owner = db.session.get(User, org.owner_id)
            if owner and owner.plan == "enterprise" and owner.premium_until and owner.premium_until >= datetime.utcnow():
                return "pro"
        return "free"
    return getattr(user, "plan", "free") or "free"

def plan_allows(user, feature):
    return PLAN_LIMITS.get(effective_plan(user), PLAN_LIMITS["free"]).get(feature, False)

def extension_auto_master(user):
    raw = f"vault-auto:{user.id}:{user.password_hash}".encode()
    return hmac.new(JWT_SECRET.encode(), raw, hashlib.sha256).hexdigest()

def check_premium(user):
    if user.plan in ["basic", "pro", "enterprise"] and user.premium_until and user.premium_until < datetime.utcnow():
        expired_plan = user.plan
        user.plan = "free"
        user.premium_until = None
        user.browser_integration = False
        if expired_plan == "enterprise" and user.organization_id:
            org = db.session.get(Organization, user.organization_id)
            if org and org.owner_id == user.id:
                org.is_active = False
        db.session.commit()

def password_score(p):
    score = 0
    if len(p) >= 12: score += 30
    if re.search(r"[a-z]", p): score += 15
    if re.search(r"[A-Z]", p): score += 15
    if re.search(r"\d", p): score += 20
    if re.search(r"[^A-Za-z0-9]", p): score += 20
    return min(score, 100)

def generate_password(length=16):
    if length < 12 or length > 64:
        raise ValueError("La longueur doit être entre 12 et 64 caractères")
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?/"
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if password_score(pwd) >= 80:
            return pwd

def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def encrypt_secret(master_password, plaintext):
    salt = os.urandom(16)
    f = Fernet(derive_key(master_password, salt))
    return f.encrypt(plaintext.encode()), salt

def decrypt_secret(master_password, encrypted, salt):
    f = Fernet(derive_key(master_password, salt))
    return f.decrypt(encrypted).decode()

def normalize_site(site):
    site = (site or '').strip().lower()
    site = re.sub(r'^https?://', '', site)
    site = site.split('/')[0]
    return site[:200]

def strong_master_password(master):
    return bool(master and len(master) >= 8)

def valid_email(email):
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email or ""))

def valid_username(username):
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username or ""))

def strong_account_password(password, username='', email=''):
    if not password or len(password) < 12:
        return False, "Le mot de passe doit contenir au moins 12 caractères"
    if not re.search(r"[a-z]", password):
        return False, "Ajoutez au moins une lettre minuscule"
    if not re.search(r"[A-Z]", password):
        return False, "Ajoutez au moins une lettre majuscule"
    if not re.search(r"\d", password):
        return False, "Ajoutez au moins un chiffre"
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Ajoutez au moins un caractère spécial"
    low = password.lower()
    if username and username.lower() in low:
        return False, "Le mot de passe ne doit pas contenir le nom utilisateur"
    local = (email or '').split('@')[0].lower()
    if local and len(local) >= 3 and local in low:
        return False, "Le mot de passe ne doit pas contenir l'adresse email"
    common = ['password','azerty','qwerty','admin','securepass','123456','joel']
    if any(c in low for c in common):
        return False, "Choisissez un mot de passe moins prévisible"
    return True, "Mot de passe acceptable"

def create_invoice(payment, user):
    os.makedirs("invoices", exist_ok=True)
    number = f"SP-{datetime.utcnow().strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"
    path = os.path.join("invoices", f"{number}.pdf")
    c = canvas.Canvas(path, pagesize=A4)
    c.setFont("Helvetica-Bold", 18); c.drawString(50, 790, "SecurePass - Facture")
    c.setFont("Helvetica", 11)
    c.drawString(50, 750, f"Facture: {number}")
    c.drawString(50, 730, f"Client: {user.email}")
    c.drawString(50, 710, f"Plan: {payment.plan.upper()}")
    c.drawString(50, 690, f"Montant: {payment.amount_usd}$")
    c.drawString(50, 670, f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    c.drawString(50, 650, f"Support: {SUPPORT_EMAIL} | {SUPPORT_PHONE}")
    c.showPage(); c.save()
    payment.invoice_number = number
    db.session.commit()
    print(f"[EMAIL DEV] To={user.email} | Facture SecurePass {number}")
    return number

# ---------------- PAGES ----------------
@app.after_request
def headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    # CSP volontairement compatible avec l'application single-page locale
    resp.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https://securepass-hzaa.onrender.com https:"
    return resp

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/securepass-admin-console')
def admin_console():
    return render_template('admin.html')

@app.route('/admin')
def old_admin():
    return clean_message("Page introuvable", 404)

@app.route('/payment-success')
def payment_success():
    return render_template('message.html', title='Paiement reçu', message='Votre paiement a été traité. Retournez sur SecurePass pour vérifier votre abonnement.')

@app.route('/payment-failed')
def payment_failed():
    return render_template('message.html', title='Paiement échoué', message=f'Le paiement n’a pas été validé. Réessayez ou contactez le support : {SUPPORT_EMAIL} / {SUPPORT_PHONE}.')

@app.route('/api/support')
def support_info():
    return jsonify({"email": SUPPORT_EMAIL, "phone": SUPPORT_PHONE, "version": APP_VERSION})

# ---------------- AUTH ----------------
@app.route('/api/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    if not username or not email or not password:
        return clean_message("Veuillez remplir tous les champs", 400)
    if not valid_username(username):
        return clean_message("Nom utilisateur invalide: 3 à 30 caractères, lettres, chiffres, point, tiret ou underscore", 400)
    if not valid_email(email):
        return clean_message("Adresse email invalide", 400)
    ok, msg = strong_account_password(password, username, email)
    if not ok:
        return clean_message(msg, 400)
    if User.query.filter((User.email == email) | (User.username == username)).first():
        return clean_message("Ce compte existe déjà", 409)
    user = User(username=username, email=email, password_hash=generate_password_hash(password))
    db.session.add(user); db.session.commit()
    log_event("Compte créé", user)
    return jsonify({"message": "Compte créé avec succès"}), 201

@app.route('/api/login', methods=['POST'])
@limiter.limit("8 per minute")
def login():
    data = request.get_json(silent=True) or {}
    identifier = (data.get('identifier') or data.get('email') or data.get('username') or '').strip().lower()
    password = data.get('password') or ''
    otp = (data.get('otp') or '').strip()
    if not identifier or not password:
        return clean_message("Veuillez remplir tous les champs", 400)
    user = User.query.filter((User.email == identifier) | (User.username == identifier)).first()
    if user and not getattr(user, "is_active", True):
        return clean_message("Ce compte est suspendu", 403)
    if user and user.blocked_until and user.blocked_until > datetime.utcnow():
        return clean_message("Trop de tentatives. Réessayez plus tard", 429)
    if not user or not check_password_hash(user.password_hash, password):
        if user:
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.blocked_until = datetime.utcnow() + timedelta(minutes=15)
                log_event("Compte temporairement bloqué après échecs login", user)
            db.session.commit()
        return clean_message("Identifiants incorrects", 401)
    if user.is_2fa_enabled:
        if not otp:
            return jsonify({"message": "Code 2FA requis", "requires_otp": True}), 206
        if not pyotp.TOTP(user.twofa_secret).verify(otp, valid_window=1):
            return clean_message("Code 2FA incorrect", 401)
    user.failed_attempts = 0
    user.blocked_until = None
    user.last_login_at = datetime.utcnow()
    db.session.commit()
    log_event("Connexion réussie", user)
    return jsonify({"message": "Connexion réussie", "token": create_token(user)})

@app.route('/api/me')
@token_required
def me():
    u = request.user
    org_name = None
    if u.organization_id:
        org = db.session.get(Organization, u.organization_id)
        if org:
            org_name = org.name
    return jsonify({"id": u.id, "username": u.username, "email": u.email, "role": u.role, "plan": effective_plan(u), "billing_plan": u.plan, "hide_billing": u.role == "employee", "premium_until": u.premium_until.isoformat() if u.premium_until else None, "is_2fa_enabled": u.is_2fa_enabled, "browser_integration": u.browser_integration, "organization_id": u.organization_id, "org_name": org_name})

@app.route('/api/profile/update', methods=['POST'])
@token_required
@twofa_required
def update_profile():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    current_password = data.get('current_password') or ''
    new_password = data.get('new_password') or ''
    confirm_password = data.get('confirm_password') or ''
    u = request.user
    changed = False

    if username and username != u.username:
        if len(username) < 3 or len(username) > 40:
            return clean_message("Le nom d'utilisateur doit contenir entre 3 et 40 caractères", 400)
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', username):
            return clean_message("Utilisez seulement lettres, chiffres, point, tiret ou underscore", 400)
        exists = User.query.filter(User.username == username, User.id != u.id).first()
        if exists:
            return clean_message("Ce nom d'utilisateur est déjà utilisé", 409)
        u.username = username
        changed = True

    if current_password or new_password or confirm_password:
        if not current_password or not new_password or not confirm_password:
            return clean_message("Remplissez tous les champs du changement de mot de passe", 400)
        if not check_password_hash(u.password_hash, current_password):
            return clean_message("Mot de passe actuel incorrect", 400)
        if new_password != confirm_password:
            return clean_message("Les nouveaux mots de passe ne correspondent pas", 400)
        if len(new_password) < 10:
            return clean_message("Le nouveau mot de passe doit contenir au moins 10 caractères", 400)
        if password_score(new_password) < 60:
            return clean_message("Choisissez un mot de passe plus fort", 400)
        u.password_hash = generate_password_hash(new_password)
        changed = True
        log_event("Mot de passe du profil modifié", u)

    if not changed:
        return clean_message("Aucune modification détectée", 400)

    db.session.commit()
    return jsonify({"message": "Profil mis à jour", "username": u.username})

@app.route('/api/2fa/setup', methods=['POST'])
@token_required
def setup_2fa():
    u = request.user
    if not u.twofa_secret:
        u.twofa_secret = pyotp.random_base32()
        db.session.commit()
    uri = pyotp.TOTP(u.twofa_secret).provisioning_uri(name=u.email, issuer_name="SecurePass")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr = base64.b64encode(buf.getvalue()).decode()
    # QR TOTP valide: otpauth://totp/SecurePass:email?secret=...&issuer=SecurePass
    return jsonify({"secret": u.twofa_secret, "qr": f"data:image/png;base64,{qr}"})

@app.route('/api/2fa/enable', methods=['POST'])
@token_required
def enable_2fa():
    code = ((request.get_json(silent=True) or {}).get('code', '') or '').strip()
    u = request.user
    if not u.twofa_secret:
        return clean_message("Générez d'abord le QR Code", 400)
    if not pyotp.TOTP(u.twofa_secret).verify(code, valid_window=1):
        return clean_message("Code 2FA incorrect", 400)
    u.is_2fa_enabled = True
    db.session.commit()
    log_event("2FA activée", u)
    return jsonify({"message": "Double authentification activée"})

@app.route('/api/2fa/disable', methods=['POST'])
@token_required
@twofa_required
def disable_2fa():
    request.user.is_2fa_enabled = False
    db.session.commit()
    return jsonify({"message": "Double authentification désactivée"})

# ---------------- PASSWORD ----------------
@app.route('/api/password/generate', methods=['POST'])
@token_required
@twofa_required
def api_generate():
    data = request.get_json(silent=True) or {}
    try:
        length = int(data.get('length', 16))
    except Exception:
        return clean_message("Longueur invalide", 400)
    if length < 12 or length > 64:
        return clean_message("La longueur doit être entre 12 et 64 caractères", 400)
    month = datetime.utcnow().strftime('%Y-%m')
    limit = PLAN_LIMITS[effective_plan(request.user)]['monthly_generations']
    used = GenerationLog.query.filter_by(user_id=request.user.id, month=month).count()
    if limit is not None and used >= limit:
        return clean_message(f"Limite mensuelle atteinte pour le plan {request.user.plan}", 403)
    pwd = generate_password(length)
    db.session.add(GenerationLog(user_id=request.user.id, month=month)); db.session.commit()
    return jsonify({"password": pwd, "score": password_score(pwd), "used": used + 1, "limit": limit})

@app.route('/api/password/analyze', methods=['POST'])
@token_required
@twofa_required
def analyze():
    pwd = (request.get_json(silent=True) or {}).get('password', '')
    if not pwd:
        return clean_message("Mot de passe manquant", 400)
    score = password_score(pwd)
    level = "Faible" if score < 50 else "Moyen" if score < 80 else "Fort"
    return jsonify({"score": score, "level": level})

@app.route('/api/history')
@token_required
@twofa_required
def history():
    month = datetime.utcnow().strftime('%Y-%m')
    used = GenerationLog.query.filter_by(user_id=request.user.id, month=month).count()
    return jsonify({"month": month, "generated_this_month": used, "plan": effective_plan(request.user), "limit": PLAN_LIMITS[effective_plan(request.user)]['monthly_generations']})

# ---------------- VAULT ----------------
@app.route('/api/vault/status')
@token_required
@twofa_required
def vault_status():
    return jsonify({
        "master_created": bool(request.user.master_password_hash),
        "message": "Mot de passe maître déjà créé" if request.user.master_password_hash else "Crée d'abord ton mot de passe maître"
    })

@app.route('/api/vault/master/create', methods=['POST'])
@token_required
@twofa_required
@limiter.limit("5 per hour")
def vault_master_create():
    data = request.get_json(silent=True) or {}
    master = data.get('master_password') or ''
    confirm = data.get('confirm_master_password') or ''
    if request.user.master_password_hash:
        return clean_message("Le mot de passe maître existe déjà", 400)
    if not master or not confirm:
        return clean_message("Veuillez remplir les deux champs", 400)
    if master != confirm:
        return clean_message("Les deux mots de passe ne correspondent pas", 400)
    if not strong_master_password(master):
        return clean_message("Le mot de passe maître doit contenir au moins 8 caractères", 400)
    # On stocke seulement un hash. Le mot de passe maître lui-même n'est jamais sauvegardé.
    request.user.master_password_hash = generate_password_hash(master)
    db.session.commit()
    log_event("Coffre: mot de passe maître créé", request.user)
    return jsonify({"message": "Mot de passe maître créé. Coffre prêt à être déverrouillé."})

@app.route('/api/vault/unlock', methods=['POST'])
@token_required
@twofa_required
@limiter.limit("8 per minute")
def vault_unlock():
    data = request.get_json(silent=True) or {}
    master = data.get('master_password') or ''
    if not request.user.master_password_hash:
        return clean_message("Crée d'abord ton mot de passe maître", 400)
    if not master:
        return clean_message("Entrez votre mot de passe maître", 400)
    if not check_password_hash(request.user.master_password_hash, master):
        log_event("Coffre: échec de déverrouillage", request.user)
        return clean_message("Mot de passe maître incorrect", 403)
    log_event("Coffre: déverrouillé", request.user)
    return jsonify({"message": "Coffre déverrouillé", "unlocked_for_seconds": 600})

def require_valid_master(user, master):
    if not user.master_password_hash:
        return False, "Crée d'abord ton mot de passe maître"
    if not master:
        return False, "Déverrouille d'abord ton coffre"
    if not check_password_hash(user.master_password_hash, master):
        return False, "Mot de passe maître incorrect"
    return True, "OK"

@app.route('/api/vault/add', methods=['POST'])
@token_required
@twofa_required
def vault_add():
    data = request.get_json(silent=True) or {}
    site = normalize_site(data.get('site'))
    login = (data.get('login') or '').strip()[:200]
    password = data.get('password') or ''
    master = data.get('master_password') or ''
    ok, msg = require_valid_master(request.user, master)
    if not ok:
        return clean_message(msg, 403 if msg == "Mot de passe maître incorrect" else 400)
    if not site or not login or not password:
        return clean_message("Veuillez remplir le site, l'identifiant et le mot de passe", 400)
    if len(password) > 512:
        return clean_message("Mot de passe trop long", 400)
    count = Vault.query.filter_by(user_id=request.user.id).count()
    limit = PLAN_LIMITS[effective_plan(request.user)]['vault']
    if limit is not None and count >= limit:
        return clean_message("Limite du coffre atteinte pour votre plan", 403)
    enc, salt = encrypt_secret(master, password)
    try:
        assert decrypt_secret(master, enc, salt) == password
    except Exception:
        return clean_message("Impossible de sécuriser ce mot de passe", 500)
    v = Vault(user_id=request.user.id, organization_id=request.user.organization_id, site=site, login=login, encrypted_password=enc, salt=salt, source="manual", strength_score=password_score(password))
    db.session.add(v); db.session.commit()
    log_event(f"Coffre: ajout d'un identifiant pour {site}", request.user)
    return jsonify({"message": "Mot de passe sauvegardé dans le coffre chiffré"})

@app.route('/api/vault/list')
@token_required
@twofa_required
def vault_list():
    if not request.user.master_password_hash:
        return clean_message("Crée d'abord ton mot de passe maître", 403)
    items = Vault.query.filter_by(user_id=request.user.id).order_by(Vault.created_at.desc()).all()
    return jsonify([{"id":v.id,"site":v.site,"login":v.login,"source":v.source,"strength_score":v.strength_score,"created_at":v.created_at.isoformat(),"masked":"••••••••••••"} for v in items])

@app.route('/api/vault/reveal/<int:vault_id>', methods=['POST'])
@token_required
@twofa_required
def vault_reveal(vault_id):
    master = (request.get_json(silent=True) or {}).get('master_password','')
    v = db.session.get(Vault, vault_id)
    if not v or v.user_id != request.user.id:
        return clean_message("Accès refusé", 403)
    try:
        # Les entrées sauvegardées par l’extension navigateur utilisent une clé technique liée au compte.
        # On les ouvre donc avec cette clé, même si le coffre est déjà déverrouillé avec le mot de passe maître.
        if v.source == "browser":
            password = decrypt_secret(extension_auto_master(request.user), v.encrypted_password, v.salt)
        else:
            ok, msg = require_valid_master(request.user, master)
            if not ok:
                return clean_message(msg, 403 if msg == "Mot de passe maître incorrect" else 400)
            password = decrypt_secret(master, v.encrypted_password, v.salt)
        log_event(f"Coffre: consultation d'un mot de passe pour {v.site}", request.user)
        return jsonify({"password": password})
    except Exception:
        log_event(f"Coffre: tentative de déchiffrement échouée pour {v.site}", request.user)
        return clean_message("Impossible d'ouvrir ce mot de passe", 403)

@app.route('/api/vault/delete/<int:vault_id>', methods=['DELETE'])
@token_required
@twofa_required
def vault_delete(vault_id):
    v = db.session.get(Vault, vault_id)
    if not v or v.user_id != request.user.id:
        return clean_message("Accès refusé", 403)
    site = v.site
    db.session.delete(v); db.session.commit()
    log_event(f"Coffre: suppression d'un identifiant pour {site}", request.user)
    return jsonify({"message": "Entrée supprimée"})

@app.route('/api/security/audit', methods=['GET', 'POST'])
@token_required
@twofa_required
def audit():
    if not plan_allows(request.user, 'audit'):
        return clean_message("Audit réservé aux plans Pro et Enterprise", 402)

    data = request.get_json(silent=True) or {}
    master = data.get('master_password') or ''
    manual_master_ok = False
    if master:
        ok, _ = require_valid_master(request.user, master)
        manual_master_ok = ok

    items = Vault.query.filter_by(user_id=request.user.id).all()
    total = len(items)
    weak = 0
    unknown = 0
    seen_hashes = {}
    site_results = []

    for v in items:
        score = v.strength_score
        pwd_hash = None
        try:
            if v.source == "browser":
                pwd = decrypt_secret(extension_auto_master(request.user), v.encrypted_password, v.salt)
                score = password_score(pwd)
                pwd_hash = hashlib.sha256(pwd.encode()).hexdigest()
            elif manual_master_ok:
                pwd = decrypt_secret(master, v.encrypted_password, v.salt)
                score = password_score(pwd)
                pwd_hash = hashlib.sha256(pwd.encode()).hexdigest()
            elif score is None:
                unknown += 1
        except Exception:
            unknown += 1
            pwd_hash = None

        if pwd_hash:
            seen_hashes[pwd_hash] = seen_hashes.get(pwd_hash, 0) + 1

        if score is not None and score < 70:
            weak += 1

        status = "Bon" if score and score >= 80 else "À améliorer" if score is not None else "À vérifier"
        advice = (
            "Mot de passe solide." if status == "Bon"
            else "Change ce mot de passe avec une version plus longue et unique." if status == "À améliorer"
            else "Déverrouille le coffre puis relance l’audit pour vérifier les réutilisations."
        )
        site_results.append({"site": v.site, "login": v.login, "status": status, "score": score, "advice": advice, "source": v.source})

    reused_password_groups = sum(1 for c in seen_hashes.values() if c > 1)
    reused_entries = sum(c for c in seen_hashes.values() if c > 1)
    risk_points = weak * 18 + reused_password_groups * 20 + unknown * 5
    score_global = max(0, min(100, 100 - risk_points)) if total else 70
    recent_logs = SecurityLog.query.filter_by(user_id=request.user.id).order_by(SecurityLog.created_at.desc()).limit(10).all()
    return jsonify({
        "total": total,
        "weak_passwords": weak,
        "reused_password_groups": reused_password_groups,
        "reused_entries": reused_entries,
        "unknown": unknown,
        "score": score_global,
        "level": "Très bon" if score_global >= 85 else "Correct" if score_global >= 65 else "À corriger",
        "plain_explanation": "SecurePass vérifie la force des mots de passe, les réutilisations et l'activité de votre compte. Les connexions internes à Facebook, Gmail ou autres sites ne sont pas visibles sans leurs API officielles.",
        "sites": site_results,
        "recent_activity": [{"action": l.action, "date": l.created_at.isoformat(), "ip": l.ip} for l in recent_logs]
    })

# ---------------- BILLING FEDAPAY ----------------
def fedapay_headers():
    return {"Authorization": f"Bearer {FEDAPAY_SECRET_KEY}", "Content-Type": "application/json"}

def fedapay_base():
    return "https://sandbox-api.fedapay.com/v1" if FEDAPAY_ENVIRONMENT == "sandbox" else "https://api.fedapay.com/v1"

@app.route('/api/billing/fedapay/create', methods=['POST'])
@token_required
@twofa_required
def fedapay_create():
    if request.user.role == "employee":
        return clean_message("Votre abonnement est géré par l’administrateur de votre entreprise", 403)
    data = request.get_json(silent=True) or {}
    plan = data.get('plan')
    if plan not in ['basic','pro','enterprise']:
        return clean_message("Choisissez un plan valide", 400)
    cfg = PLAN_LIMITS[plan]
    ref = f"SP-{request.user.id}-{uuid.uuid4().hex[:8]}"
    payment = Payment(user_id=request.user.id, reference=ref, plan=plan, amount_xof=cfg['amount_xof'], amount_usd=cfg['price_usd'])
    db.session.add(payment); db.session.commit()
    payload = {
        "description": f"SecurePass {plan.upper()} | {ref}",
        "amount": cfg['amount_xof'],
        "currency": {"iso": "XOF"},
        "callback_url": f"{APP_BASE_URL}/fedapay/return?ref={ref}",
        "customer": {"firstname": request.user.username, "email": request.user.email},
        "metadata": {"user_id": request.user.id, "plan": plan, "ref": ref}
    }
    try:
        r = requests.post(f"{fedapay_base()}/transactions", json=payload, headers=fedapay_headers(), timeout=20)
        if r.status_code >= 300:
            print("FEDAPAY CREATE ERROR:", r.status_code, r.text)
            return clean_message(f"Paiement indisponible pour le moment. Contactez le support : {SUPPORT_PHONE}", 500)
        tx = r.json().get('v1/transaction') or r.json().get('transaction') or r.json()
        tx_id = tx.get('id')
        payment.transaction_id = str(tx_id); db.session.commit()
        token_res = requests.post(f"{fedapay_base()}/transactions/{tx_id}/token", headers=fedapay_headers(), timeout=20)
        if token_res.status_code >= 300:
            print("FEDAPAY TOKEN ERROR:", token_res.status_code, token_res.text)
            return clean_message(f"Impossible d'ouvrir la page de paiement. Contactez le support : {SUPPORT_PHONE}", 500)
        token_data = token_res.json()
        url = token_data.get('url') or token_data.get('token', {}).get('url')
        return jsonify({"url": url, "reference": ref})
    except Exception as e:
        print("FEDAPAY ERROR:", e)
        return clean_message(f"Paiement indisponible pour le moment. Contactez le support : {SUPPORT_PHONE}", 500)

@app.route('/fedapay/return')
def fedapay_return():
    ref = request.args.get('ref')
    tx_id = request.args.get('id')
    payment = Payment.query.filter_by(reference=ref).first() if ref else None
    if not payment:
        return redirect('/payment-failed')
    approved = request.args.get('status') == 'approved'
    # In sandbox, FedaPay return can include approved. In prod, webhook remains the source of truth.
    if approved:
        user = db.session.get(User, payment.user_id)
        activate_plan(user, payment)
        return redirect('/payment-success')
    # Try API verification if tx_id exists
    if tx_id:
        try:
            r = requests.get(f"{fedapay_base()}/transactions/{tx_id}", headers=fedapay_headers(), timeout=20)
            obj = r.json().get('v1/transaction') or r.json().get('transaction') or r.json()
            if obj.get('status') == 'approved':
                user = db.session.get(User, payment.user_id)
                activate_plan(user, payment)
                return redirect('/payment-success')
        except Exception as e:
            print("VERIFY ERROR:", e)
    return redirect('/payment-failed')

def activate_plan(user, payment):
    if not user or not payment: return
    user.plan = payment.plan
    user.premium_until = datetime.utcnow() + timedelta(days=31)
    payment.status = 'approved'
    if not payment.invoice_number:
        create_invoice(payment, user)
    db.session.commit()
    log_event(f"Plan activé: {payment.plan}", user)
    print(f"[OK] PLAN UPDATE → {user.email} = {user.plan}")

@app.route('/webhook/fedapay', methods=['POST'])
def fedapay_webhook():
    data = request.get_json(silent=True) or {}
    tx = data.get('data') or data.get('transaction') or {}
    metadata = tx.get('metadata') or {}
    ref = metadata.get('ref')
    if tx.get('status') == 'approved' and ref:
        payment = Payment.query.filter_by(reference=ref).first()
        if payment:
            user = db.session.get(User, payment.user_id)
            activate_plan(user, payment)
    return '', 200

@app.route('/api/premium/status')
@token_required
def premium_status():
    return jsonify({
        "plan": effective_plan(request.user),
        "billing_plan": request.user.plan,
        "hide_billing": request.user.role == "employee",
        "can_cancel": request.user.role not in ["employee", "super_admin"] and request.user.plan != "free",
        "premium_until": request.user.premium_until.isoformat() if request.user.premium_until else None,
        "plans": {k:{"price_usd":v['price_usd'],"price_label": str(v['price_usd']) + "$"} for k,v in PLAN_LIMITS.items()}
    })

@app.route('/api/billing/cancel', methods=['POST'])
@token_required
@twofa_required
def cancel_subscription():
    user = request.user
    if user.role == 'employee':
        return clean_message("Votre abonnement est géré par l'administrateur de votre entreprise", 403)
    if user.role == 'super_admin':
        return clean_message("Le compte grand admin ne peut pas annuler son accès plateforme", 403)
    if user.plan == 'free':
        return clean_message("Vous êtes déjà sur le plan gratuit", 400)

    old_plan = user.plan
    user.plan = 'free'
    user.premium_until = None
    user.browser_integration = False

    # Si l'admin entreprise annule Enterprise, son organisation est désactivée.
    # Les employés perdent alors automatiquement les avantages Pro via effective_plan().
    if old_plan == 'enterprise' and user.organization_id:
        org = db.session.get(Organization, user.organization_id)
        if org and org.owner_id == user.id:
            org.is_active = False

    p = Payment(
        user_id=user.id,
        provider='system',
        reference='CANCEL-' + uuid.uuid4().hex[:12].upper(),
        plan=old_plan,
        amount_xof=0,
        amount_usd=0,
        status='cancelled'
    )
    db.session.add(p)
    db.session.commit()
    log_event(f"Abonnement annulé: {old_plan} -> free", user)
    return jsonify({"message":"Abonnement annulé. Votre compte est revenu au plan Free.", "plan":"free"})

@app.route('/api/invoices/<number>')
@token_required
@twofa_required
def invoice(number):
    p = Payment.query.filter_by(invoice_number=number, user_id=request.user.id).first()
    if not p: return clean_message("Facture introuvable", 404)
    return send_file(os.path.join('invoices', f'{number}.pdf'), as_attachment=True)

# ---------------- EXTENSION ----------------
@app.route('/api/settings/browser-integration', methods=['POST'])
@token_required
@twofa_required
def browser_setting():
    if not plan_allows(request.user, 'extension'):
        return clean_message(f"Votre plan {request.user.plan} ne permet pas l'intégration navigateur", 402)
    request.user.browser_integration = bool((request.get_json(silent=True) or {}).get('enabled', True))
    db.session.commit()
    return jsonify({"message": "Paramètre navigateur mis à jour"})

@app.route('/api/extension/config')
@token_required
def extension_config():
    if effective_plan(request.user) not in ['pro','enterprise']:
        return clean_message(f"Votre plan {effective_plan(request.user)} ne permet pas l'extension. Passez en Pro ou Enterprise.", 402)
    if not request.user.browser_integration:
        return clean_message("Activez l'intégration navigateur dans SecurePass", 403)
    return jsonify({"enabled": True, "plan": effective_plan(request.user)})

@app.route('/api/extension/generate', methods=['POST', 'OPTIONS'])
def extension_generate():
    if request.method == 'OPTIONS': return '', 200
    user = get_user_from_token()
    if not user: return clean_message("Connectez l'extension à SecurePass", 401)
    request.user = user
    if effective_plan(user) not in ['pro','enterprise']:
        return clean_message(f"Plan {effective_plan(user)}: extension réservée à Pro et Enterprise", 402)
    if not user.browser_integration:
        return clean_message("Activez l'intégration navigateur", 403)
    return jsonify({"password": generate_password(18)})


@app.route('/api/extension/autosave', methods=['POST', 'OPTIONS'])
def extension_autosave():
    if request.method == 'OPTIONS': return '', 200
    user = get_user_from_token()
    if not user: return clean_message("Connectez l'extension à SecurePass", 401)
    if effective_plan(user) not in ['pro','enterprise']:
        return clean_message(f"Plan {effective_plan(user)}: coffre navigateur réservé à Pro et Enterprise", 402)
    if not user.browser_integration:
        return clean_message("Activez l'intégration navigateur", 403)
    data = request.get_json(silent=True) or {}
    site = normalize_site(data.get('site'))
    login = (data.get('login') or '').strip()[:200] or 'Compte sans identifiant détecté'
    password = data.get('password') or ''
    if not site or not password:
        return clean_message("Site ou mot de passe manquant", 400)
    if len(password) < 4 or len(password) > 512:
        return clean_message("Mot de passe invalide", 400)
    existing = Vault.query.filter_by(user_id=user.id, site=site, login=login, source='browser').first()
    enc, salt = encrypt_secret(extension_auto_master(user), password)
    score = password_score(password)
    if existing:
        existing.encrypted_password = enc; existing.salt = salt; existing.strength_score = score; existing.last_audited_at = datetime.utcnow()
    else:
        existing = Vault(user_id=user.id, organization_id=user.organization_id, site=site, login=login, encrypted_password=enc, salt=salt, source='browser', strength_score=score, last_audited_at=datetime.utcnow())
        db.session.add(existing)
    db.session.commit()
    log_event(f"Extension: identifiant sauvegardé pour {site}", user)
    return jsonify({"message": "Identifiant sauvegardé automatiquement dans le coffre", "score": score})

# ---------------- ENTERPRISE ----------------
@app.route('/api/org/create', methods=['POST'])
@token_required
@twofa_required
def org_create():
    if request.user.plan != 'enterprise': return clean_message("Plan Enterprise requis", 402)
    name = (request.get_json(silent=True) or {}).get('name','').strip()
    if not name: return clean_message("Nom d'organisation requis", 400)
    if request.user.organization_id: return clean_message("Vous avez déjà une organisation", 400)
    org = Organization(name=name, owner_id=request.user.id)
    db.session.add(org); db.session.commit()
    request.user.organization_id = org.id; request.user.role = 'org_admin'
    db.session.commit()
    log_event(f"Organisation créée: {name}", request.user)
    return jsonify({"message":"Organisation créée", "org_id": org.id, "org_name": org.name})

@app.route('/api/org/info')
@token_required
@twofa_required
def org_info():
    if not request.user.organization_id:
        return clean_message("Aucune organisation", 404)
    org = db.session.get(Organization, request.user.organization_id)
    if not org:
        return clean_message("Organisation introuvable", 404)
    users_count = User.query.filter_by(organization_id=org.id).count()
    employees_count = User.query.filter_by(organization_id=org.id, role='employee').count()
    return jsonify({"id": org.id, "name": org.name, "active": org.is_active, "owner_id": org.owner_id, "is_owner": org.owner_id == request.user.id, "users_count": users_count, "employees_count": employees_count, "created_at": org.created_at.isoformat()})

@app.route('/api/org/users', methods=['GET','POST'])
@token_required
@twofa_required
@org_admin_required
def org_users():
    if request.user.plan != 'enterprise':
        return clean_message("Abonnement Enterprise requis", 402)
    if not request.user.organization_id:
        return clean_message("Aucune organisation", 400)
    org = db.session.get(Organization, request.user.organization_id)
    if not org or not org.is_active:
        return clean_message("Organisation inactive", 403)
    if request.method == 'GET':
        users = User.query.filter_by(organization_id=request.user.organization_id).all()
        return jsonify([{"id":u.id,"email":u.email,"username":u.username,"role":u.role,"effective_plan":effective_plan(u),"active":u.is_active,"twofa":u.is_2fa_enabled} for u in users])

    if org.owner_id != request.user.id:
        return clean_message("Seul l'administrateur principal de l'organisation peut créer des employés", 403)
    if effective_plan(request.user) != 'enterprise':
        return clean_message("Abonnement Enterprise actif requis", 402)
    employees_count = User.query.filter_by(organization_id=request.user.organization_id, role='employee').count()
    if employees_count >= 50:
        return clean_message("Limite de 50 employés atteinte pour cette organisation", 403)

    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').lower().strip()
    username = (data.get('username') or email.split('@')[0]).strip()
    password = data.get('password') or ''
    if not email or not username or not password:
        return clean_message("Email, nom utilisateur et mot de passe requis", 400)
    if not valid_email(email):
        return clean_message("Adresse email employé invalide", 400)
    if not valid_username(username):
        return clean_message("Nom utilisateur invalide: 3 à 30 caractères, lettres, chiffres, point, tiret ou underscore", 400)
    ok, msg = strong_account_password(password, username, email)
    if not ok:
        return clean_message(msg, 400)
    if User.query.filter((User.email==email)|(User.username==username)).first():
        return clean_message("Utilisateur déjà existant", 409)
    emp = User(email=email, username=username, password_hash=generate_password_hash(password), role='employee', plan='free', premium_until=None, organization_id=request.user.organization_id, is_2fa_enabled=False)
    db.session.add(emp)
    db.session.commit()
    log_event(f"Employé créé: {email}", request.user)
    return jsonify({"message":"Employé créé. Il devra activer la 2FA à sa première connexion."})

@app.route('/api/org/logs')
@token_required
@twofa_required
@org_admin_required
def org_logs():
    if request.user.plan != 'enterprise':
        return clean_message("Abonnement Enterprise requis", 402)
    logs = SecurityLog.query.filter_by(organization_id=request.user.organization_id).order_by(SecurityLog.created_at.desc()).limit(100).all()
    return jsonify([{"action":l.action,"ip":l.ip,"created_at":l.created_at.isoformat()} for l in logs])

@app.route('/api/share', methods=['POST'])
@token_required
@twofa_required
def share():
    data = request.get_json(silent=True) or {}
    vault_id = data.get('vault_id'); target_id = data.get('target_user_id')
    v = db.session.get(Vault, vault_id); target = db.session.get(User, target_id)
    if not v or v.user_id != request.user.id: return clean_message("Accès refusé", 403)
    if not target or target.organization_id != request.user.organization_id or not request.user.organization_id: return clean_message("Destinataire invalide", 400)
    s = SharedVault(vault_id=v.id, owner_id=request.user.id, target_user_id=target.id, organization_id=request.user.organization_id)
    db.session.add(s); db.session.commit()
    return jsonify({"message":"Partage créé"})

@app.route('/api/shared')
@token_required
@twofa_required
def shared_list():
    items = SharedVault.query.filter_by(target_user_id=request.user.id).all()
    out=[]
    for s in items:
        v = db.session.get(Vault, s.vault_id)
        if v: out.append({"site":v.site,"login":v.login,"owner_id":s.owner_id})
    return jsonify(out)

# ---------------- PUBLIC API ----------------
@app.route('/api/public/key', methods=['POST'])
@token_required
@twofa_required
def public_key_create():
    if not plan_allows(request.user, 'api'):
        return clean_message("API publique réservée aux plans Pro et Enterprise", 402)
    raw = 'sp_' + secrets.token_urlsafe(32)
    request.user.api_key_hash = hashlib.sha256(raw.encode()).hexdigest()
    db.session.commit()
    return jsonify({"api_key": raw})

@app.route('/public/v1/analyze', methods=['POST'])
def public_analyze():
    key = request.headers.get('X-API-Key','')
    if not key: return clean_message("Clé API requise", 401)
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    user = User.query.filter_by(api_key_hash=key_hash).first()
    if not user or effective_plan(user) not in ['pro','enterprise']: return clean_message("Clé API invalide", 403)
    pwd = (request.get_json(silent=True) or {}).get('password','')
    return jsonify({"score": password_score(pwd)})

# ---------------- ADMIN ----------------
def enforce_single_super_admin():
    """Garantit qu'il n'existe qu'un seul grand admin plateforme."""
    admins = User.query.filter_by(role='super_admin').order_by(User.created_at.asc()).all()
    if len(admins) <= 1:
        return
    keeper = admins[0]
    for extra in admins[1:]:
        extra.role = 'user'
        extra.plan = 'free'
        db.session.add(SecurityLog(user_id=keeper.id, action=f"Sécurité: super_admin supplémentaire rétrogradé ({extra.email})", ip=None))
    db.session.commit()

@app.route('/api/admin/login', methods=['POST'])
@limiter.limit("5 per minute")
def admin_login():
    data = request.get_json(silent=True) or {}
    identifier = (data.get('identifier') or '').strip().lower()
    password = data.get('password') or ''
    otp = (data.get('otp') or '').strip()
    if not identifier or not password:
        return clean_message("Veuillez remplir tous les champs", 400)
    user = User.query.filter((User.email == identifier) | (User.username == identifier)).first()
    if not user or user.role != 'super_admin' or not check_password_hash(user.password_hash, password):
        return clean_message("Accès refusé", 403)
    if not getattr(user, 'is_active', True):
        return clean_message("Ce compte est suspendu", 403)
    if user.is_2fa_enabled:
        if not otp:
            return jsonify({"message":"Code 2FA requis", "requires_otp": True}), 206
        if not pyotp.TOTP(user.twofa_secret).verify(otp, valid_window=1):
            log_event("Échec 2FA grand admin", user)
            return clean_message("Code 2FA incorrect", 401)
    user.failed_attempts = 0
    user.blocked_until = None
    user.last_login_at = datetime.utcnow()
    db.session.commit()
    log_event("Connexion grand admin", user)
    return jsonify({"message":"Connexion administrateur réussie", "token":create_token(user), "twofa_enabled":user.is_2fa_enabled})

@app.route('/api/admin/me')
@token_required
@super_admin_required
def admin_me():
    u = request.user
    return jsonify({"username":u.username, "email":u.email, "twofa_enabled":u.is_2fa_enabled, "role":u.role})

@app.route('/api/admin/stats')
@token_required
@twofa_required
@super_admin_required
def admin_stats():
    now = datetime.utcnow()
    active_recent = User.query.filter(User.last_login_at != None, User.last_login_at >= now - timedelta(minutes=30)).count()
    approved = Payment.query.filter_by(status='approved').all()
    return jsonify({
        "users": User.query.count(),
        "active_recent": active_recent,
        "premium": User.query.filter(User.plan!='free').count(),
        "payments": Payment.query.count(),
        "organizations": Organization.query.count(),
        "blocked": User.query.filter(User.blocked_until != None, User.blocked_until > now).count(),
        "revenue_xof": sum([p.amount_xof for p in approved])
    })

@app.route('/api/admin/users')
@token_required
@twofa_required
@super_admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).limit(500).all()
    return jsonify([{
        "id":u.id, "email":u.email, "username":u.username, "role":u.role, "plan":u.plan,
        "effective_plan": effective_plan(u), "org":u.organization_id, "twofa":u.is_2fa_enabled,
        "active": getattr(u,'is_active',True),
        "blocked_until": u.blocked_until.isoformat() if u.blocked_until else None,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        "created_at": u.created_at.isoformat() if u.created_at else None
    } for u in users])

@app.route('/api/admin/users/<int:user_id>/toggle-active', methods=['POST'])
@token_required
@twofa_required
@super_admin_required
def admin_toggle_active(user_id):
    u = db.session.get(User, user_id)
    if not u:
        return clean_message("Utilisateur introuvable", 404)
    if u.role == 'super_admin':
        return clean_message("Impossible de suspendre le compte grand admin", 403)
    u.is_active = not getattr(u, 'is_active', True)
    db.session.commit()
    log_event(("Compte réactivé" if u.is_active else "Compte suspendu") + f" par grand admin: {u.email}", request.user)
    return jsonify({"message":"Statut mis à jour", "active":u.is_active})

@app.route('/api/admin/users/<int:user_id>/unblock', methods=['POST'])
@token_required
@twofa_required
@super_admin_required
def admin_unblock_user(user_id):
    u = db.session.get(User, user_id)
    if not u:
        return clean_message("Utilisateur introuvable", 404)
    u.failed_attempts = 0
    u.blocked_until = None
    db.session.commit()
    log_event(f"Compte débloqué par grand admin: {u.email}", request.user)
    return jsonify({"message":"Compte débloqué"})

@app.route('/api/admin/payments')
@token_required
@twofa_required
@super_admin_required
def admin_payments():
    payments = Payment.query.order_by(Payment.created_at.desc()).limit(300).all()
    return jsonify([{
        "id":p.id,"user_id":p.user_id,"provider":p.provider,"reference":p.reference,"plan":p.plan,
        "amount_xof":p.amount_xof,"amount_usd":p.amount_usd,"status":p.status,
        "transaction_id":p.transaction_id,"invoice_number":p.invoice_number,"created_at":p.created_at.isoformat()
    } for p in payments])

@app.route('/api/admin/organizations')
@token_required
@twofa_required
@super_admin_required
def admin_organizations():
    orgs = Organization.query.order_by(Organization.created_at.desc()).all()
    out=[]
    for o in orgs:
        out.append({"id":o.id,"name":o.name,"owner_id":o.owner_id,"active":o.is_active,"users":User.query.filter_by(organization_id=o.id).count(),"created_at":o.created_at.isoformat()})
    return jsonify(out)

@app.route('/api/admin/logs')
@token_required
@twofa_required
@super_admin_required
def admin_logs():
    logs = SecurityLog.query.order_by(SecurityLog.created_at.desc()).limit(300).all()
    return jsonify([{"user_id":l.user_id,"org":l.organization_id,"action":l.action,"ip":l.ip,"created_at":l.created_at.isoformat()} for l in logs])

# ---------------- INIT ----------------
def init_db():
    with app.app_context():
        db.create_all()
        admins = User.query.filter_by(role='super_admin').order_by(User.created_at.asc()).all()
        if not admins:
            admin = User(username='admin', email='admin@securepass.local', password_hash=generate_password_hash('Admin@12345!'), role='super_admin', plan='enterprise', premium_until=datetime.utcnow()+timedelta(days=365), is_2fa_enabled=False, is_active=True)
            db.session.add(admin); db.session.commit()
            print("Grand admin créé: admin / Admin@12345!")
            print("Important: connecte-toi puis active la 2FA avant d'utiliser la console admin.")
        enforce_single_super_admin()

init_db()
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
