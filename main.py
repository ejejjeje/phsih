from flask import Flask, request, jsonify, render_template, redirect, flash, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_socketio import SocketIO, emit
from urllib.parse import urlparse
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from sqlalchemy import func
from functools import lru_cache
from feature_extraction.feature_extractor import extract_url_features
import joblib
import random
import socket
import time
import string
import os
import concurrent.futures
import pandas as pd

from models.db_models import db, SafeURL, SafeDomain, PhishingURL, BlacklistURL, BlacklistDomain, BlacklistIP, Notification, BlockedURL, User
from predict_url import predict_url

rf_model = joblib.load("trained_models/randomForest_final.pkl")

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configuration from environment variables
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "dev-secret")

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail setup
app.config['MAIL_SERVER'] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config['MAIL_PORT'] = int(os.environ.get("MAIL_PORT", 587))
app.config['MAIL_USE_TLS'] = os.environ.get("MAIL_USE_TLS", "True") == "True"
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")

mail = Mail(app)


# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"   # 👈 Redirect to login page instead of JSON
login_manager.login_message_category = "info"
socketio = SocketIO(app, cors_allowed_origins="*")  # ✅ added

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

FEATURE_NAMES = [
    'url_having_ip', 'url_length', 'url_short', 'having_at_symbol', 'doubleSlash',
    'prefix_suffix', 'sub_domain', 'SSLfinal_State', 'domain_registration', 'favicon',
    'port', 'https_token', 'request_url', 'url_of_anchor', 'Links_in_tags', 'sfh',
    'email_submit', 'abnormal_url', 'redirect', 'on_mouseover', 'rightClick', 'popup',
    'iframe', 'age_of_domain', 'check_dns', 'web_traffic', 'page_rank', 'google_index',
    'links_pointing', 'statistical'
]


# ---------------- Helper Functions ----------------

def resolve_ip_timeout(url, timeout=5.0):
    """Resolve IP address with a timeout using ThreadPoolExecutor."""
    hostname = urlparse(url).hostname
    if not hostname:
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(socket.gethostbyname, hostname)
        try:
            return future.result(timeout=timeout)
        except Exception:
            return None

# ---------------- Routes ----------------

@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data:
        return jsonify({'message': 'Invalid or missing JSON'}), 400

    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    if not all([email, username, password]):
        return jsonify({'message': 'All fields are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already registered'}), 409

    try:
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Account created successfully'}), 201
    except Exception as e:
        print("Registration error:", e)
        return jsonify({'message': 'Internal server error'}), 500

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'GET':
        return render_template('login.html')

    # Handle form submissions from browser
    if request.form:
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get("next")  # redirect back after login
            return redirect(next_page or url_for("dash"))
        else:
            flash("Invalid email or password", "danger")
            return redirect(url_for("login"))

    # Handle JSON logins (e.g., from extension)
    data = request.get_json()
    if data:
        email = data.get('email')
        password = data.get('password')
        if not all([email, password]):
            return jsonify({'message': 'Email and password are required'}), 400

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return jsonify({'message': 'Login successful'}), 200
        else:
            return jsonify({'message': 'Invalid credentials'}), 401

    return jsonify({'message': 'Invalid request'}), 400

@app.route("/check_login")
def check_login():
    return jsonify({"logged_in": current_user.is_authenticated})

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('scanner'))

# --- Helper function to normalize URLs consistently ---
def normalize_url_for_matching(u):
    if not u:
        return ""
    u = u.strip().lower()
    if u.endswith('/'):
        u = u.rstrip('/')
    return u

# --- Cache blacklists and safelists in memory ---
@lru_cache(maxsize=1)
def load_blacklist_cache():
    urls = {normalize_url_for_matching(b.url) for b in BlacklistURL.query.all()}
    domains = {d.domain.lower() for d in BlacklistDomain.query.all()}
    ips = {i.ip_address for i in BlacklistIP.query.all()}
    return urls, domains, ips

@lru_cache(maxsize=1)
def load_safelist_cache():
    urls = {normalize_url_for_matching(s.url) for s in SafeURL.query.all()}
    domains = {d.domain.lower() for d in SafeDomain.query.all()}
    return urls, domains

import concurrent.futures
import socket
from urllib.parse import urlparse

# --- Helper: Resolve IP with timeout ---
def resolve_ip_timeout(url, timeout=5.0):
    """Resolve IP address with a timeout using ThreadPoolExecutor."""
    hostname = urlparse(url).hostname
    if not hostname:
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(socket.gethostbyname, hostname)
        try:
            return future.result(timeout=timeout)
        except Exception:
            return None

def normalize_url(url: str) -> str:
    """Normalize URLs to ensure consistent matching."""
    if not url:
        return url
    
    url = url.strip().lower()

    # Ensure scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    # Remove default ports
    netloc = parsed.hostname or ""
    if parsed.port:
        if (parsed.scheme == "http" and parsed.port == 80) or \
           (parsed.scheme == "https" and parsed.port == 443):
            netloc = parsed.hostname

    # Normalize path (remove trailing slash unless root)
    path = parsed.path if parsed.path not in ["", "/"] else ""

    return f"{parsed.scheme}://{netloc}{path}"

# --- Heuristic + RF combined prediction ---
def predict_url_with_heuristic(url):
    features = extract_url_features(url)

    suspicious_js_features = [
        'iframe', 'popup', 'rightClick', 'on_mouseover', 
        'Links_in_tags', 'sfh', 'email_submit', 'abnormal_url'
    ]
    js_suspicious_count = sum(features[f] for f in suspicious_js_features)

    feature_df = pd.DataFrame([[features[f] for f in FEATURE_NAMES]], columns=FEATURE_NAMES)
    rf_pred = rf_model.predict(feature_df)[0]
    rf_result = "Phish" if rf_pred == 1 else "Safe"
    rf_proba = rf_model.predict_proba(feature_df)[0]

    if js_suspicious_count >= 3:
        final_result = "Phish"
    else:
        final_result = rf_result

    return {
        "result": final_result,
        "rf_result": rf_result,
        "rf_proba": rf_proba,
        "suspicious_js_count": js_suspicious_count,
        "features": features
    }


# --- Fast URL prediction ---
def predict_url_fast(url):
    """Predict using the preloaded Random Forest model"""
    features_dict = extract_url_features(url)

    # ✅ Convert dict → DataFrame with correct feature order
    features_df = pd.DataFrame([[features_dict[f] for f in FEATURE_NAMES]], columns=FEATURE_NAMES)

    pred = rf_model.predict(features_df)[0]
    return "Phish" if pred == 1 else "Safe"

    
@app.route('/predict', methods=['POST'])
def predict():
    import time
    from datetime import datetime, timezone
    start_time = time.time()
    data = request.get_json()
    raw_url = data.get('url')
    manual = bool(data.get('manual', False))
    user_token = data.get('user_token')

    if not raw_url:
        return jsonify({'result': 'Unknown', 'error': 'No URL provided'}), 400

    try:
        # 🚫 Skip scanning internal/system URLs
        if "localhost:5000" in raw_url or "127.0.0.1:5000" in raw_url:
            return jsonify({
                "result": "Safe",
                "status": "internal_skip",
                "user_blocked": False,
                "url": raw_url,
                "domain": "internal",
                "ip_address": "127.0.0.1",
                "user": "system",
                "guest": False,
                "time": 0
            }), 200

        # --- Ensure URL has scheme ---
        if not raw_url.startswith(("http://", "https://")):
            raw_url = "https://" + raw_url

        original_url = raw_url
        normalized_url = normalize_url_for_matching(raw_url)
        normalized_url_lower = normalized_url.lower()

        parsed = urlparse(raw_url)
        domain = parsed.hostname if parsed.hostname else parsed.netloc
        domain_lower = domain.lower() if domain else ""

        # --- Determine user ---
        user = current_user if current_user.is_authenticated else None
        if user_token and not user:
            user = User.query.filter_by(api_token=user_token).first()

        # --- Resolve IP with caching ---
        ip_cache = getattr(app, "_ip_cache", {})
        if domain in ip_cache:
            ip_address = ip_cache[domain]
        else:
            ip_address = resolve_ip_timeout(raw_url, timeout=5.0)
            ip_cache[domain] = ip_address
            app._ip_cache = ip_cache

        print("\n====== URL Scan Request ======")
        print(f"Scanning URL: {original_url}")
        print(f"Domain: {domain}")
        print(f"IP Address: {ip_address}")

        result = None
        status = "scanned"
        user_blocked = False

        # --- Load caches ---
        bl_urls, bl_domains, bl_ips = load_blacklist_cache()
        bl_urls = {u.lower(): True for u in bl_urls}
        bl_domains = {d.lower(): True for d in bl_domains}
        bl_ips = {i for i in bl_ips}

        safe_urls, safe_domains = load_safelist_cache()
        safe_urls = {u.lower(): True for u in safe_urls}

        # --- Step 1: Check if user blocked (per-user only, priority) ---
        if user:
            blocked_urls_set = {
                normalize_url_for_matching(b.url).lower()
                for b in BlockedURL.query.with_entities(BlockedURL.url).filter_by(user_id=user.id)
            }
            if normalized_url_lower in blocked_urls_set:
                user_blocked = True
                result = "Already Blocked"
                status = "user_blocked"
                print("→ URL is blocked by user")

        # --- Step 2: Check global blacklists only if not user-blocked ---
        if not user_blocked:
            if normalized_url_lower in bl_urls:
                result = "Phish"
                status = "global_blocked_url"
                print(f"→ Matched GLOBAL BLACKLIST URL: {original_url}")
            elif domain_lower in bl_domains:
                result = "Phish"
                status = "global_blocked_domain"
                print(f"→ Matched GLOBAL BLACKLIST DOMAIN: {domain}")
            elif ip_address in bl_ips:
                result = "Phish"
                status = "global_blocked_ip"
                print(f"→ Matched GLOBAL BLACKLIST IP: {ip_address}")

        # --- Step 3: Check Safe URLs only if not set ---
        if result is None and normalized_url_lower in safe_urls:
            result = "Safe"
            print(f"→ Matched SAFE URL: {original_url}")

        # --- Step 4: Check user scan history only if not blocked ---
        existing_scan = None
        if user and not user_blocked:
            scans = PhishingURL.query.filter_by(user_id=user.id).all()
            for scan in scans:
                if normalize_url_for_matching(scan.url).lower() == normalized_url_lower:
                    existing_scan = scan
                    break
            if existing_scan and manual:
                result = existing_scan.result
                print(f"→ Found in user scan history: {result}")

        # --- Step 5: ML prediction if unknown ---
        if result is None:
            heuristic_result = predict_url_with_heuristic(raw_url)
            result = heuristic_result["result"]
            rf_result = heuristic_result["rf_result"]
            proba = heuristic_result["rf_proba"]
            features = heuristic_result["features"]

            print("\n====== Random Forest Debug ======")
            print(f"Scanned URL: {original_url}")
            for k, v in features.items():
                print(f"{k}: {v}")
            print(f"Prediction: {result}")
            print(f"Confidence: {proba}")
            print("================================\n")

        # --- Save scan & notification ---
        if user and manual:
            if not user_blocked and not existing_scan:
                db.session.add(
                    PhishingURL(
                        url=original_url,
                        domain=domain,
                        ip_address=ip_address,
                        result=result,
                        user_id=user.id,
                        created_at=datetime.now(timezone.utc)
                    )
                )
            notif_msg = f"The URL '{original_url}' is in your blocked URLs." if user_blocked \
                        else f"The URL '{original_url}' was scanned. Result: {result}."
            db.session.add(Notification(user_id=user.id, message=notif_msg, created_at=datetime.now(timezone.utc)))
            db.session.commit()
            print("→ Notification sent for user:", user.username)

        elapsed_time = round(time.time() - start_time, 2)
        print(f"✓ Scan completed in {elapsed_time} seconds")

        return jsonify({
            "result": result,
            "status": status,
            "user_blocked": user_blocked,
            "url": original_url,
            "domain": domain,
            "ip_address": ip_address,
            "user": user.username if user else "Guest",
            "guest": not bool(user),
            "time": elapsed_time
        })

    except Exception as e:
        print("Prediction error:", e)
        return jsonify({
            "result": "Unknown",
            "error": str(e),
            "message": "Internal server error occurred during URL prediction."
        }), 500

@app.route('/api/blocklist', methods=['GET'])
@login_required
def get_blocklist():
    from flask import jsonify
    # Fetch blocked URLs/domains/IPs for the logged-in user
    urls = [b.url for b in BlacklistURL.query.all()]
    domains = [d.domain for d in BlacklistDomain.query.all()]
    ips = [i.ip for i in BlacklistIP.query.all()]
    
    return jsonify({
        "urls": urls,
        "domains": domains,
        "ips": ips
    })


@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user
    scan_count = PhishingURL.query.filter_by(user_id=user.id).count()
    blocked_count = BlockedURL.query.filter_by(user_id=current_user.id).count()

    # --- Fetch history for table ---
    scans = (
        PhishingURL.query
        .filter_by(user_id=user.id)
        .order_by(PhishingURL.created_at.desc())
        .all()
    )
    history = [{
        'url': s.url,
        'domain': s.domain,
        'ip_address': s.ip_address,
        'result': s.result,
        'created_at': s.created_at.strftime('%Y-%m-%d')
    } for s in scans]

    # --- Aggregate scans by day (last 30 days) ---
    scan_stats = (
        db.session.query(
            func.date(PhishingURL.created_at).label('date'),
            func.count().label('count')
        )
        .filter(PhishingURL.user_id == user.id)
        .group_by(func.date(PhishingURL.created_at))
        .order_by(func.date(PhishingURL.created_at))
        .all()
    )

    # Convert to dict list for chart
    chart_data = [{'date': str(r.date), 'count': r.count} for r in scan_stats]

    return render_template(
        'dash.html',
        user=user,
        scan_count=scan_count,
        block_count=blocked_count,
        history=history,
        chart_data=chart_data
    )
@app.route('/')
def home():
    # Landing page is scanner
    return render_template('Scanner.html', user=current_user if current_user.is_authenticated else None)

@app.route('/scanner')
def scanner():
    # Public scanner page (no login required)
    return render_template('scanner.html', user=current_user if current_user.is_authenticated else None)


@app.route('/blockpage', methods=['GET'])
@login_required
def block_page():
    user = current_user
    blocked_urls = BlockedURL.query.filter_by(user_id=user.id).all()
    return render_template('blockpage.html', user=user, blocked_urls=blocked_urls)

@app.route('/get_notifications')
@login_required
def get_notifications():
    notifs = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return jsonify([
        {
            'message': n.message,
            'is_read': n.is_read,
            'timestamp': n.created_at.isoformat()  # ✅ Add timestamp in valid format
        }
        for n in notifs
    ])
@app.route('/clear_notifications', methods=['POST'])
@login_required
def clear_notifications():
    Notification.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    return '', 204

@app.route('/block_url', methods=['POST'])
def block_url():
    if not current_user.is_authenticated:
        return jsonify({'status': 'error', 'message': 'Login required'}), 401

    data = request.get_json()
    url = normalize_url(data.get('url'))

    # Safely parse domain
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower() if parsed.netloc else None
    except Exception:
        domain = None

    if not url or not domain:
        return jsonify({'status': 'error', 'message': 'Invalid URL'}), 400

    # Prevent duplicates
    existing = BlockedURL.query.filter_by(user_id=current_user.id, url=url).first()
    if existing:
        return jsonify({'status': 'already_blocked', 'message': 'URL already blocked'}), 200

    # Save blocked entry
    blocked = BlockedURL(
        user_id=current_user.id,
        url=url,
        domain=domain,
        ip_address=resolve_ip_timeout(url)
    )
    db.session.add(blocked)
    db.session.commit()

    return jsonify({'status': 'blocked', 'message': 'URL successfully blocked'}), 200

@app.route('/unblock', methods=['POST'])
@login_required
def unblock_url():
    url_id = request.form.get('url_id')
    blocked = BlockedURL.query.filter_by(id=url_id, user_id=current_user.id).first()

    if blocked:
        db.session.delete(blocked)
        db.session.commit()
        flash("URL has been unblocked.", "success")
    else:
        flash("URL not found or unauthorized.", "danger")

    return redirect(url_for('block_page'))

@app.route('/remove_blacklist/<int:id>', methods=['POST'])
@login_required
def remove_blacklist(id):
    item = BlockedURL.query.filter_by(id=id, user_id=current_user.id).first()
    if item:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('block_page'))


@app.route('/api/blocked-urls', methods=['GET'])
@login_required
def get_blocked_urls():
    blocked = BlockedURL.query.filter_by(user_id=current_user.id).all()
    urls = [entry.url for entry in blocked]
    return jsonify({'blocked_urls': urls})

@app.route('/check_url', methods=['POST'])
def check_url():
    import time
    import pandas as pd
    from urllib.parse import urlparse
    import sys
    import os

    # Ensure feature_extractor can be imported
    sys.path.append(os.path.join(os.path.dirname(__file__), "feature_extraction"))
    from feature_extractor import extract_url_features as extract_features

    data = request.get_json()
    raw_url = data.get('url')

    if not raw_url:
        return jsonify({'result': 'Unknown', 'domain': None, 'elapsed_time': 0}), 400

    start_time = time.time()
    try:
        # Normalize and parse URL
        url = normalize_url(raw_url.strip().lower())
        parsed = urlparse(url)
        domain = parsed.netloc
        result = None

        print(f"\n🔍 Testing URL (ML only): {url}")

        # --- ML model prediction only ---
        try:
            features = extract_features(url)
            df = pd.DataFrame([features])
            prediction = rf_model.predict(df)[0]  # Use preloaded model
            result = 'phish' if prediction == 1 else 'safe'
            print(f"🤖 ML predicted: {result}")
        except Exception as ml_err:
            print(f"⚠️ ML prediction failed: {ml_err}")
            result = 'Unknown'

        # Compute elapsed time
        elapsed = round(time.time() - start_time, 2)
        print(f"✅ Finished ML-only check in {elapsed}s")

        # Return JSON
        return jsonify({
            'result': result,
            'domain': domain,
            'elapsed_time': elapsed
        })

    except Exception as e:
        elapsed = round(time.time() - start_time, 2)
        print("❌ Error in /check_url:", e)
        return jsonify({
            'result': 'error',
            'domain': None,
            'elapsed_time': elapsed,
            'error': str(e)
        }), 500


@login_manager.unauthorized_handler
def unauthorized_callback():
    # If the request prefers JSON (API/extension requests)
    if request.accept_mimetypes['application/json'] >= request.accept_mimetypes['text/html']:
        return jsonify({'error': 'Unauthorized'}), 401
    # Otherwise, redirect normal browser users to the login page
    return redirect(url_for('login_page'))

@app.route("/send-reset-code", methods=["POST"])
def send_reset_code():
    email = request.form.get("email")
    user = User.query.filter_by(email=email).first()

    if not user:
        flash("Email not found.")
        return redirect(url_for("forgot_password"))

    # Generate a 6-digit reset code
    reset_code = ''.join(random.choices(string.digits, k=6))
    user.reset_code = reset_code
    user.reset_expiration = datetime.utcnow() + timedelta(minutes=2)
    db.session.commit()

    # Save email to session for later verification
    session['reset_email'] = email

    # Compose email
    msg = Message("Your Reset Code", sender="your@email.com", recipients=[email])

    # Plain-text fallback
    msg.body = (
        "⚠️ DO NOT share this code with anyone.\n\n"
        "This reset code is valid for only 2 minutes.\n\n"
        f"Your reset code: {reset_code}"
    )

    # HTML-styled message
    msg.html = f"""
    <!DOCTYPE html>
    <html>
      <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
        <div style="max-width: 500px; margin: auto; background-color: #ffffff; border-radius: 10px; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
          <h2 style="color: #d9534f;">⚠️ Do Not Share This Code</h2>
          <p style="font-size: 16px;">This reset code is private. <strong>Do not share it</strong> with anyone.</p>
          <p><strong>⏰ Code expires in <span style="color:#d9534f;">2 minutes</span>.</strong></p>
          <p style="margin-top: 20px; font-size: 20px;">🔐 <strong>Your Reset Code:</strong></p>
          <div style="font-size: 32px; font-weight: bold; color: #0275d8; margin: 10px 0;">{reset_code}</div>
          <p style="font-size: 14px; color: #999;">If you didn't request this, please ignore this email.</p>
        </div>
      </body>
    </html>
    """

    mail.send(msg)

    flash("A reset code has been sent to your email.")
    return redirect(url_for("verify_code"))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            reset_code = ''.join(random.choices(string.digits, k=6))
            user.reset_code = reset_code
            user.reset_expiration = datetime.utcnow() + timedelta(minutes=10)
            db.session.commit()
            send_reset_email(user.email, reset_code)
            session['reset_user_id'] = user.id
            flash('Reset code sent to your email.', 'success')
            return redirect(url_for('verify_code'))
        else:
            flash('Email not found.', 'danger')
    return render_template('forgot_password.html')

@app.route("/verify-code", methods=["GET", "POST"])
def verify_code():
    if request.method == "POST":
        code = request.form.get("code")
        email = session.get("reset_email")

        user = User.query.filter_by(email=email).first()

        if not user or not user.reset_code or user.reset_code != code:
            flash("Invalid or expired reset code.", "error")
            return redirect(url_for("verify_code"))

        if datetime.utcnow() > user.reset_expiration:
            flash("Reset code has expired.", "error")
            return redirect(url_for("forgot_password"))

        # ✅ Valid code — proceed to set password, but DO NOT flash success yet
        return redirect(url_for("set_new_password"))

    return render_template("verify_code.html")

@app.route("/set-new-password", methods=["GET", "POST"])
def set_new_password():
    email = session.get("reset_email")
    user = User.query.filter_by(email=email).first()

    if not user:
        flash("Session expired. Please try again.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm = request.form.get("confirm")

        if new_password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for("set_new_password"))

        hashed_pw = bcrypt.generate_password_hash(new_password).decode("utf-8")
        user.password = hashed_pw
        user.reset_code = None
        user.reset_expiration = None
        db.session.commit()

        flash("Password reset successfully!", "success")
        return redirect(url_for("login_page"))

    return render_template("set_new_password.html")

@app.route('/is_blocked', methods=['POST'])
def is_blocked():
    data = request.get_json()
    url = data.get("url", "")
    normalized = normalize_url(url)
    domain = urlparse(normalized).netloc
    ip = socket.gethostbyname(domain)

    if (
        db.session.query(BlacklistURL).filter_by(url=normalized).first() or
        db.session.query(BlacklistDomain).filter_by(domain=domain).first() or
        db.session.query(BlacklistIP).filter_by(ip_address=ip).first()
    ):
        return jsonify({'blocked': True})
    
    return jsonify({'blocked': False})

@app.route('/get_recent_scan')
@login_required
def get_recent_scan():
    recent_scan = PhishingURL.query.filter_by(user_id=current_user.id)\
                                   .order_by(PhishingURL.timestamp.desc()).first()
    if recent_scan:
        return jsonify({
            "url": recent_scan.url,
            "result": recent_scan.result,
            "timestamp": recent_scan.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify({"result": "Unknown"})

@app.route('/clear_scan_history', methods=['POST'])
@login_required
def clear_scan_history():
    try:
        PhishingURL.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        print("Error clearing scan history:", e)
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route("/api/scan-history", methods=["GET"])
@login_required
def api_scan_history():
    filter_type = request.args.get("filter", "7days")
    now = datetime.utcnow()
    if filter_type == "7days":
        start_date = now - timedelta(days=7)
    elif filter_type == "1m":
        start_date = now - timedelta(days=30)
    elif filter_type == "1y":
        start_date = now - timedelta(days=365)
    else:
        start_date = now - timedelta(days=7)

    scans = (
    PhishingURL.query.filter(
        PhishingURL.user_id == current_user.id,
        PhishingURL.created_at >= start_date
    )
    .order_by(PhishingURL.created_at.desc())
    .all()
)


    history = []
    for scan in scans:
        history.append({
            "url": scan.url,
            "domain": scan.domain or "-",
            "ip_address": scan.ip_address or "-",
            "result": scan.result
        })

    return jsonify({"history": history})

    # --- Prepare data for frontend ---
    history = []
    safe_count = 0
    phishing_count = 0
    blocked_count = 0

    for scan in scans:
        history.append({
            "url": scan.url,
            "domain": scan.domain or "-",
            "ip_address": scan.ip_address or "-",
            "result": scan.result or "Unknown",
            "timestamp": scan.timestamp.strftime("%Y-%m-%d %H:%M"),
            "blocked": scan.blocked if hasattr(scan, "blocked") else False
        })

        if scan.result == "Safe":
            safe_count += 1
        elif scan.result == "Phish":
            phishing_count += 1

        if hasattr(scan, "blocked") and scan.blocked:
            blocked_count += 1

    return jsonify({
        "history": history,
        "stats": {
            "safe": safe_count,
            "phish": phishing_count,
            "blocked": blocked_count
        }
    })

@app.route('/api/chart-data/<period>')
@login_required
def chart_data(period):
    from datetime import datetime, timedelta
    from sqlalchemy import extract, func
    from calendar import month_name

    now = datetime.utcnow()
    user_id = current_user.id

    labels = []
    data = []

    # --- 7-day chart ---
    if period == "7d":
        start_date = now - timedelta(days=6)  # last 7 days including today
        rows = (
            db.session.query(
                func.date(BlockedURL.added_on).label("day"),
                func.count().label("count")
            )
            .filter(BlockedURL.user_id == user_id, BlockedURL.added_on >= start_date)
            .group_by(func.date(BlockedURL.added_on))
            .order_by(func.date(BlockedURL.added_on))
            .all()
        )
        counts = {row.day: row.count for row in rows}

        for i in range(7):
            day = (start_date + timedelta(days=i)).date()
            labels.append(day.strftime("%b %d"))  # e.g., "Aug 26"
            data.append(counts.get(day, 0))

    # --- 1-month chart (weekly) ---
    elif period == "1m":
        start_date = now - timedelta(days=30)
        rows = (
            db.session.query(
                extract("year", BlockedURL.added_on).label("year"),
                extract("month", BlockedURL.added_on).label("month"),
                func.floor((extract("day", BlockedURL.added_on)-1)/7 + 1).label("week_of_month"),
                func.count().label("count")
            )
            .filter(BlockedURL.user_id == user_id, BlockedURL.added_on >= start_date)
            .group_by(
                extract("year", BlockedURL.added_on),
                extract("month", BlockedURL.added_on),
                func.floor((extract("day", BlockedURL.added_on)-1)/7 + 1)
            )
            .order_by(
                extract("year", BlockedURL.added_on),
                extract("month", BlockedURL.added_on),
                func.floor((extract("day", BlockedURL.added_on)-1)/7 + 1)
            )
            .all()
        )

        counts = {(int(r.year), int(r.month), int(r.week_of_month)): r.count for r in rows}

        # Generate labels week by week from start_date to now
        current = start_date
        while current <= now:
            y, m, d = current.year, current.month, current.day
            week_of_month = (d - 1) // 7 + 1
            # Determine suffix
            suffix = "th"
            if week_of_month == 1: suffix = "st"
            elif week_of_month == 2: suffix = "nd"
            elif week_of_month == 3: suffix = "rd"
            label = f"{month_name[m]} {week_of_month}{suffix} Week"
            labels.append(label)
            data.append(counts.get((y, m, week_of_month), 0))
            current += timedelta(days=7)

    # --- 1-year chart (monthly) ---
    elif period == "1y":
        start_date = now - timedelta(days=365)
        rows = (
            db.session.query(
                extract("month", BlockedURL.added_on).label("month"),
                func.count().label("count")
            )
            .filter(BlockedURL.user_id == user_id, BlockedURL.added_on >= start_date)
            .group_by(extract("month", BlockedURL.added_on))
            .order_by(extract("month", BlockedURL.added_on))
            .all()
        )

        counts = {int(r.month): r.count for r in rows}
        for i in range(1, 13):
            labels.append(month_name[i])
            data.append(counts.get(i, 0))

    else:
        return jsonify({"labels": [], "data": []})

    return jsonify({"labels": labels, "data": data})

@app.route('/check_urls_batch', methods=['POST'])
def check_urls_batch():
    import logging
    import pandas as pd
    from joblib import Parallel, delayed
    import multiprocessing
    from flask import request, jsonify

    data = request.get_json()
    urls = data.get('urls', [])
    if not urls:
        return jsonify({"results": [], "error": "No URLs provided"}), 400

    def predict_single(u):
        try:
            # Extract features (skip WHOIS if not needed)
            features = extract_url_features(u)
            df = pd.DataFrame([[features[f] for f in FEATURE_NAMES]], columns=FEATURE_NAMES)
            pred = rf_model.predict(df)[0]
            return {"url": u, "result": "phish" if pred == 1 else "safe"}
        except Exception as e:
            logging.error(f"Error scanning {u}: {e}")
            return {"url": u, "result": "Unknown"}

    # Run in parallel for speed
    n_jobs = min(len(urls), multiprocessing.cpu_count())
    results = Parallel(n_jobs=n_jobs)(delayed(predict_single)(u) for u in urls)

    # Ensure all URLs are returned, even if errors occurred
    return jsonify({"results": results})


if __name__ == '__main__':
    socketio.run(app, debug=True)
