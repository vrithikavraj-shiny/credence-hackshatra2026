import hashlib
import uuid
import qrcode
from datetime import datetime, timezone
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)
from functools import wraps
from pathlib import Path
import json
import os

app = Flask(__name__)

app.secret_key = os.environ.get(
    "CREDENCE_SECRET_KEY",
    "development-key-change-before-deployment"
)

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "database.json"

# DATABASE FUNCTIONS

def load_database():
    if not DB_FILE.exists():
        return {
            "users": [],
            "certificates": [],
            "ledger": []
        }

    with open(DB_FILE, "r", encoding="utf-8") as file:
        return json.load(file)

def save_database(data):
    temp_file = DB_FILE.with_suffix(".tmp")

    with open(temp_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    os.replace(temp_file, DB_FILE)

# CREATE DEMONSTRATION ACCOUNTS

# CREATE AND UPDATE DEMONSTRATION ACCOUNTS

def initialize_users():

    db = load_database()

    db.setdefault("users", [])
    db.setdefault("certificates", [])
    db.setdefault("ledger", [])

    demo_accounts = [
        {
            "username": "admin",
            "password": "Admin@123",
            "role": "staff"
        },
        {
            "username": "employer",
            "password": "Employer@123",
            "role": "verifier"
        }
    ]

    for account in demo_accounts:

        existing_user = next(
            (
                user for user in db["users"]
                if user.get("username") == account["username"]
            ),
            None
        )

        if existing_user:

            existing_user["password"] = generate_password_hash(
                account["password"]
            )

            existing_user["role"] = account["role"]

        else:

            db["users"].append({
                "username": account["username"],
                "password": generate_password_hash(
                    account["password"]
                ),
                "role": account["role"]
            })

    save_database(db)


initialize_users()

# GENERATE CERTIFICATE FINGERPRINT

def generate_certificate_hash(certificate):

    data = json.dumps(
        certificate,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        data.encode("utf-8")
    ).hexdigest()


# ADD TRANSACTION TO LEDGER

def add_ledger_entry(action, certificate_id):


    db = load_database()

    ledger = db["ledger"]

    previous_hash = (
        ledger[-1]["hash"] if ledger else "GENESIS"
    )

    block = {
        "block_id": len(ledger) + 1,
        "action": action,
        "certificate_id": certificate_id,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "previous_hash": previous_hash
    }

    block_data = json.dumps(
        block,
        sort_keys=True,
        separators=(",", ":")
    )

    block["hash"] = hashlib.sha256(
        block_data.encode("utf-8")
    ).hexdigest()

    ledger.append(block)

    save_database(db)

# VERIFY LEDGER INTEGRITY

def verify_ledger_integrity():

    db = load_database()
    ledger = db.get("ledger", [])

    previous_hash = "GENESIS"
    errors = []

    for index, block in enumerate(ledger):

        # Check block number
        if block.get("block_id") != index + 1:
            errors.append(
                f"Block {index + 1}: Invalid block ID"
            )

        # Check previous block hash
        if block.get("previous_hash") != previous_hash:
            errors.append(
                f"Block {index + 1}: Previous hash mismatch"
            )

        # Recalculate current block hash
        block_data = block.copy()
        recorded_hash = block_data.pop("hash", None)

        data = json.dumps(
            block_data,
            sort_keys=True,
            separators=(",", ":")
        )

        calculated_hash = hashlib.sha256(
            data.encode("utf-8")
        ).hexdigest()

        if recorded_hash != calculated_hash:
            errors.append(
                f"Block {index + 1}: Hash mismatch"
            )

        previous_hash = recorded_hash

    return {
        "valid": len(errors) == 0,
        "total_blocks": len(ledger),
        "errors": errors
    }



# GENERATE QR CODE

def generate_qr_code(certificate_id):

    verification_url = url_for(
        "verify_certificate",
        certificate_id=certificate_id,
        _external=True
    )

    qr = qrcode.make(verification_url)

    qr_path = BASE_DIR / "static" /"images"/ (
        certificate_id + ".png"
    )

    qr_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    qr.save(qr_path)

    return "images/" + certificate_id + ".png"

# ROLE PROTECTION

def role_required(required_role):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):

            if "username" not in session:
                return redirect(url_for("home"))

            if session.get("role") != required_role:
                return "Access Denied", 403

            return function(*args, **kwargs)

        return wrapper
    return decorator

# HOMEPAGE

@app.route("/")
def home():
    return render_template("index.html")

# LOGIN FUNCTION

def authenticate_user(required_role, dashboard):

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Please enter both username and password.")
        return redirect(request.referrer or url_for("home"))

    db = load_database()

    for user in db["users"]:

        if user["username"] == username:

            if (
                user["role"] == required_role
                and check_password_hash(
                    user["password"], password
                )
            ):

                session.clear()
                session["username"] = username
                session["role"] = required_role

                return redirect(url_for(dashboard))

    flash("Invalid username or password.")
    return redirect(request.referrer or url_for("home"))

# STAFF LOGIN

@app.route("/staff-login", methods=["GET", "POST"])
def staff_login():

    if request.method == "POST":
        return authenticate_user(
            "staff", "staff_dashboard"
        )

    return render_template("staff_login.html")

# VERIFIER LOGIN

@app.route("/verifier-login", methods=["GET", "POST"])
def verifier_login():

    if request.method == "POST":
        return authenticate_user(
            "verifier", "verifier_dashboard"
        )

    return render_template("verifier_login.html")

# STAFF DASHBOARD

@app.route("/staff-dashboard")
@role_required("staff")
def staff_dashboard():
    return render_template("staff_dashboard.html")

# VERIFIER DASHBOARD

@app.route("/verifier-dashboard")
@role_required("verifier")
def verifier_dashboard():
    return render_template("verifier_dashboard.html")
# CERTIFICATE VERIFICATION ROUTE


# CERTIFICATE VERIFICATION ROUTE

@app.route("/verify/<certificate_id>")
def verify_certificate(certificate_id):

    db = load_database()

    certificate = next(
        (
            cert for cert in db["certificates"]
            if cert["certificate_id"] == certificate_id
        ),
        None
    )

    if certificate is None:
        return render_template(
            "verify_certificate.html",
            certificate=None
        ), 404

    # RECORD SUCCESSFUL VERIFICATION
    add_ledger_entry(
        "VERIFY",
        certificate_id
    )

    # DISPLAY CERTIFICATE
    return render_template(
        "verify_certificate.html",
        certificate=certificate
    )

# ISSUE CERTIFICATE

@app.route("/issue-certificate", methods=["GET", "POST"])
@role_required("staff")
def issue_certificate():

    if request.method == "POST":

        student_name = request.form.get(
            "student_name", ""
        ).strip()

        student_id = request.form.get(
            "student_id", ""
        ).strip()

        qualification = request.form.get(
            "qualification", ""
        ).strip()

        department = request.form.get(
            "department", ""
        ).strip()

        university = request.form.get(
            "university", ""
        ).strip()

        graduation_year = request.form.get(
            "graduation_year", ""
        ).strip()

        if not all([
            student_name,
            student_id,
            qualification,
            department,
            university,
            graduation_year
        ]):
            flash("Please complete all fields.")
            return redirect(url_for("issue_certificate"))

        try:
            year = int(graduation_year)

            if not 1900 <= year <= 2100:
                raise ValueError

        except ValueError:
            flash("Enter a valid graduation year.")
            return redirect(url_for("issue_certificate"))

        db = load_database()

        certificate_id = "NSU-" + uuid.uuid4().hex[:10].upper()

        certificate = {
            "certificate_id": certificate_id,
            "student_name": student_name,
            "student_id": student_id,
            "qualification": qualification,
            "department": department,
            "university": university,
            "graduation_year": year,
            "issue_date": datetime.now(
                timezone.utc
            ).date().isoformat(),
            "status": "ACTIVE"
        }

        # Generate SHA-256 fingerprint
        certificate["fingerprint"] = (
            generate_certificate_hash(certificate)
        )

        # Generate QR code
        certificate["qr_code"] = generate_qr_code(
            certificate_id
        )

        # Save certificate
        db["certificates"].append(certificate)

        save_database(db)

        # Record issuance
        add_ledger_entry(
            "ISSUE",
            certificate_id
        )

        return render_template(
            "issue_certificate.html",
            success=True,
            certificate=certificate
        )

    return render_template("issue_certificate.html")
# CERTIFICATE REGISTRY

@app.route("/certificate-registry")
@role_required("staff")
def certificate_registry():

    db = load_database()

    search = request.args.get("search", "").strip().lower()

    certificates = db.get("certificates", [])

    if search:
        certificates = [
            cert for cert in certificates
            if search in cert.get("student_name", "").lower()
            or search in cert.get("certificate_id", "").lower()
        ]

    return render_template(
        "certificate_registry.html",
        certificates=certificates,
        search=search
    )

# REVOKE CERTIFICATE

@app.route(
    "/revoke-certificate/<certificate_id>",
    methods=["POST"]
)
@role_required("staff")
def revoke_certificate(certificate_id):

    db = load_database()

    certificate = next(
        (
            cert for cert in db["certificates"]
            if cert["certificate_id"] == certificate_id
        ),
        None
    )

    if certificate is None:
        flash("Certificate not found.")
        return redirect(url_for("certificate_registry"))

    if certificate["status"] == "ACTIVE":

        certificate["status"] = "REVOKED"

        save_database(db)

        add_ledger_entry(
            "REVOKE",
            certificate_id
        )

        flash("Certificate successfully revoked.")

    else:
        flash("This certificate is already revoked.")

    return redirect(url_for("certificate_registry"))


# EMPLOYER QR SCANNER PAGE

@app.route("/qr-scanner")
@role_required("verifier")
def qr_scanner():

    return render_template("qr_scanner.html")
# EMPLOYER CERTIFICATE SEARCH

@app.route("/verify-certificate", methods=["GET"])
@role_required("verifier")
def verifier_search():

    certificate_id = request.args.get(
        "certificate_id", ""
    ).strip()

    if not certificate_id:
        flash("Please enter a certificate ID.")
        return redirect(url_for("verifier_dashboard"))

    return redirect(
        url_for(
            "verify_certificate",
            certificate_id=certificate_id
        )
    )

# STAFF LEDGER DASHBOARD

@app.route("/ledger")
@role_required("staff")
def ledger():

    db = load_database()

    integrity = verify_ledger_integrity()

    return render_template(
        "ledger.html",
        ledger=db.get("ledger", []),
        integrity=integrity
    )

# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)