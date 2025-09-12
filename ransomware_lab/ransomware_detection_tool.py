import os
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, abort
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
import json

# ---------------- Config ---------------- #
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ransomware_lab.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)

db = SQLAlchemy(app)

QUARANTINE_DIR = "quarantine"
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# ---------------- Models ---------------- #
class DetectionEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.String(32), nullable=False)  # store as string for simplicity
    filename = db.Column(db.String(1024), nullable=False)
    process = db.Column(db.String(512), nullable=False)
    action = db.Column(db.String(512), nullable=False)
    status = db.Column(db.String(32), nullable=False)
    reasons = db.Column(db.String(2048), nullable=True)  # JSON string list
    quarantined = db.Column(db.Boolean, default=False)
    quarantine_path = db.Column(db.String(1024), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "time": self.time,
            "filename": self.filename,
            "process": self.process,
            "action": self.action,
            "status": self.status,
            "reasons": json.loads(self.reasons) if self.reasons else [],
            "quarantined": self.quarantined,
            "quarantine_path": self.quarantine_path
        }

# Create DB if not exists
with app.app_context():
    db.create_all()

# ---------------- Demo users ---------------- #
VALID_USERS = {
    "analyst": "password123",
    "admin": "adminpass"
}

# ---------------- Detection Logic ---------------- #
def detect_attack(filename, process, action):
    reasons = []
    if filename and filename.lower().endswith((".locked", ".enc", ".crypt")):
        reasons.append("File has ransomware-like extension")
    if process and any(word in process.lower() for word in ["encrypt", "ransom", "locker"]):
        reasons.append("Suspicious process name")
    if action and action.lower() in ["mass encryption", "delete backups"]:
        reasons.append("Dangerous action detected")
    return reasons

def create_quarantine_marker(entry_time, filename, process, action, reasons):
    safe_name = filename.replace("/", "_").replace(" ", "_")[:200]
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    qfile = f"quarantined_{timestamp}_{safe_name}.txt"
    qpath = os.path.join(QUARANTINE_DIR, qfile)
    try:
        with open(qpath, "w", encoding="utf-8") as f:
            f.write(f"Quarantined at {entry_time}\n")
            f.write(f"Original filename: {filename}\n")
            f.write(f"Process: {process}\n")
            f.write(f"Action: {action}\n\n")
            f.write("Reasons:\n")
            for r in reasons:
                f.write(f" - {r}\n")
        return qpath
    except Exception as e:
        return f"ERROR_CREATING_QUARANTINE: {e}"

# ---------------- Web Routes ---------------- #
@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username in VALID_USERS and VALID_USERS[username] == password:
        session["user"] = username
        return redirect(url_for("dashboard"))
    else:
        flash("Invalid username or password")
        return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if not session.get("user"):
        return redirect(url_for("index"))
    return render_template("dashboard.html", user=session["user"])

@app.route("/clear_logs")
def clear_logs():
    if not session.get("user"):
        return redirect(url_for("index"))
    db.session.query(DetectionEvent).delete()
    db.session.commit()
    flash("All logs cleared!")
    return redirect(url_for("dashboard"))


# Web form submit (reuses API internally)
@app.route("/detect", methods=["POST"])
def detect_form():
    if not session.get("user"):
        return redirect(url_for("index"))

    filename = request.form.get("filename", "").strip()
    process = request.form.get("process", "").strip()
    action = request.form.get("action", "").strip()

    # call internal helper to store
    result = store_detection_event(filename, process, action)
    flash(f"Event analyzed: {result['status']}")
    return redirect(url_for("dashboard"))

# ---------------- API Endpoints ---------------- #
@app.route("/api/detect", methods=["POST"])
def api_detect():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    payload = request.get_json()
    filename = payload.get("filename", "").strip()
    process = payload.get("process", "").strip()
    action = payload.get("action", "").strip()
    result = store_detection_event(filename, process, action)
    return jsonify(result), 201

@app.route("/api/logs", methods=["GET"])
def api_logs():
    # optional query params: ?limit=50&offset=0&status=Suspicious
    q = DetectionEvent.query
    status = request.args.get("status")
    if status:
        q = q.filter_by(status=status)
    q = q.order_by(DetectionEvent.id.desc())
    limit = min(int(request.args.get("limit", 200)), 1000)
    offset = int(request.args.get("offset", 0))
    items = q.offset(offset).limit(limit).all()
    return jsonify([item.to_dict() for item in items])

@app.route("/api/logs/<int:event_id>", methods=["GET"])
def api_log_item(event_id):
    item = DetectionEvent.query.get_or_404(event_id)
    return jsonify(item.to_dict())

# ---------------- Helper to store events ---------------- #
def store_detection_event(filename, process, action):
    entry_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reasons = detect_attack(filename, process, action)
    status = "Suspicious" if reasons else "Normal"
    quarantine_path = None
    quarantined = False

    if status == "Suspicious":
        quarantine_path = create_quarantine_marker(entry_time, filename, process, action, reasons)
        quarantined = True

    ev = DetectionEvent(
        time=entry_time,
        filename=filename,
        process=process,
        action=action,
        status=status,
        reasons=json.dumps(reasons),
        quarantined=quarantined,
        quarantine_path=quarantine_path
    )
    try:
        db.session.add(ev)
        db.session.commit()
        return {"id": ev.id, "status": status, "reasons": reasons, "quarantined": quarantined, "quarantine_path": quarantine_path}
    except SQLAlchemyError as e:
        db.session.rollback()
        return {"error": str(e)}

# ---------------- Main ---------------- #
if __name__ == "__main__":
    # Development only: debug=True
    app.run(host="0.0.0.0", port=5000, debug=True)
