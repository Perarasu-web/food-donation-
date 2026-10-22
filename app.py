import os, math, sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-development-secret")
DB_PATH = os.path.join(os.path.dirname(__file__), "food_donation.db")
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('donor','trust','admin')),
      phone TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS trusts (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      organization_name TEXT NOT NULL, address TEXT NOT NULL, city TEXT NOT NULL,
      latitude REAL, longitude REAL, verified INTEGER NOT NULL DEFAULT 0,
      description TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS donations (
      id INTEGER PRIMARY KEY AUTOINCREMENT, donor_id INTEGER NOT NULL REFERENCES users(id),
      food_name TEXT NOT NULL, food_type TEXT NOT NULL, quantity_kg REAL NOT NULL,
      servings INTEGER, prepared_at TEXT NOT NULL, storage_method TEXT NOT NULL,
      storage_temp_c REAL, pickup_deadline TEXT NOT NULL, address TEXT NOT NULL, city TEXT NOT NULL,
      latitude REAL, longitude REAL, notes TEXT, image_filename TEXT,
      safety_ack INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'Available',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT, donation_id INTEGER NOT NULL REFERENCES donations(id),
      trust_id INTEGER NOT NULL REFERENCES trusts(id), message TEXT, status TEXT NOT NULL DEFAULT 'Pending',
      created_at TEXT NOT NULL, UNIQUE(donation_id, trust_id)
    );
    CREATE TABLE IF NOT EXISTS tracking (
      id INTEGER PRIMARY KEY AUTOINCREMENT, donation_id INTEGER NOT NULL REFERENCES donations(id),
      status TEXT NOT NULL, note TEXT, updated_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
      message TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
    );
    """)
    # Development-only demo accounts. Passwords are documented in README.
    now = datetime.now().isoformat(timespec="minutes")
    demo_users = [
      ("Demo Donor", "donor@example.com", generate_password_hash("Demo123!"), "donor", "0000000000"),
      ("Demo Trust User", "trust@example.com", generate_password_hash("Demo123!"), "trust", "0000000000"),
      ("Demo Admin", "admin@example.com", generate_password_hash("Admin123!"), "admin", "0000000000")
    ]
    for row in demo_users:
        conn.execute("INSERT OR IGNORE INTO users(name,email,password_hash,role,phone,created_at) VALUES(?,?,?,?,?,?)", (*row, now))
    trust_user = conn.execute("SELECT id FROM users WHERE email='trust@example.com'").fetchone()[0]
    conn.execute("""INSERT OR IGNORE INTO trusts(user_id,organization_name,address,city,latitude,longitude,verified,description,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                 (trust_user, "Demo Community Trust (Sample)", "Demo address — replace with verified address", "Salem",
                  11.6643, 78.1460, 1, "DEMO DATA ONLY — not a real organization or contact address.", now))
    conn.commit()
    conn.close()

def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("You do not have permission to access that page.", "danger")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)
        return wrapped
    return decorator

def notify(user_id, message):
    db().execute("INSERT INTO notifications(user_id,message,created_at) VALUES(?,?,?)",
                 (user_id, message, datetime.now().isoformat(timespec="minutes")))
    db().commit()

def haversine(lat1, lon1, lat2, lon2):
    if None in (lat1, lon1, lat2, lon2): return None
    r = 6371
    p1, p2 = math.radians(float(lat1)), math.radians(float(lat2))
    dlat, dlon = math.radians(float(lat2)-float(lat1)), math.radians(float(lon2)-float(lon1))
    a = math.sin(dlat/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dlon/2)**2
    return 2*r*math.asin(math.sqrt(a))

def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.context_processor
def common_context():
    count = 0
    if session.get("user_id"):
        row = db().execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0",
                           (session["user_id"],)).fetchone()
        count = row[0]
    return {"notification_count": count}

@app.route("/")
def index():
    stats = {
      "donations": db().execute("SELECT COUNT(*) FROM donations WHERE status IN ('Accepted','Picked Up','Delivered')").fetchone()[0],
      "kg": db().execute("SELECT COALESCE(SUM(quantity_kg),0) FROM donations WHERE status IN ('Accepted','Picked Up','Delivered')").fetchone()[0],
      "trusts": db().execute("SELECT COUNT(*) FROM trusts WHERE verified=1").fetchone()[0]
    }
    return render_template("index.html", stats=stats)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        role = request.form.get("role","donor")
        phone = request.form.get("phone","").strip()
        if not name or not email or len(password) < 8 or role not in ("donor","trust"):
            flash("Enter valid details. Password must be at least 8 characters.", "danger")
            return render_template("register.html")
        try:
            cur = db().execute("INSERT INTO users(name,email,password_hash,role,phone,created_at) VALUES(?,?,?,?,?,?)",
                (name,email,generate_password_hash(password),role,phone,datetime.now().isoformat(timespec="minutes")))
            db().commit()
            session.update(user_id=cur.lastrowid, name=name, role=role)
            if role == "trust":
                flash("Account created. Please complete your organization profile for admin verification.", "success")
                return redirect(url_for("trust_profile"))
            flash("Welcome! Your donor account is ready.", "success")
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("That email is already registered.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        user = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form.get("password","")):
            session.clear()
            session.update(user_id=user["id"], name=user["name"], role=user["role"])
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required()
def dashboard():
    user_id, role = session["user_id"], session["role"]
    if role == "donor":
        donations = db().execute("SELECT * FROM donations WHERE donor_id=? ORDER BY id DESC", (user_id,)).fetchall()
        return render_template("donor_dashboard.html", donations=donations)
    if role == "trust":
        trust = db().execute("SELECT * FROM trusts WHERE user_id=?", (user_id,)).fetchone()
        if not trust:
            return redirect(url_for("trust_profile"))
        donations = db().execute("""SELECT d.*, u.name AS donor_name FROM donations d JOIN users u ON u.id=d.donor_id
          WHERE d.status='Available' ORDER BY d.created_at DESC""").fetchall()
        reqs = db().execute("""SELECT r.*, d.food_name, d.quantity_kg, d.pickup_deadline, t.organization_name
          FROM requests r JOIN donations d ON d.id=r.donation_id JOIN trusts t ON t.id=r.trust_id
          WHERE r.trust_id=? ORDER BY r.id DESC""", (trust["id"],)).fetchall()
        return render_template("trust_dashboard.html", trust=trust, donations=donations, requests=reqs)
    return redirect(url_for("admin_dashboard"))

@app.route("/trust/profile", methods=["GET","POST"])
@login_required("trust")
def trust_profile():
    if request.method == "POST":
        name = request.form.get("organization_name","").strip()
        address = request.form.get("address","").strip()
        city = request.form.get("city","").strip()
        phone = request.form.get("phone","").strip()
        description = request.form.get("description","").strip()
        try:
            lat = float(request.form.get("latitude") or 0) or None
            lon = float(request.form.get("longitude") or 0) or None
        except ValueError:
            lat = lon = None
        if not name or not address or not city:
            flash("Organization name, address, and city are required.", "danger")
        else:
            db().execute("UPDATE users SET phone=? WHERE id=?", (phone, session["user_id"]))
            db().execute("""INSERT INTO trusts(user_id,organization_name,address,city,latitude,longitude,verified,description,created_at)
              VALUES(?,?,?,?,?,?,0,?,?) ON CONFLICT(user_id) DO UPDATE SET organization_name=excluded.organization_name,
              address=excluded.address,city=excluded.city,latitude=excluded.latitude,longitude=excluded.longitude,
              description=excluded.description""",
              (session["user_id"],name,address,city,lat,lon,description,datetime.now().isoformat(timespec="minutes")))
            db().commit()
            flash("Profile saved. The trust remains unverified until an admin checks it.", "success")
            return redirect(url_for("dashboard"))
    trust = db().execute("SELECT * FROM trusts WHERE user_id=?", (session["user_id"],)).fetchone()
    user = db().execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return render_template("trust_profile.html", trust=trust, user=user)

@app.route("/donations/new", methods=["GET","POST"])
@login_required("donor")
def new_donation():
    if request.method == "POST":
        f = request.form
        required = ["food_name","food_type","quantity_kg","prepared_at","storage_method","pickup_deadline","address","city"]
        if any(not f.get(k,"").strip() for k in required) or not f.get("safety_ack"):
            flash("Complete all required fields and confirm the food safety checklist.", "danger")
            return render_template("new_donation.html", form=f)
        try:
            qty = float(f["quantity_kg"])
            if qty <= 0: raise ValueError()
            servings = int(f.get("servings") or 0) or None
            temp = float(f.get("storage_temp_c") or 0)
            lat = float(f.get("latitude") or 0) or None
            lon = float(f.get("longitude") or 0) or None
        except ValueError:
            flash("Quantity, servings, temperature, or location values are invalid.", "danger")
            return render_template("new_donation.html", form=f)
        image_name = None
        upload = request.files.get("image")
        if upload and upload.filename:
            if not allowed_image(upload.filename):
                flash("Upload a PNG, JPG, JPEG, or WEBP image only.", "danger")
                return render_template("new_donation.html", form=f)
            image_name = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{upload.filename}")
            upload.save(os.path.join(app.config["UPLOAD_FOLDER"], image_name))
        cur = db().execute("""INSERT INTO donations(donor_id,food_name,food_type,quantity_kg,servings,prepared_at,storage_method,
          storage_temp_c,pickup_deadline,address,city,latitude,longitude,notes,image_filename,safety_ack,status,created_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (session["user_id"],f["food_name"].strip(),f["food_type"],qty,servings,f["prepared_at"],f["storage_method"],
           temp if f.get("storage_temp_c") else None,f["pickup_deadline"],f["address"].strip(),f["city"].strip(),lat,lon,
           f.get("notes","").strip(),image_name,1,"Available",datetime.now().isoformat(timespec="minutes")))
        donation_id = cur.lastrowid
        db().execute("INSERT INTO tracking(donation_id,status,note,updated_by,created_at) VALUES(?,?,?,?,?)",
                     (donation_id,"Available","Donation listed; safety details provided by donor.",session["user_id"],datetime.now().isoformat(timespec="minutes")))
        db().commit()
        flash("Donation listed. Nearby verified trusts can now view it. This app does not independently certify food safety.", "success")
        return redirect(url_for("nearby_trusts", donation_id=donation_id))
    return render_template("new_donation.html", form={})

@app.route("/nearby-trusts")
@login_required("donor")
def nearby_trusts():
    donation_id = request.args.get("donation_id", type=int)
    donation = None
    if donation_id:
        donation = db().execute("SELECT * FROM donations WHERE id=? AND donor_id=?", (donation_id,session["user_id"])).fetchone()
    trusts = db().execute("SELECT * FROM trusts WHERE verified=1 ORDER BY organization_name").fetchall()
    donor_lat = request.args.get("lat", type=float) or (donation["latitude"] if donation else None)
    donor_lon = request.args.get("lon", type=float) or (donation["longitude"] if donation else None)
    items = []
    for t in trusts:
        dist = haversine(donor_lat,donor_lon,t["latitude"],t["longitude"])
        items.append({"trust": dict(t), "distance": dist})
    items.sort(key=lambda x: x["distance"] if x["distance"] is not None else 10**9)
    

    items = [dict(row) for row in items] if items else []

    if donation is not None:
      donation = dict(donation)
      

    return render_template("nearby_trusts.html", items=items, donation=donation, donor_lat=donor_lat, donor_lon=donor_lon)

@app.route("/donations/<int:donation_id>/request", methods=["POST"])
@login_required("donor")
def send_request(donation_id):
    trust_id = request.form.get("trust_id", type=int)
    donation = db().execute("SELECT * FROM donations WHERE id=? AND donor_id=? AND status='Available'",
                            (donation_id,session["user_id"])).fetchone()
    trust = db().execute("SELECT * FROM trusts WHERE id=? AND verified=1", (trust_id,)).fetchone()
    if not donation or not trust:
        flash("Donation or verified trust could not be found.", "danger")
        return redirect(url_for("nearby_trusts", donation_id=donation_id))
    try:
        db().execute("INSERT INTO requests(donation_id,trust_id,message,status,created_at) VALUES(?,?,?,?,?)",
          (donation_id,trust_id,request.form.get("message","").strip(),"Pending",datetime.now().isoformat(timespec="minutes")))
        db().commit()
        notify(trust["user_id"], f"New donation request: {donation['food_name']} ({donation['quantity_kg']} kg).")
        flash("Donation request sent to the trust.", "success")
    except sqlite3.IntegrityError:
        flash("You have already requested this trust for this donation.", "warning")
    return redirect(url_for("dashboard"))

@app.route("/requests/<int:req_id>/<action>", methods=["POST"])
@login_required("trust")
def handle_request(req_id, action):
    trust = db().execute("SELECT * FROM trusts WHERE user_id=?", (session["user_id"],)).fetchone()
    if not trust:
        flash("Complete your trust profile first.", "warning"); return redirect(url_for("trust_profile"))
    req = db().execute("SELECT * FROM requests WHERE id=? AND trust_id=?", (req_id,trust["id"])).fetchone()
    if not req or action not in ("accept","reject"):
        flash("Request not found.", "danger"); return redirect(url_for("dashboard"))
    if action == "accept":
        db().execute("UPDATE requests SET status='Accepted' WHERE id=?", (req_id,))
        db().execute("UPDATE donations SET status='Accepted' WHERE id=? AND status='Available'", (req["donation_id"],))
        status, msg = "Accepted", "Your food donation request was accepted."
    else:
        db().execute("UPDATE requests SET status='Rejected' WHERE id=?", (req_id,))
        status, msg = "Rejected", "A trust rejected your donation request."
    db().execute("INSERT INTO tracking(donation_id,status,note,updated_by,created_at) VALUES(?,?,?,?,?)",
      (req["donation_id"],status,f"Trust request {status.lower()}.",session["user_id"],datetime.now().isoformat(timespec="minutes")))
    donor_id = db().execute("SELECT donor_id FROM donations WHERE id=?", (req["donation_id"],)).fetchone()[0]
    db().commit(); notify(donor_id,msg)
    flash(f"Request {status.lower()}.", "success")
    return redirect(url_for("dashboard"))

@app.route("/donations/<int:donation_id>/status", methods=["POST"])
@login_required()
def update_status(donation_id):
    status = request.form.get("status")
    allowed = ["Picked Up","Delivered"]
    donation = db().execute("SELECT * FROM donations WHERE id=?", (donation_id,)).fetchone()
    if not donation:
        flash("Donation not found.", "danger"); return redirect(url_for("dashboard"))
    trust = db().execute("SELECT * FROM trusts WHERE user_id=?", (session["user_id"],)).fetchone() if session["role"]=="trust" else None
    req = db().execute("SELECT 1 FROM requests WHERE donation_id=? AND trust_id=? AND status='Accepted'",
                       (donation_id,trust["id"])).fetchone() if trust else None
    if not (session["role"]=="admin" or (session["role"]=="trust" and req)):
        flash("Only the accepting trust or admin can update pickup/delivery status.", "danger")
        return redirect(url_for("dashboard"))
    if status not in allowed or donation["status"] not in ("Accepted","Picked Up"):
        flash("Invalid status transition.", "danger"); return redirect(url_for("dashboard"))
    db().execute("UPDATE donations SET status=? WHERE id=?", (status,donation_id))
    db().execute("INSERT INTO tracking(donation_id,status,note,updated_by,created_at) VALUES(?,?,?,?,?)",
      (donation_id,status,"Status updated by authorized user.",session["user_id"],datetime.now().isoformat(timespec="minutes")))
    donor_id = donation["donor_id"]
    db().commit(); notify(donor_id,f"Donation #{donation_id} status updated: {status}.")
    flash(f"Donation marked {status.lower()}.", "success")
    return redirect(url_for("dashboard"))

@app.route("/donations/<int:donation_id>/cancel", methods=["POST"])
@login_required("donor")
def cancel_donation(donation_id):
    d = db().execute("SELECT * FROM donations WHERE id=? AND donor_id=?", (donation_id,session["user_id"])).fetchone()
    if not d or d["status"] != "Available":
        flash("Only an available, not-yet-accepted donation can be cancelled.", "danger")
    else:
        db().execute("UPDATE donations SET status='Cancelled' WHERE id=?", (donation_id,))
        db().execute("INSERT INTO tracking(donation_id,status,note,updated_by,created_at) VALUES(?,?,?,?,?)",
          (donation_id,"Cancelled","Cancelled by donor.",session["user_id"],datetime.now().isoformat(timespec="minutes")))
        db().commit(); flash("Donation cancelled.", "success")
    return redirect(url_for("dashboard"))

@app.route("/donations/<int:donation_id>/tracking")
@login_required()
def tracking(donation_id):
    d = db().execute("SELECT d.*, u.name AS donor_name FROM donations d JOIN users u ON u.id=d.donor_id WHERE d.id=?",
                     (donation_id,)).fetchone()
    if not d:
        flash("Donation not found.", "danger"); return redirect(url_for("dashboard"))
    if session["role"]=="donor" and d["donor_id"] != session["user_id"]:
        flash("Not allowed.", "danger"); return redirect(url_for("dashboard"))
    if session["role"]=="trust":
        t = db().execute("SELECT id FROM trusts WHERE user_id=?", (session["user_id"],)).fetchone()
        allowed = t and db().execute("SELECT 1 FROM requests WHERE donation_id=? AND trust_id=?", (donation_id,t["id"])).fetchone()
        if not allowed: flash("Not allowed.", "danger"); return redirect(url_for("dashboard"))
    events = db().execute("SELECT * FROM tracking WHERE donation_id=? ORDER BY id", (donation_id,)).fetchall()
    return render_template("tracking.html", donation=d, events=events)

@app.route("/notifications")
@login_required()
def notifications():
    rows = db().execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    db().execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (session["user_id"],)); db().commit()
    return render_template("notifications.html", rows=rows)

@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    trusts = db().execute("SELECT t.*,u.email,u.phone FROM trusts t JOIN users u ON u.id=t.user_id ORDER BY t.verified,t.id DESC").fetchall()
    donations = db().execute("SELECT d.*,u.name AS donor_name FROM donations d JOIN users u ON u.id=d.donor_id ORDER BY d.id DESC LIMIT 50").fetchall()
    stats = {"users":db().execute("SELECT COUNT(*) FROM users").fetchone()[0],
             "donations":db().execute("SELECT COUNT(*) FROM donations").fetchone()[0],
             "kg":db().execute("SELECT COALESCE(SUM(quantity_kg),0) FROM donations WHERE status IN ('Accepted','Picked Up','Delivered')").fetchone()[0]}
    return render_template("admin.html", trusts=trusts, donations=donations, stats=stats)

@app.route("/admin/trust/<int:trust_id>/<action>", methods=["POST"])
@login_required("admin")
def verify_trust(trust_id, action):
    if action not in ("verify","unverify"):
        flash("Invalid action.", "danger")
    else:
        verified = 1 if action == "verify" else 0
        db().execute("UPDATE trusts SET verified=? WHERE id=?", (verified,trust_id)); db().commit()
        flash("Trust verification updated.", "success")
    return redirect(url_for("admin_dashboard"))

@app.errorhandler(413)
def too_large(_e):
    flash("Image too large. Maximum upload size is 5 MB.", "danger")
    return redirect(request.referrer or url_for("dashboard"))

@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", message="The page or record could not be found."), 404

@app.errorhandler(500)
def server_error(_e):
    return render_template("error.html", message="An unexpected error occurred. Please try again."), 500

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True)
