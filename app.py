import os
import sqlite3
from datetime import date, datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, abort, session
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "healthqueue-demo-secret-change-before-deployment"
)

DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() == "true"

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "healthqueue.db"
)


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db_connection():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


# ==========================================
# LOGIN PROTECTION
# ==========================================

def patient_login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if session.get("role") != "patient":
            return redirect("/login")
        return function(*args, **kwargs)
    return wrapper


def doctor_login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if session.get("role") != "doctor":
            return redirect("/doctor/login")
        return function(*args, **kwargs)
    return wrapper


def admin_login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return redirect("/admin/login")
        return function(*args, **kwargs)
    return wrapper


def staff_login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if session.get("role") != "staff":
            return redirect("/staff/login")
        return function(*args, **kwargs)
    return wrapper


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

def initialize_database():
    db = get_db_connection()

    db.executescript("""
        CREATE TABLE IF NOT EXISTS hospitals (
            hospital_id INTEGER PRIMARY KEY AUTOINCREMENT,
            hospital_name TEXT NOT NULL,
            location TEXT NOT NULL,
            phone TEXT,
            email TEXT,
            status TEXT DEFAULT 'Active'
        );

        CREATE TABLE IF NOT EXISTS patients (
            patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            age INTEGER NOT NULL,
            gender TEXT,
            phone TEXT NOT NULL,
            department TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS tokens (
            token_id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            token_number TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'Waiting',
            FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
        );

        CREATE TABLE IF NOT EXISTS doctors (
            doctor_id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_name TEXT NOT NULL,
            department TEXT NOT NULL,
            phone TEXT,
            availability TEXT DEFAULT 'Available',
            hospital_id INTEGER,
            FOREIGN KEY (hospital_id) REFERENCES hospitals(hospital_id)
        );

        CREATE TABLE IF NOT EXISTS queue (
            queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id INTEGER NOT NULL,
            doctor_id INTEGER,
            queue_position INTEGER NOT NULL,
            queue_status TEXT DEFAULT 'Waiting',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (token_id) REFERENCES tokens(token_id),
            FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id)
        );

        CREATE TABLE IF NOT EXISTS camps (
            camp_id INTEGER PRIMARY KEY AUTOINCREMENT,
            camp_name TEXT NOT NULL,
            location TEXT NOT NULL,
            camp_date DATE NOT NULL,
            status TEXT DEFAULT 'Active'
        );

        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS doctor_accounts (
            account_id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_id INTEGER UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id)
        );

        CREATE TABLE IF NOT EXISTS consultations (
            consultation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            queue_id INTEGER NOT NULL UNIQUE,
            doctor_id INTEGER NOT NULL,
            diagnosis TEXT,
            notes TEXT,
            prescription TEXT,
            follow_up_date TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (queue_id) REFERENCES queue(queue_id),
            FOREIGN KEY (doctor_id) REFERENCES doctors(doctor_id)
        );

        CREATE TABLE IF NOT EXISTS staff (
            staff_id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_name TEXT NOT NULL,
            role TEXT NOT NULL,
            phone TEXT,
            hospital_id INTEGER,
            status TEXT DEFAULT 'Active',
            shift TEXT DEFAULT 'General',
            FOREIGN KEY (hospital_id) REFERENCES hospitals(hospital_id)
        );

        CREATE TABLE IF NOT EXISTS beds (
            bed_id INTEGER PRIMARY KEY AUTOINCREMENT,
            hospital_id INTEGER NOT NULL,
            ward TEXT NOT NULL,
            bed_number TEXT NOT NULL,
            status TEXT DEFAULT 'Available',
            FOREIGN KEY (hospital_id) REFERENCES hospitals(hospital_id)
        );

        CREATE TABLE IF NOT EXISTS medicines (
            medicine_id INTEGER PRIMARY KEY AUTOINCREMENT,
            medicine_name TEXT NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 0,
            unit TEXT DEFAULT 'units',
            hospital_id INTEGER,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (hospital_id) REFERENCES hospitals(hospital_id)
        );

        CREATE TABLE IF NOT EXISTS staff_accounts (
            account_id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            FOREIGN KEY (staff_id) REFERENCES staff(staff_id)
        );

        CREATE TABLE IF NOT EXISTS staff_attendance (
            attendance_id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER NOT NULL,
            attendance_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Present',
            check_in TEXT,
            check_out TEXT,
            UNIQUE(staff_id, attendance_date),
            FOREIGN KEY (staff_id) REFERENCES staff(staff_id)
        );

        CREATE TABLE IF NOT EXISTS staff_tasks (
            task_id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER NOT NULL,
            task_title TEXT NOT NULL,
            description TEXT,
            due_date TEXT,
            status TEXT DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (staff_id) REFERENCES staff(staff_id)
        );
    """)

    # Existing database migrations
    doctor_columns = [
        row["name"]
        for row in db.execute("PRAGMA table_info(doctors)").fetchall()
    ]

    if "hospital_id" not in doctor_columns:
        db.execute("""
            ALTER TABLE doctors
            ADD COLUMN hospital_id INTEGER REFERENCES hospitals(hospital_id)
        """)

    user_columns = [
        row["name"]
        for row in db.execute("PRAGMA table_info(users)").fetchall()
    ]

    for column, definition in [
        ("name", "TEXT"),
        ("phone", "TEXT"),
        ("patient_id", "INTEGER")
    ]:
        if column not in user_columns:
            db.execute(
                f"ALTER TABLE users ADD COLUMN {column} {definition}"
            )

    staff_columns = [
        row["name"]
        for row in db.execute("PRAGMA table_info(staff)").fetchall()
    ]

    if "shift" not in staff_columns:
        db.execute(
            "ALTER TABLE staff ADD COLUMN shift TEXT DEFAULT 'General'"
        )

    # Demo hospitals
    demo_hospitals = [
        ("HealthQueue City Hospital", "Bengaluru", "9876543210"),
        ("HealthQueue Care Centre", "Mysuru", "9876543211"),
        ("HealthQueue Medical Centre", "Mangaluru", "9876543212")
    ]

    for hospital in demo_hospitals:
        db.execute("""
            INSERT INTO hospitals (hospital_name, location, phone)
            SELECT ?, ?, ?
            WHERE NOT EXISTS (
                SELECT 1 FROM hospitals WHERE hospital_name = ?
            )
        """, (*hospital, hospital[0]))

    # Demo doctors
    demo_doctors = [
        ("Dr. Aarav Sharma", "Cardiology", "9000000001",
         "HealthQueue City Hospital"),
        ("Dr. Meera Rao", "Dermatology", "9000000002",
         "HealthQueue City Hospital"),
        ("Dr. Rohan Shetty", "Orthopedics", "9000000003",
         "HealthQueue Care Centre"),
        ("Dr. Ananya Nair", "Pediatrics", "9000000004",
         "HealthQueue Care Centre"),
        ("Dr. Kiran Kumar", "General Medicine", "9000000005",
         "HealthQueue Medical Centre")
    ]

    for doctor in demo_doctors:
        hospital = db.execute("""
            SELECT hospital_id FROM hospitals
            WHERE hospital_name = ?
        """, (doctor[3],)).fetchone()

        if hospital:
            db.execute("""
                INSERT INTO doctors
                (doctor_name, department, phone, hospital_id)
                SELECT ?, ?, ?, ?
                WHERE NOT EXISTS (
                    SELECT 1 FROM doctors
                    WHERE doctor_name = ? AND hospital_id = ?
                )
            """, (
                doctor[0], doctor[1], doctor[2],
                hospital["hospital_id"], doctor[0],
                hospital["hospital_id"]
            ))

    # Doctor accounts
    all_doctors = db.execute("""
        SELECT doctor_id, phone FROM doctors
        WHERE phone IS NOT NULL
    """).fetchall()

    for doctor in all_doctors:
        existing = db.execute("""
            SELECT account_id FROM doctor_accounts
            WHERE doctor_id = ?
        """, (doctor["doctor_id"],)).fetchone()

        if not existing:
            db.execute("""
                INSERT INTO doctor_accounts
                (doctor_id, username, password_hash)
                VALUES (?, ?, ?)
            """, (
                doctor["doctor_id"],
                doctor["phone"],
                generate_password_hash("Doctor@123")
            ))

    # Admin account
    admin_exists = db.execute("""
        SELECT user_id FROM users
        WHERE username = 'admin' AND role = 'admin'
    """).fetchone()

    if not admin_exists:
        db.execute("""
            INSERT INTO users
            (username, name, phone, password_hash, role)
            VALUES (?, ?, ?, ?, ?)
        """, (
            "admin",
            "HealthQueue Administrator",
            "0000000000",
            generate_password_hash(os.environ.get("INITIAL_ADMIN_PASSWORD", "Admin@123")),
            "admin"
        ))

    # Demo staff account
    demo_staff = db.execute("""
        SELECT staff_id FROM staff WHERE phone = 'demo-staff'
    """).fetchone()

    if not demo_staff:
        demo_hospital = db.execute("""
            SELECT hospital_id FROM hospitals
            ORDER BY hospital_id LIMIT 1
        """).fetchone()

        if demo_hospital:
            staff_cursor = db.execute("""
                INSERT INTO staff
                (staff_name, role, phone, hospital_id, status, shift)
                VALUES (?, ?, ?, ?, 'Active', ?)
            """, (
                "Priya Sharma",
                "Nurse",
                "demo-staff",
                demo_hospital["hospital_id"],
                "Morning"
            ))

            staff_id = staff_cursor.lastrowid

            db.execute("""
                INSERT INTO staff_accounts
                (staff_id, username, password_hash)
                VALUES (?, ?, ?)
            """, (
                staff_id,
                "demo-staff",
                generate_password_hash("Staff@123")
            ))

    db.commit()
    db.close()


# ==========================================
# ADMIN PORTAL
# ==========================================

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip() or "Demo Admin"
        password = request.form.get("password", "")

        if DEMO_MODE:
            db = get_db_connection()
            admin = db.execute("""
                SELECT * FROM users
                WHERE username = 'admin' AND role = 'admin'
            """).fetchone()
            db.close()

            session.clear()
            session["role"] = "admin"
            session["admin_id"] = admin["user_id"] if admin else 0
            session["admin_name"] = username
            return redirect("/admin")

        db = get_db_connection()
        admin = db.execute("""
            SELECT * FROM users
            WHERE username = ? AND role = 'admin'
        """, (username,)).fetchone()
        db.close()

        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["role"] = "admin"
            session["admin_id"] = admin["user_id"]
            session["admin_name"] = admin["name"] or "Administrator"
            return redirect("/admin")

        error = "Invalid administrator username or password."

    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect("/admin/login")


@app.route("/admin")
@admin_login_required
def admin_dashboard():
    db = get_db_connection()

    stats = {
        "hospitals": db.execute(
            "SELECT COUNT(*) FROM hospitals"
        ).fetchone()[0],
        "doctors": db.execute(
            "SELECT COUNT(*) FROM doctors"
        ).fetchone()[0],
        "patients": db.execute(
            "SELECT COUNT(*) FROM patients"
        ).fetchone()[0],
        "staff": db.execute(
            "SELECT COUNT(*) FROM staff"
        ).fetchone()[0],
        "beds": db.execute(
            "SELECT COUNT(*) FROM beds"
        ).fetchone()[0],
        "available_beds": db.execute(
            "SELECT COUNT(*) FROM beds WHERE status = 'Available'"
        ).fetchone()[0],
        "medicines": db.execute(
            "SELECT COUNT(*) FROM medicines"
        ).fetchone()[0]
    }

    hospitals_list = db.execute("""
        SELECT * FROM hospitals ORDER BY hospital_name
    """).fetchall()

    doctors_list = db.execute("""
        SELECT doctors.*, hospitals.hospital_name
        FROM doctors
        LEFT JOIN hospitals
        ON doctors.hospital_id = hospitals.hospital_id
        ORDER BY doctors.doctor_name
    """).fetchall()

    staff_list = db.execute("""
        SELECT staff.*, hospitals.hospital_name
        FROM staff
        LEFT JOIN hospitals
        ON staff.hospital_id = hospitals.hospital_id
        ORDER BY staff.staff_name
    """).fetchall()

    beds_list = db.execute("""
        SELECT beds.*, hospitals.hospital_name
        FROM beds
        JOIN hospitals
        ON beds.hospital_id = hospitals.hospital_id
        ORDER BY hospitals.hospital_name, beds.ward, beds.bed_number
    """).fetchall()

    medicines_list = db.execute("""
        SELECT medicines.*, hospitals.hospital_name
        FROM medicines
        LEFT JOIN hospitals
        ON medicines.hospital_id = hospitals.hospital_id
        ORDER BY medicines.medicine_name
    """).fetchall()

    db.close()

    return render_template(
        "admin.html",
        stats=stats,
        hospitals=hospitals_list,
        doctors=doctors_list,
        staff=staff_list,
        beds=beds_list,
        medicines=medicines_list,
        admin_name=session.get("admin_name", "Administrator")
    )


# ==========================================
# ADMIN MANAGEMENT ROUTES
# ==========================================

@app.route("/admin/hospitals/add", methods=["POST"])
@admin_login_required
def admin_add_hospital():
    name = request.form.get("hospital_name", "").strip()
    location = request.form.get("location", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()

    if not name or not location:
        abort(400, "Hospital name and location are required.")

    db = get_db_connection()
    db.execute("""
        INSERT INTO hospitals (hospital_name, location, phone, email)
        VALUES (?, ?, ?, ?)
    """, (name, location, phone, email))
    db.commit()
    db.close()

    return redirect("/admin#hospitals")


@app.route("/admin/hospitals/<int:hospital_id>/status", methods=["POST"])
@admin_login_required
def admin_toggle_hospital(hospital_id):
    db = get_db_connection()
    db.execute("""
        UPDATE hospitals
        SET status = CASE
            WHEN status = 'Active' THEN 'Inactive'
            ELSE 'Active'
        END
        WHERE hospital_id = ?
    """, (hospital_id,))
    db.commit()
    db.close()

    return redirect("/admin#hospitals")


@app.route("/admin/doctors/add", methods=["POST"])
@admin_login_required
def admin_add_doctor():
    name = request.form.get("doctor_name", "").strip()
    department = request.form.get("department", "").strip()
    phone = request.form.get("phone", "").strip()
    hospital_id = request.form.get("hospital_id", type=int)

    if not name or not department or not phone or not hospital_id:
        abort(400, "Complete all doctor fields.")

    if not DEMO_MODE and (len(phone) != 10 or not phone.isdigit()):
        abort(400, "Doctor phone number must contain 10 digits.")

    db = get_db_connection()

    try:
        cursor = db.execute("""
            INSERT INTO doctors
            (doctor_name, department, phone, hospital_id)
            VALUES (?, ?, ?, ?)
        """, (name, department, phone, hospital_id))

        db.execute("""
            INSERT INTO doctor_accounts
            (doctor_id, username, password_hash)
            VALUES (?, ?, ?)
        """, (
            cursor.lastrowid,
            phone,
            generate_password_hash("Doctor@123")
        ))

        db.commit()

    except sqlite3.IntegrityError:
        db.rollback()
        abort(400, "That doctor phone number or account already exists.")

    finally:
        db.close()

    return redirect("/admin#doctors")


@app.route("/admin/staff/add", methods=["POST"])
@admin_login_required
def admin_add_staff():
    name = request.form.get("staff_name", "").strip()
    role = request.form.get("role", "").strip()
    phone = request.form.get("phone", "").strip()
    hospital_id = request.form.get("hospital_id", type=int)
    shift = request.form.get("shift", "General").strip() or "General"

    if not name or not role or not hospital_id or not phone:
        abort(400, "Staff name, role, phone and hospital are required.")

    if not DEMO_MODE and (len(phone) != 10 or not phone.isdigit()):
        abort(400, "Staff phone number must contain 10 digits.")

    db = get_db_connection()

    try:
        cursor = db.execute("""
            INSERT INTO staff
            (staff_name, role, phone, hospital_id, shift)
            VALUES (?, ?, ?, ?, ?)
        """, (name, role, phone, hospital_id, shift))

        db.execute("""
            INSERT INTO staff_accounts
            (staff_id, username, password_hash)
            VALUES (?, ?, ?)
        """, (
            cursor.lastrowid,
            phone,
            generate_password_hash("Staff@123")
        ))

        db.commit()

    except sqlite3.IntegrityError:
        db.rollback()
        abort(400, "This staff phone number or account already exists.")

    finally:
        db.close()

    return redirect("/admin#staff")


@app.route("/admin/beds/add", methods=["POST"])
@admin_login_required
def admin_add_bed():
    hospital_id = request.form.get("hospital_id", type=int)
    ward = request.form.get("ward", "").strip()
    bed_number = request.form.get("bed_number", "").strip()

    if not hospital_id or not ward or not bed_number:
        abort(400, "Complete all bed fields.")

    db = get_db_connection()
    db.execute("""
        INSERT INTO beds (hospital_id, ward, bed_number)
        VALUES (?, ?, ?)
    """, (hospital_id, ward, bed_number))
    db.commit()
    db.close()

    return redirect("/admin#beds")


@app.route("/admin/beds/<int:bed_id>/status", methods=["POST"])
@admin_login_required
def admin_update_bed(bed_id):
    status = request.form.get("status", "")

    if status not in ("Available", "Occupied", "Maintenance"):
        abort(400)

    db = get_db_connection()
    db.execute("""
        UPDATE beds SET status = ? WHERE bed_id = ?
    """, (status, bed_id))
    db.commit()
    db.close()

    return redirect("/admin#beds")


@app.route("/admin/medicines/add", methods=["POST"])
@admin_login_required
def admin_add_medicine():
    name = request.form.get("medicine_name", "").strip()
    quantity = request.form.get("quantity", type=int)
    unit = request.form.get("unit", "units").strip() or "units"
    hospital_id = request.form.get("hospital_id", type=int)

    if not name or quantity is None or quantity < 0:
        abort(400, "Enter a medicine name and a non-negative quantity.")

    db = get_db_connection()
    db.execute("""
        INSERT INTO medicines
        (medicine_name, quantity, unit, hospital_id)
        VALUES (?, ?, ?, ?)
    """, (name, quantity, unit, hospital_id or None))
    db.commit()
    db.close()

    return redirect("/admin#medicines")


@app.route("/admin/medicines/<int:medicine_id>/update", methods=["POST"])
@admin_login_required
def admin_update_medicine(medicine_id):
    quantity = request.form.get("quantity", type=int)

    if quantity is None or quantity < 0:
        abort(400, "Quantity cannot be negative.")

    db = get_db_connection()
    db.execute("""
        UPDATE medicines
        SET quantity = ?, updated_at = CURRENT_TIMESTAMP
        WHERE medicine_id = ?
    """, (quantity, medicine_id))
    db.commit()
    db.close()

    return redirect("/admin#medicines")


@app.route("/admin/tasks/add", methods=["POST"])
@admin_login_required
def admin_add_task():
    staff_id = request.form.get("staff_id", type=int)
    title = request.form.get("task_title", "").strip()
    description = request.form.get("description", "").strip()
    due_date = request.form.get("due_date", "").strip()

    if not staff_id or not title:
        abort(400, "Select a staff member and enter a task title.")

    db = get_db_connection()

    staff_member = db.execute("""
        SELECT staff_id FROM staff
        WHERE staff_id = ? AND status = 'Active'
    """, (staff_id,)).fetchone()

    if not staff_member:
        db.close()
        abort(400, "Selected staff member is unavailable.")

    db.execute("""
        INSERT INTO staff_tasks
        (staff_id, task_title, description, due_date)
        VALUES (?, ?, ?, ?)
    """, (staff_id, title, description, due_date or None))

    db.commit()
    db.close()

    return redirect("/admin#staff")


# ==========================================
# STAFF PORTAL
# ==========================================

@app.route("/staff/login", methods=["GET", "POST"])
def staff_login():
    if session.get("role") == "staff":
        return redirect("/staff")

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db_connection()

        if DEMO_MODE:
            account = db.execute("""
                SELECT
                    staff.staff_id,
                    staff.staff_name,
                    staff.role AS staff_role,
                    staff.shift,
                    staff.hospital_id,
                    hospitals.hospital_name
                FROM staff
                LEFT JOIN hospitals
                ON staff.hospital_id = hospitals.hospital_id
                WHERE staff.status = 'Active'
                ORDER BY staff.staff_id
                LIMIT 1
            """).fetchone()
        else:
            account = db.execute("""
                SELECT
                    staff_accounts.account_id,
                    staff_accounts.username,
                    staff_accounts.password_hash,
                    staff.staff_id,
                    staff.staff_name,
                    staff.role AS staff_role,
                    staff.shift,
                    staff.hospital_id,
                    hospitals.hospital_name
                FROM staff_accounts
                JOIN staff
                ON staff_accounts.staff_id = staff.staff_id
                LEFT JOIN hospitals
                ON staff.hospital_id = hospitals.hospital_id
                WHERE staff_accounts.username = ?
                AND staff.status = 'Active'
            """, (username,)).fetchone()

        db.close()

        valid_login = DEMO_MODE or (
            account and check_password_hash(account["password_hash"], password)
        )

        if account and valid_login:
            session.clear()
            session["role"] = "staff"
            session["staff_id"] = account["staff_id"]
            session["staff_name"] = (
                username if DEMO_MODE and username else account["staff_name"]
            )
            session["staff_role"] = account["staff_role"]
            session["staff_shift"] = account["shift"] or "General"
            session["hospital_id"] = account["hospital_id"]
            session["hospital_name"] = account["hospital_name"]

            return redirect("/staff")

        error = "Invalid staff username or password."

    return render_template("staff_login.html", error=error)


@app.route("/staff/logout")
def staff_logout():
    session.clear()
    return redirect("/staff/login")


@app.route("/staff")
@staff_login_required
def staff_dashboard():
    db = get_db_connection()
    staff_id = session["staff_id"]
    today = date.today().isoformat()

    attendance = db.execute("""
        SELECT * FROM staff_attendance
        WHERE staff_id = ? AND attendance_date = ?
    """, (staff_id, today)).fetchone()

    attendance_history = db.execute("""
        SELECT * FROM staff_attendance
        WHERE staff_id = ?
        ORDER BY attendance_date DESC
        LIMIT 10
    """, (staff_id,)).fetchall()

    tasks = db.execute("""
        SELECT * FROM staff_tasks
        WHERE staff_id = ?
        ORDER BY
            CASE status
                WHEN 'Pending' THEN 1
                WHEN 'In Progress' THEN 2
                ELSE 3
            END,
            due_date ASC
    """, (staff_id,)).fetchall()

    task_counts = {
        "pending": db.execute("""
            SELECT COUNT(*) FROM staff_tasks
            WHERE staff_id = ? AND status = 'Pending'
        """, (staff_id,)).fetchone()[0],

        "in_progress": db.execute("""
            SELECT COUNT(*) FROM staff_tasks
            WHERE staff_id = ? AND status = 'In Progress'
        """, (staff_id,)).fetchone()[0],

        "completed": db.execute("""
            SELECT COUNT(*) FROM staff_tasks
            WHERE staff_id = ? AND status = 'Completed'
        """, (staff_id,)).fetchone()[0]
    }

    db.close()

    return render_template(
        "staff.html",
        staff_name=session["staff_name"],
        staff_role=session["staff_role"],
        staff_shift=session["staff_shift"],
        hospital_name=session.get("hospital_name"),
        attendance=attendance,
        attendance_history=attendance_history,
        tasks=tasks,
        task_counts=task_counts,
        today=today
    )


@app.route("/staff/attendance", methods=["POST"])
@staff_login_required
def staff_mark_attendance():
    staff_id = session["staff_id"]
    today = date.today().isoformat()
    current_time = datetime.now().strftime("%H:%M:%S")
    action = request.form.get("action", "check_in")

    db = get_db_connection()

    attendance = db.execute("""
        SELECT * FROM staff_attendance
        WHERE staff_id = ? AND attendance_date = ?
    """, (staff_id, today)).fetchone()

    if action == "check_in":
        if not attendance:
            db.execute("""
                INSERT INTO staff_attendance
                (staff_id, attendance_date, status, check_in)
                VALUES (?, ?, 'Present', ?)
            """, (staff_id, today, current_time))

        elif not attendance["check_in"]:
            db.execute("""
                UPDATE staff_attendance
                SET status = 'Present', check_in = ?
                WHERE staff_id = ? AND attendance_date = ?
            """, (current_time, staff_id, today))

    elif action == "check_out":
        if attendance and attendance["check_in"]:
            db.execute("""
                UPDATE staff_attendance
                SET check_out = ?
                WHERE staff_id = ? AND attendance_date = ?
            """, (current_time, staff_id, today))

    else:
        db.close()
        abort(400, "Invalid attendance action.")

    db.commit()
    db.close()

    return redirect("/staff")


@app.route("/staff/tasks/<int:task_id>/status", methods=["POST"])
@staff_login_required
def staff_update_task(task_id):
    status = request.form.get("status", "")

    if status not in ("Pending", "In Progress", "Completed"):
        abort(400, "Invalid task status.")

    db = get_db_connection()
    db.execute("""
        UPDATE staff_tasks
        SET status = ?
        WHERE task_id = ? AND staff_id = ?
    """, (status, task_id, session["staff_id"]))

    db.commit()
    db.close()

    return redirect("/staff#tasks")


# ==========================================
# PATIENT PORTAL
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not phone or not password:
            return render_template(
                "signup.html",
                error="Please fill in all fields."
            )

        if not DEMO_MODE and (len(phone) != 10 or not phone.isdigit()):
            return render_template(
                "signup.html",
                error="Enter a valid 10-digit phone number."
            )

        if len(password) < 8:
            return render_template(
                "signup.html",
                error="Password must contain at least 8 characters."
            )

        if password != confirm_password:
            return render_template(
                "signup.html",
                error="Passwords do not match."
            )

        db = get_db_connection()

        try:
            existing_user = db.execute("""
                SELECT user_id FROM users
                WHERE phone = ? OR username = ?
            """, (phone, phone)).fetchone()

            if existing_user:
                return render_template(
                    "signup.html",
                    error="An account with this phone number already exists."
                )

            db.execute("""
                INSERT INTO users
                (username, name, phone, password_hash, role)
                VALUES (?, ?, ?, ?, 'patient')
            """, (
                phone,
                name,
                phone,
                generate_password_hash(password)
            ))

            db.commit()

            user = db.execute("""
                SELECT user_id, username, phone
                FROM users WHERE phone = ?
            """, (phone,)).fetchone()

            session.clear()
            session["user_id"] = user["user_id"]
            session["username"] = phone
            session["name"] = name
            session["phone"] = phone
            session["role"] = "patient"

            return redirect("/patient/dashboard")

        except sqlite3.Error:
            db.rollback()
            app.logger.exception("Signup failed")
            return render_template(
                "signup.html",
                error="Account creation failed. Please try again."
            )

        finally:
            db.close()

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        db = get_db_connection()

        if DEMO_MODE:
            user = db.execute("""
                SELECT * FROM users
                WHERE role = 'patient'
                ORDER BY user_id LIMIT 1
            """).fetchone()
        else:
            user = db.execute("""
                SELECT * FROM users
                WHERE (phone = ? OR username = ?)
                AND role = 'patient'
            """, (phone, phone)).fetchone()

        db.close()

        if DEMO_MODE:
            session.clear()
            session["user_id"] = user["user_id"] if user else 0
            session["username"] = phone or "Demo Patient"
            session["name"] = phone or "Demo Patient"
            session["phone"] = phone or "demo-patient"
            session["role"] = "patient"
            return redirect("/patient/dashboard")

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["user_id"]
            session["username"] = user["username"]
            session["name"] = user["name"] or user["username"]
            session["phone"] = user["phone"] or user["username"]
            session["role"] = "patient"

            return redirect("/patient/dashboard")

        return render_template(
            "login.html",
            error="Invalid phone number or password."
        )

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/patient/dashboard")
@patient_login_required
def patient_dashboard():
    db = get_db_connection()

    appointments = db.execute("""
        SELECT
            patients.name,
            patients.department,
            tokens.token_number,
            queue.queue_position,
            queue.queue_status,
            doctors.doctor_name,
            hospitals.hospital_name
        FROM patients
        JOIN tokens ON patients.patient_id = tokens.patient_id
        JOIN queue ON tokens.token_id = queue.token_id
        LEFT JOIN doctors ON queue.doctor_id = doctors.doctor_id
        LEFT JOIN hospitals ON doctors.hospital_id = hospitals.hospital_id
        WHERE patients.phone = ?
        ORDER BY patients.created_at DESC
    """, (session["phone"],)).fetchall()

    db.close()

    return render_template(
        "patient_dashboard.html",
        appointments=appointments,
        patient_name=session.get("name", session["username"])
    )


# ==========================================
# DOCTOR PORTAL
# ==========================================

@app.route("/doctor/login", methods=["GET", "POST"])
def doctor_login():
    if session.get("role") == "doctor":
        return redirect("/doctor")

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db_connection()

        if DEMO_MODE:
            account = db.execute("""
                SELECT
                    doctors.doctor_id,
                    doctors.doctor_name,
                    doctors.department,
                    doctors.hospital_id
                FROM doctors
                ORDER BY doctors.doctor_id
                LIMIT 1
            """).fetchone()
        else:
            account = db.execute("""
                SELECT
                    doctor_accounts.account_id,
                    doctor_accounts.username,
                    doctor_accounts.password_hash,
                    doctors.doctor_id,
                    doctors.doctor_name,
                    doctors.department,
                    doctors.hospital_id
                FROM doctor_accounts
                JOIN doctors
                ON doctor_accounts.doctor_id = doctors.doctor_id
                WHERE doctor_accounts.username = ?
            """, (username,)).fetchone()

        db.close()

        valid_login = DEMO_MODE or (
            account and check_password_hash(account["password_hash"], password)
        )

        if account and valid_login:
            session.clear()
            session["role"] = "doctor"
            session["doctor_id"] = account["doctor_id"]
            session["doctor_name"] = (
                username if DEMO_MODE and username else account["doctor_name"]
            )
            session["doctor_department"] = account["department"]
            session["hospital_id"] = account["hospital_id"]

            return redirect("/doctor")

        error = "Invalid doctor username or password."

    return render_template("doctor_login.html", error=error)


@app.route("/doctor/logout")
def doctor_logout():
    session.clear()
    return redirect("/doctor/login")


@app.route("/doctor")
@doctor_login_required
def doctor_dashboard():
    db = get_db_connection()
    doctor_id = session["doctor_id"]

    patients = db.execute("""
        SELECT
            queue.queue_id,
            patients.name,
            patients.age,
            patients.gender,
            patients.phone,
            patients.department,
            tokens.token_number,
            queue.queue_position,
            queue.queue_status
        FROM queue
        JOIN tokens ON queue.token_id = tokens.token_id
        JOIN patients ON tokens.patient_id = patients.patient_id
        WHERE queue.doctor_id = ?
        ORDER BY
            CASE queue.queue_status
                WHEN 'Serving' THEN 1
                WHEN 'Waiting' THEN 2
                ELSE 3
            END,
            queue.queue_position ASC
    """, (doctor_id,)).fetchall()

    counts = db.execute("""
        SELECT
            SUM(CASE WHEN queue_status = 'Waiting' THEN 1 ELSE 0 END) AS waiting,
            SUM(CASE WHEN queue_status = 'Serving' THEN 1 ELSE 0 END) AS serving,
            SUM(CASE WHEN queue_status = 'Completed' THEN 1 ELSE 0 END) AS completed
        FROM queue
        WHERE doctor_id = ?
    """, (doctor_id,)).fetchone()

    db.close()

    return render_template(
        "doctor.html",
        patients=patients,
        doctor_name=session["doctor_name"],
        department=session["doctor_department"],
        waiting=counts["waiting"] or 0,
        serving=counts["serving"] or 0,
        completed=counts["completed"] or 0
    )


@app.route("/doctor/call-next", methods=["POST"])
@doctor_login_required
def call_next():
    db = get_db_connection()
    doctor_id = session["doctor_id"]

    try:
        current_patient = db.execute("""
            SELECT queue_id FROM queue
            WHERE queue_status = 'Serving'
            AND doctor_id = ?
            LIMIT 1
        """, (doctor_id,)).fetchone()

        if not current_patient:
            patient = db.execute("""
                SELECT queue_id FROM queue
                WHERE queue_status = 'Waiting'
                AND doctor_id = ?
                ORDER BY queue_position ASC
                LIMIT 1
            """, (doctor_id,)).fetchone()

            if patient:
                db.execute("""
                    UPDATE queue
                    SET queue_status = 'Serving',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE queue_id = ?
                """, (patient["queue_id"],))

        db.commit()

    finally:
        db.close()

    return redirect("/doctor")


@app.route("/doctor/complete/<int:queue_id>", methods=["POST"])
@doctor_login_required
def complete_consultation(queue_id):
    db = get_db_connection()

    db.execute("""
        UPDATE queue
        SET queue_status = 'Completed',
            updated_at = CURRENT_TIMESTAMP
        WHERE queue_id = ?
        AND doctor_id = ?
        AND queue_status = 'Serving'
    """, (queue_id, session["doctor_id"]))

    db.commit()
    db.close()

    return redirect("/doctor")


@app.route("/doctor/consultation/<int:queue_id>", methods=["GET", "POST"])
@doctor_login_required
def consultation_record(queue_id):
    db = get_db_connection()

    patient = db.execute("""
        SELECT
            queue.queue_id,
            queue.queue_status,
            patients.name,
            patients.age,
            patients.gender,
            patients.phone,
            patients.department,
            tokens.token_number
        FROM queue
        JOIN tokens ON queue.token_id = tokens.token_id
        JOIN patients ON tokens.patient_id = patients.patient_id
        WHERE queue.queue_id = ?
        AND queue.doctor_id = ?
    """, (queue_id, session["doctor_id"])).fetchone()

    if not patient:
        db.close()
        abort(404)

    if request.method == "POST":
        diagnosis = request.form.get("diagnosis", "").strip()
        notes = request.form.get("notes", "").strip()
        prescription = request.form.get("prescription", "").strip()
        follow_up_date = request.form.get("follow_up_date", "").strip()

        if not diagnosis:
            existing = db.execute("""
                SELECT * FROM consultations WHERE queue_id = ?
            """, (queue_id,)).fetchone()

            db.close()

            return render_template(
                "consultation.html",
                patient=patient,
                consultation=existing,
                error="Please enter a diagnosis."
            )

        db.execute("""
            INSERT INTO consultations
            (queue_id, doctor_id, diagnosis, notes, prescription, follow_up_date)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(queue_id) DO UPDATE SET
                diagnosis = excluded.diagnosis,
                notes = excluded.notes,
                prescription = excluded.prescription,
                follow_up_date = excluded.follow_up_date,
                created_at = CURRENT_TIMESTAMP
        """, (
            queue_id,
            session["doctor_id"],
            diagnosis,
            notes,
            prescription,
            follow_up_date
        ))

        db.commit()

        consultation = db.execute("""
            SELECT * FROM consultations WHERE queue_id = ?
        """, (queue_id,)).fetchone()

        db.close()

        return render_template(
            "consultation.html",
            patient=patient,
            consultation=consultation,
            success="Consultation record saved."
        )

    consultation = db.execute("""
        SELECT * FROM consultations
        WHERE queue_id = ? AND doctor_id = ?
    """, (queue_id, session["doctor_id"])).fetchone()

    db.close()

    return render_template(
        "consultation.html",
        patient=patient,
        consultation=consultation,
        error=None
    )


# ==========================================
# HOSPITAL AND APPOINTMENT SYSTEM
# ==========================================

@app.route("/hospitals")
def hospitals():
    db = get_db_connection()

    hospital_list = db.execute("""
        SELECT * FROM hospitals
        WHERE status = 'Active'
        ORDER BY hospital_name
    """).fetchall()

    db.close()

    return render_template("hospitals.html", hospitals=hospital_list)


@app.route("/doctors/<int:hospital_id>")
def hospital_doctors(hospital_id):
    db = get_db_connection()

    hospital = db.execute("""
        SELECT * FROM hospitals
        WHERE hospital_id = ? AND status = 'Active'
    """, (hospital_id,)).fetchone()

    if not hospital:
        db.close()
        abort(404)

    doctor_list = db.execute("""
        SELECT * FROM doctors
        WHERE hospital_id = ?
        ORDER BY department, doctor_name
    """, (hospital_id,)).fetchall()

    db.close()

    return render_template(
        "doctors.html",
        hospital=hospital,
        doctors=doctor_list
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    db = get_db_connection()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        age = request.form.get("age", type=int)
        gender = request.form.get("gender", "")
        phone = request.form.get("phone", "").strip()
        hospital_id = request.form.get("hospital_id", type=int)
        doctor_id = request.form.get("doctor_id", type=int)

        if not name or not age or age < 1 or age > 120:
            db.close()
            return "Please enter valid patient details.", 400

        if not DEMO_MODE and (len(phone) != 10 or not phone.isdigit()):
            db.close()
            return "Please enter a valid 10-digit phone number.", 400

        if not hospital_id or not doctor_id:
            db.close()
            return "Please select a hospital and doctor.", 400

        hospital = db.execute("""
            SELECT hospital_id, hospital_name
            FROM hospitals
            WHERE hospital_id = ? AND status = 'Active'
        """, (hospital_id,)).fetchone()

        if not hospital:
            db.close()
            return "Selected hospital is unavailable.", 400

        doctor = db.execute("""
            SELECT doctor_id, doctor_name, department
            FROM doctors
            WHERE doctor_id = ?
            AND hospital_id = ?
            AND availability = 'Available'
        """, (doctor_id, hospital_id)).fetchone()

        if not doctor:
            db.close()
            return "Please select a valid available doctor.", 400

        department = doctor["department"]

        try:
            cursor = db.cursor()

            cursor.execute("""
                INSERT INTO patients
                (name, age, gender, phone, department)
                VALUES (?, ?, ?, ?, ?)
            """, (name, age, gender, phone, department))

            patient_id = cursor.lastrowid
            token_number = f"HQ-{patient_id:05d}"

            cursor.execute("""
                INSERT INTO tokens (patient_id, token_number)
                VALUES (?, ?)
            """, (patient_id, token_number))

            token_id = cursor.lastrowid

            cursor.execute("""
                SELECT COALESCE(MAX(queue_position), 0) + 1
                FROM queue
                WHERE doctor_id = ?
                AND queue_status IN ('Waiting', 'Serving')
            """, (doctor_id,))

            queue_position = cursor.fetchone()[0]

            cursor.execute("""
                INSERT INTO queue
                (token_id, doctor_id, queue_position, queue_status)
                VALUES (?, ?, ?, 'Waiting')
            """, (token_id, doctor_id, queue_position))

            db.commit()

            return render_template(
                "token.html",
                name=name,
                token=token_number,
                position=queue_position,
                department=department,
                hospital_name=hospital["hospital_name"],
                doctor_name=doctor["doctor_name"]
            )

        except Exception:
            db.rollback()
            app.logger.exception("Registration failed")
            return "Registration failed. Please try again.", 500

        finally:
            db.close()

    hospital_list = db.execute("""
        SELECT * FROM hospitals
        WHERE status = 'Active'
        ORDER BY hospital_name
    """).fetchall()

    doctor_list = db.execute("""
        SELECT * FROM doctors
        WHERE availability = 'Available'
        ORDER BY doctor_name
    """).fetchall()

    db.close()

    return render_template(
        "register.html",
        hospitals=hospital_list,
        doctors=doctor_list,
        selected_hospital=request.args.get("hospital_id", "")
    )


@app.route("/track", methods=["GET", "POST"])
def track_appointment():
    appointment = None
    error = None

    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        token_number = request.form.get("token", "").strip()

        if not phone or not token_number:
            error = "Enter both your phone number and token number."

        elif not DEMO_MODE and (len(phone) != 10 or not phone.isdigit()):
            error = "Enter a valid 10-digit phone number."

        else:
            db = get_db_connection()

            appointment = db.execute("""
                SELECT
                    patients.name,
                    patients.phone,
                    patients.department,
                    tokens.token_number,
                    queue.queue_position,
                    queue.queue_status,
                    doctors.doctor_name,
                    hospitals.hospital_name
                FROM patients
                JOIN tokens ON patients.patient_id = tokens.patient_id
                JOIN queue ON tokens.token_id = queue.token_id
                LEFT JOIN doctors ON queue.doctor_id = doctors.doctor_id
                LEFT JOIN hospitals ON doctors.hospital_id = hospitals.hospital_id
                WHERE patients.phone = ?
                AND tokens.token_number = ?
            """, (phone, token_number)).fetchone()

            db.close()

            if not appointment:
                error = "No appointment found. Check your phone number and token."

    return render_template(
        "track.html",
        appointment=appointment,
        error=error
    )


@app.route("/queue")
def queue_dashboard():
    db = get_db_connection()

    patients = db.execute("""
        SELECT
            patients.name,
            patients.department,
            tokens.token_number,
            queue.queue_position,
            queue.queue_status
        FROM queue
        JOIN tokens ON queue.token_id = tokens.token_id
        JOIN patients ON tokens.patient_id = patients.patient_id
        ORDER BY queue.queue_position ASC
    """).fetchall()

    db.close()

    return render_template("queue.html", patients=patients)


# ==========================================
# START APPLICATION
# ==========================================

initialize_database()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )