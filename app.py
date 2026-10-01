import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# SECURITY: Strong secret key for session signing
app.secret_key = os.urandom(24)
DATABASE = 'database.db'

# ------------------------------------------------------------------------------
# DATABASE INITIALIZATION
# ------------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Users Table (RBAC)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('superadmin', 'admin', 'student')),
                full_name TEXT NOT NULL
            )
        ''')
        
        # Courses Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS courses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                course_code TEXT UNIQUE NOT NULL,
                course_name TEXT NOT NULL,
                capacity INTEGER NOT NULL
            )
        ''')

        # Enrollments Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS enrollments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                course_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending', 'Approved', 'Rejected')),
                FOREIGN KEY (student_id) REFERENCES users (id),
                FOREIGN KEY (course_id) REFERENCES courses (id)
            )
        ''')

        # Seed Default Superadmin if not exists
        cursor.execute("SELECT * FROM users WHERE role = 'superadmin'")
        if not cursor.fetchone():
            default_pw = generate_password_hash("SuperAdmin123!")
            cursor.execute(
                "INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)",
                ("superadmin", default_pw, "superadmin", "System Director")
            )
        conn.commit()

# ------------------------------------------------------------------------------
# SECURITY & RBAC DECORATORS
# ------------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in first.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Please log in first.", "danger")
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                flash("Access denied. Authorized personnel only.", "danger")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Security Headers Middleware
@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# ------------------------------------------------------------------------------
# ROUTES
# ------------------------------------------------------------------------------

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "danger")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        full_name = request.form['full_name'].strip()
        password = request.form['password']

        hashed_pw = generate_password_hash(password)

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password, role, full_name) VALUES (?, ?, 'student', ?)",
                (username, hashed_pw, full_name)
            )
            conn.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Student ID / Username already exists.", "danger")

    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    if role == 'superadmin':
        return redirect(url_for('superadmin_dashboard'))
    elif role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'student':
        return redirect(url_for('student_dashboard'))
    return redirect(url_for('logout'))

# --- STUDENT ROUTES ---
@app.route('/student/dashboard')
@roles_required('student')
def student_dashboard():
    conn = get_db()
    cursor = conn.cursor()
    
    # Available courses
    cursor.execute("SELECT * FROM courses")
    courses = cursor.fetchall()

    # Student's current enrollments
    cursor.execute('''
        SELECT e.id, c.course_code, c.course_name, e.status 
        FROM enrollments e
        JOIN courses c ON e.course_id = c.id
        WHERE e.student_id = ?
    ''', (session['user_id'],))
    my_enrollments = cursor.fetchall()

    return render_template('student_dashboard.html', courses=courses, enrollments=my_enrollments)

@app.route('/student/enroll/<int:course_id>', methods=['POST'])
@roles_required('student')
def enroll(course_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Check duplicate enrollment
    cursor.execute("SELECT * FROM enrollments WHERE student_id = ? AND course_id = ?", 
                   (session['user_id'], course_id))
    if cursor.fetchone():
        flash("You are already enrolled or pending for this course.", "warning")
    else:
        cursor.execute("INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)", 
                       (session['user_id'], course_id))
        conn.commit()
        flash("Enrollment request submitted!", "success")

    return redirect(url_for('student_dashboard'))

# --- ADMIN ROUTES ---
@app.route('/admin/dashboard')
@roles_required('admin', 'superadmin')
def admin_dashboard():
    conn = get_db()
    cursor = conn.cursor()

    # Get pending and processed enrollments
    cursor.execute('''
        SELECT e.id, u.full_name, c.course_code, c.course_name, e.status
        FROM enrollments e
        JOIN users u ON e.student_id = u.id
        JOIN courses c ON e.course_id = c.id
    ''')
    enrollments = cursor.fetchall()

    # Get list of courses
    cursor.execute("SELECT * FROM courses")
    courses = cursor.fetchall()

    return render_template('admin_dashboard.html', enrollments=enrollments, courses=courses)

@app.route('/admin/manage-enrollment/<int:enrollment_id>/<string:action>', methods=['POST'])
@roles_required('admin', 'superadmin')
def manage_enrollment(enrollment_id, action):
    if action in ['Approved', 'Rejected']:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE enrollments SET status = ? WHERE id = ?", (action, enrollment_id))
        conn.commit()
        flash(f"Enrollment status updated to {action}.", "info")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add-course', methods=['POST'])
@roles_required('admin', 'superadmin')
def add_course():
    code = request.form['course_code'].strip().upper()
    name = request.form['course_name'].strip()
    capacity = request.form['capacity']

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO courses (course_code, course_name, capacity) VALUES (?, ?, ?)",
                       (code, name, capacity))
        conn.commit()
        flash("Course added successfully!", "success")
    except sqlite3.IntegrityError:
        flash("Course code already exists.", "danger")

    return redirect(url_for('admin_dashboard'))

# --- SUPER ADMIN ROUTES ---
@app.route('/superadmin/dashboard')
@roles_required('superadmin')
def superadmin_dashboard():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, full_name, role FROM users WHERE role != 'superadmin'")
    users = cursor.fetchall()
    return render_template('superadmin_dashboard.html', users=users)

@app.route('/superadmin/create-admin', methods=['POST'])
@roles_required('superadmin')
def create_admin():
    username = request.form['username'].strip()
    full_name = request.form['full_name'].strip()
    password = request.form['password']

    hashed_pw = generate_password_hash(password)

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, role, full_name) VALUES (?, ?, 'admin', ?)",
            (username, hashed_pw, full_name)
        )
        conn.commit()
        flash("New Admin created successfully!", "success")
    except sqlite3.IntegrityError:
        flash("Username already exists.", "danger")

    return redirect(url_for('superadmin_dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    # Debug=False for production readiness
    app.run(debug=True, port=5000)