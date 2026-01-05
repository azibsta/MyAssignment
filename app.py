from flask import Flask, render_template, request, redirect, session, url_for, flash
import pyodbc
import hashlib
import os
import re
from datetime import datetime
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

# [SECURITY] Use Environment Variable for Secret Key
app.secret_key = os.getenv('FLASK_SECRET', 'dev_fallback_key_do_not_use_in_prod')
csrf = CSRFProtect(app)
# --- DATABASE CONNECTION ---
def get_db():
    conn = pyodbc.connect(
        'DRIVER={ODBC Driver 18 for SQL Server};'
        'SERVER=localhost;'  
        'DATABASE=StudentProjectDB;'
        'Trusted_Connection=yes;'
        'TrustServerCertificate=yes;'
    )
    
    # [SECURITY] Inject User Context (ID, Role, IP) for RLS and Auditing
    if 'user_id' in session and 'role' in session:
        cursor = conn.cursor()
        cursor.execute("EXEC sp_set_session_context @key=N'UserID', @value=?", (session['user_id'],))
        cursor.execute("EXEC sp_set_session_context @key=N'RoleID', @value=?", (session['role'],))
        
        try:
            client_ip = request.remote_addr
            cursor.execute("EXEC sp_set_session_context @key=N'UserIP', @value=?", (client_ip,))
        except:
            pass
        cursor.close()
        
    return conn

# --- UTILS ---
def hash_password(password, salt=None):
    if not salt: salt = os.urandom(16).hex()
    return hashlib.sha256((password + salt).encode()).hexdigest(), salt

def is_password_complex(password):
    return len(password) >= 8 and re.search(r"[A-Z]", password) and re.search(r"[0-9]", password) and re.search(r"[!@#$%^&*]", password)

def is_login_allowed():
    return not (3 <= datetime.now().hour < 5)

@app.context_processor
def inject_globals():
    if 'user_id' not in session: return {}
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM App.Notifications WHERE UserID = ? AND IsRead = 0", (session['user_id'],))
        count = cursor.fetchone()[0]
        conn.close()
        return {'notif_count': count, 'role': session.get('role'), 'username': session.get('username')}
    except:
        return {}

# --- ROUTES ---
@app.route('/')
def home():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not is_login_allowed():
            flash("Maintenance Mode (3AM-5AM)")
            return render_template('login.html')

        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("{CALL Sec.sp_GetDecryptedUser (?)}", (username,))
            user = cursor.fetchone()
            
            if user and hash_password(password, user[2])[0] == user[1]:
                session['user_id'] = user[0]
                session['role'] = user[3]
                session['username'] = username
                
                # [LOGGING] Log Login Success
                cursor.execute("INSERT INTO Sec.AuditLog (ActionType, TableName, RecordID, UserID, UserIP, Details) VALUES (?, ?, ?, ?, ?, ?)",
                               ('LOGIN_SUCCESS', 'App.Users', str(user[0]), user[0], request.remote_addr, f"User {username} logged in"))
                conn.commit()
                conn.close()
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid Credentials")
        except Exception as e:
            print(e)
            flash("Database Error")
        conn.close()
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not request.form.get('consent'):
            flash("You must agree to PDPA.")
            return render_template('register.html')
        if not is_password_complex(request.form['password']):
            flash("Weak Password")
            return render_template('register.html')

        # [SECURITY] Force Role = 3 (Student)
        role = 3
        pwd_hash, salt = hash_password(request.form['password'])
        
        try:
            conn = get_db()
            conn.cursor().execute("{CALL Sec.sp_RegisterUser (?, ?, ?, ?, ?, ?)}", 
                                  (request.form['username'], pwd_hash, salt, request.form['email'], request.form['phone'], role))
            conn.commit()
            conn.close()
            flash("Registered! Please Login.")
            return redirect(url_for('login'))
        except:
            flash("Username likely exists.")
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('home'))
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT ConfigValue FROM Sec.SystemConfig WHERE ConfigKey = 'AllowUploads'")
    uploads_allowed = cursor.fetchone()[0]
    
    # Fetch Projects
    # NEW CODE (Secure: Relies on SQL RLS)
    # We ask for EVERYTHING. The Database will silently remove rows the user isn't allowed to see.
    cursor.execute("SELECT A.*, U.Username FROM App.Assignments A JOIN App.Users U ON A.SubmittedBy = U.UserID")
    projects = cursor.fetchall()
    
    audit_logs = []
    feedbacks = [] # NEW: Variable to store feedback

    if session['role'] == 1:
        # 1. Fetch Audit Logs
        cursor.execute("SELECT TOP 15 * FROM Sec.AuditLog ORDER BY Timestamp DESC")
        audit_logs = cursor.fetchall()

        # 2. [NEW] Fetch User Feedback
        cursor.execute("""
            SELECT F.DateCreated, F.IssueType, F.Message, U.Username 
            FROM App.Feedback F 
            JOIN App.Users U ON F.SubmittedBy = U.UserID 
            ORDER BY F.DateCreated DESC
        """)
        feedbacks = cursor.fetchall()

    milestones = {}
    for p in projects:
        cursor.execute("SELECT MilestoneID, TaskName, IsCompleted FROM App.Milestones WHERE AssignmentID = ?", (p[0],))
        milestones[p[0]] = cursor.fetchall()
        
    conn.close()
    return render_template('dashboard.html', projects=projects, audit_logs=audit_logs, 
                           feedbacks=feedbacks, milestones=milestones, uploads_allowed=uploads_allowed)

@app.route('/submit', methods=['POST'])
def submit():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT ConfigValue FROM Sec.SystemConfig WHERE ConfigKey = 'AllowUploads'")
    if cursor.fetchone()[0] == 'FALSE':
        flash("Submissions Disabled")
    else:
        cursor.execute("INSERT INTO App.Assignments (ProjectTitle, Description, GitHubLink, SubmittedBy) VALUES (?, ?, ?, ?)", 
                       (request.form['title'], request.form['desc'], request.form['link'], session['user_id']))
        conn.commit()
        flash("Project Submitted")
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:id>', methods=['POST'])
def delete_project(id):
    if session.get('role') in [1, 2]:
        conn = get_db()
        conn.cursor().execute("DELETE FROM App.Assignments WHERE AssignmentID = ?", (id,))
        conn.commit()
        conn.close()
        flash("Project Deleted")
    return redirect(url_for('dashboard'))

@app.route('/toggle_security', methods=['POST'])
def toggle_security():
    if session.get('role') == 1:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE Sec.SystemConfig SET ConfigValue = CASE WHEN ConfigValue = 'TRUE' THEN 'FALSE' ELSE 'TRUE' END WHERE ConfigKey = 'AllowUploads'")
        # [LOGGING] Log Config Change
        cursor.execute("INSERT INTO Sec.AuditLog (ActionType, TableName, RecordID, UserID, UserIP, Details) VALUES (?, ?, ?, ?, ?, ?)",
                       ('TOGGLE_SECURITY', 'Sec.SystemConfig', 'AllowUploads', session['user_id'], request.remote_addr, 'Admin toggled upload permission'))
        conn.commit()
        conn.close()
    return redirect(url_for('dashboard'))

@app.route('/add_milestone', methods=['POST'])
def add_milestone():
    conn = get_db()
    conn.cursor().execute("INSERT INTO App.Milestones (AssignmentID, TaskName) VALUES (?, ?)", (request.form['assign_id'], request.form['task']))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/toggle_milestone/<int:mid>')
def toggle_milestone(mid):
    conn = get_db()
    conn.cursor().execute("UPDATE App.Milestones SET IsCompleted = 1 - IsCompleted WHERE MilestoneID = ?", (mid,))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/notifications')
def notifications():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT Message, DateCreated FROM App.Notifications WHERE UserID = ? ORDER BY DateCreated DESC", (session['user_id'],))
    data = cursor.fetchall()
    cursor.execute("UPDATE App.Notifications SET IsRead = 1 WHERE UserID = ?", (session['user_id'],))
    conn.commit()
    conn.close()
    return render_template('notifications.html', notifications=data)

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        conn = get_db()
        conn.cursor().execute("INSERT INTO App.Feedback (SubmittedBy, IssueType, Message) VALUES (?, ?, ?)", 
                              (session['user_id'], request.form['type'], request.form['msg']))
        conn.commit()
        conn.close()
        flash("Feedback Sent.")
        return redirect(url_for('dashboard'))
    return render_template('feedback.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)