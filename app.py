from flask import Flask, render_template, request, redirect, session, url_for, flash
import pyodbc
import hashlib
import os
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secure_assignment_key_final'

# --- DATABASE CONNECTION WITH RLS INJECTION ---
def get_db():
    # 1. Create the connection object (store it in a variable)
    conn = pyodbc.connect(
        'DRIVER={ODBC Driver 18 for SQL Server};'
        'SERVER=LAPTOP-7O2M5DER;'
        'DATABASE=StudentProjectDB;'
        'Trusted_Connection=yes;'
    )
    
    # 2. RLS Security Logic (Now structurally reachable)
    # We check if a user is currently logged in via Flask session
    if 'user_id' in session and 'role' in session:
        cursor = conn.cursor()
        # We inject the current UserID and RoleID into SQL Server's session memory
        # This allows the SQL Security Policy (created in SSMS) to filter rows automatically
        cursor.execute("EXEC sp_set_session_context @key=N'UserID', @value=?", (session['user_id'],))
        cursor.execute("EXEC sp_set_session_context @key=N'RoleID', @value=?", (session['role'],))
        cursor.close()
        
    # 3. Finally, return the configured connection
    return conn
# --- SECURITY UTILITIES ---
def hash_password(password, salt=None):
    if not salt: salt = os.urandom(16).hex()
    return hashlib.sha256((password + salt).encode()).hexdigest(), salt

# Lecture 4: Password Complexity
def is_password_complex(password):
    if len(password) < 8: return False
    if not re.search(r"[A-Z]", password): return False # Uppercase
    if not re.search(r"[0-9]", password): return False # Number
    if not re.search(r"[!@#$%^&*]", password): return False # Symbol
    return True

# Lecture 5: Time-Based Access Control
def is_login_allowed():
    current_hour = datetime.now().hour
    # Prevent login between 3 AM and 5 AM
    if 3 <= current_hour < 5: return False
    return True

# --- CONTEXT PROCESSOR (Global Data for UI) ---
@app.context_processor
def inject_globals():
    if 'user_id' not in session: return {}
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM App.Notifications WHERE UserID = ? AND IsRead = 0", (session['user_id'],))
    count = cursor.fetchone()[0]
    conn.close()
    return {'notif_count': count, 'role': session.get('role'), 'username': session.get('username')}

# --- ROUTES ---

@app.route('/')
def home():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not is_login_allowed():
            flash("Maintenance Mode: Logins disabled (3AM-5AM).")
            return render_template('login.html')

        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("{CALL Sec.sp_GetDecryptedUser (?)}", (username,))
        user = cursor.fetchone()
        
        if user and hash_password(password, user[2])[0] == user[1]:
            session['user_id'] = user[0]
            session['role'] = user[3]
            session['username'] = user[5]
            
            # Audit Login
            cursor.execute("INSERT INTO Sec.AuditLog (ActionType, UserIP, Details) VALUES (?, ?, ?)", 
                           ('LOGIN_SUCCESS', request.remote_addr, f"User {username} logged in"))
            conn.commit()
            conn.close()
            return redirect(url_for('dashboard'))
        
        flash("Invalid Credentials.")
        conn.close()
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not request.form.get('consent'):
            flash("PDPA Consent Required.")
            return render_template('register.html')
        
        if not is_password_complex(request.form['password']):
            flash("Weak Password! Use 8+ chars, Uppercase, Number, Symbol.")
            return render_template('register.html')

        pwd_hash, salt = hash_password(request.form['password'])
        try:
            conn = get_db()
            conn.cursor().execute("{CALL Sec.sp_RegisterUser (?, ?, ?, ?, ?, ?)}", 
                                  (request.form['username'], pwd_hash, salt, 
                                   request.form['email'], request.form['phone'], request.form['role']))
            conn.commit()
            conn.close()
            flash("Registration Successful.")
            return redirect(url_for('login'))
        except:
            flash("Error: Username likely taken.")
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('home'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Check Admin Config (Lecture 6)
    cursor.execute("SELECT ConfigValue FROM Sec.SystemConfig WHERE ConfigKey = 'AllowUploads'")
    uploads_allowed = cursor.fetchone()[0]
    
    projects = []
    audit_logs = []
    milestones = {}

    # Fetch Projects based on Role
    if session['role'] == 3: # Student
        cursor.execute("SELECT * FROM App.Assignments WHERE SubmittedBy = ?", (session['user_id'],))
    else: # Admin, Lecturer, Examiner
        cursor.execute("SELECT A.*, U.Username FROM App.Assignments A JOIN App.Users U ON A.SubmittedBy = U.UserID")
    
    projects = cursor.fetchall()

    # Fetch Audit Logs (Admin Only)
    if session['role'] == 1:
        cursor.execute("SELECT TOP 15 * FROM Sec.AuditLog ORDER BY Timestamp DESC")
        audit_logs = cursor.fetchall()

    # Fetch Milestones
    for p in projects:
        pid = p[0]
        cursor.execute("SELECT MilestoneID, TaskName, IsCompleted FROM App.Milestones WHERE AssignmentID = ?", (pid,))
        milestones[pid] = cursor.fetchall()

    conn.close()
    return render_template('dashboard.html', projects=projects, audit_logs=audit_logs, 
                           milestones=milestones, uploads_allowed=uploads_allowed)

@app.route('/submit', methods=['POST'])
def submit():
    conn = get_db()
    cursor = conn.cursor()
    # Check "Attack Surface" switch
    cursor.execute("SELECT ConfigValue FROM Sec.SystemConfig WHERE ConfigKey = 'AllowUploads'")
    if cursor.fetchone()[0] == 'FALSE':
        flash("Submissions currently disabled by Admin.")
    else:
        cursor.execute("INSERT INTO App.Assignments (ProjectTitle, Description, GitHubLink, SubmittedBy) VALUES (?, ?, ?, ?)", 
                       (request.form['title'], request.form['desc'], request.form['link'], session['user_id']))
        conn.commit()
        flash("Project Submitted.")
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:id>')
def delete_project(id):
    if session['role'] in [1, 2]: # Admin or Lecturer
        conn = get_db()
        conn.cursor().execute("DELETE FROM App.Assignments WHERE AssignmentID = ?", (id,))
        conn.commit()
        conn.close()
        flash("Project Deleted (Audited).")
    return redirect(url_for('dashboard'))

@app.route('/toggle_security')
def toggle_security():
    if session['role'] == 1: # Admin Only
        conn = get_db()
        conn.cursor().execute("UPDATE Sec.SystemConfig SET ConfigValue = CASE WHEN ConfigValue = 'TRUE' THEN 'FALSE' ELSE 'TRUE' END WHERE ConfigKey = 'AllowUploads'")
        conn.commit()
        conn.close()
    return redirect(url_for('dashboard'))

# --- EXTRAS: Milestones, Notifications, Feedback ---
@app.route('/add_milestone', methods=['POST'])
def add_milestone():
    conn = get_db()
    conn.cursor().execute("INSERT INTO App.Milestones (AssignmentID, TaskName) VALUES (?, ?)", 
                          (request.form['assign_id'], request.form['task']))
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