from flask import Flask, render_template, request, redirect, session, url_for, flash
import pyodbc
import hashlib
import os
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secure_assignment_key_final'

# --- DATABASE CONNECTION & RLS ---
def get_db():
    # -------------------------------------------------------------------------
    # IMPORTANT: Change 'SERVER=localhost' to your actual server name if needed
    # Example: 'SERVER=DESKTOP-ABC1234\SQLEXPRESS;'
    # -------------------------------------------------------------------------
    conn = pyodbc.connect(
        'DRIVER={ODBC Driver 18 for SQL Server};'
        'SERVER=LAPTOP-7O2M5DER;'  
        'DATABASE=StudentProjectDB;'
        'Trusted_Connection=yes;'
        'TrustServerCertificate=yes;'
    )
    
    # --- ROW-LEVEL SECURITY (RLS) INJECTION ---
    # This ensures that even if our Python code fails, the Database knows who is asking.
    if 'user_id' in session and 'role' in session:
        cursor = conn.cursor()
        # Pass the UserID and RoleID to the SQL Session Context
        cursor.execute("EXEC sp_set_session_context @key=N'UserID', @value=?", (session['user_id'],))
        cursor.execute("EXEC sp_set_session_context @key=N'RoleID', @value=?", (session['role'],))
        cursor.close()
        
    return conn # <--- This MUST be at the bottom for RLS to work!

# --- SECURITY UTILITIES ---
def hash_password(password, salt=None):
    if not salt:
        salt = os.urandom(16).hex()
    # Create SHA256 Hash combined with Salt
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return pwd_hash, salt

# Lecture 4: Password Complexity Policy
def is_password_complex(password):
    if len(password) < 8: return False
    if not re.search(r"[A-Z]", password): return False # At least 1 Uppercase
    if not re.search(r"[0-9]", password): return False # At least 1 Number
    if not re.search(r"[!@#$%^&*]", password): return False # At least 1 Symbol
    return True

# Lecture 5: Time-Based Access Control (Attack Surface Reduction)
def is_login_allowed():
    current_hour = datetime.now().hour
    # Block access between 3 AM and 5 AM (Simulated maintenance/high-risk window)
    if 3 <= current_hour < 5:
        return False
    return True

# --- CONTEXT PROCESSOR ---
# This makes variables available to ALL templates (like the Notification badge)
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
        # 1. Security Check: Time-Based Access
        if not is_login_allowed():
            flash("Maintenance Mode: Logins disabled (3AM-5AM).")
            return render_template('login.html')

        username = request.form['username']
        password = request.form['password']
        
        print(f"DEBUG: Attempting login for: {username}") # DEBUG PRINT

        conn = get_db()
        cursor = conn.cursor()
        
        try:
            # 2. Call Secure Stored Procedure (Prevents SQL Injection)
            # This proc returns: UserID, PasswordHash, Salt, RoleID, Email, Phone
            cursor.execute("{CALL Sec.sp_GetDecryptedUser (?)}", (username,))
            user = cursor.fetchone()
        except Exception as e:
            print(f"DEBUG: Database Error: {e}") # DEBUG PRINT
            flash("Database Error: Check Server Connection in app.py")
            return render_template('login.html')
        
        if user:
            print(f"DEBUG: User found in DB. ID={user[0]}, Role={user[3]}")
            
            # 3. Verify Password (Hash + Salt)
            stored_hash = user[1]
            stored_salt = user[2]
            
            # Re-calculate hash using the input password + stored salt
            calculated_hash = hash_password(password, stored_salt)[0]
            
            if calculated_hash == stored_hash:
                print("DEBUG: Password Verified! Logging in...")
                session['user_id'] = user[0]
                session['role'] = user[3]
                session['username'] = username # Store the input username
                
                # 4. Log the Event (Lecture 2: Auditing)
                cursor.execute("INSERT INTO Sec.AuditLog (ActionType, UserIP, Details) VALUES (?, ?, ?)", 
                               ('LOGIN_SUCCESS', request.remote_addr, f"User {username} logged in"))
                conn.commit()
                conn.close()
                return redirect(url_for('dashboard'))
            else:
                print("DEBUG: Password Mismatch.")
        else:
            print("DEBUG: User not found in database.")

        flash("Invalid Credentials.")
        conn.close()
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # 1. Compliance Check (PDPA)
        if not request.form.get('consent'):
            flash("You must agree to PDPA processing.")
            return render_template('register.html')
        
        # 2. Security Check (Password Complexity)
        if not is_password_complex(request.form['password']):
            flash("Password too weak! (Min 8 chars, Uppercase, Number, Symbol)")
            return render_template('register.html')

        uname = request.form['username']
        pword = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        role = request.form['role']

        pwd_hash, salt = hash_password(pword)
        
        try:
            conn = get_db()
            # 3. Call Secure Procedure (Encrypts Phone Number inside SQL)
            conn.cursor().execute("{CALL Sec.sp_RegisterUser (?, ?, ?, ?, ?, ?)}", 
                                  (uname, pwd_hash, salt, email, phone, role))
            conn.commit()
            conn.close()
            flash("Registration Successful! Please Login.")
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Register Error: {e}")
            flash("Error: Username likely already exists.")
            
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('home'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Check Admin "Attack Surface" Config (Lecture 6)
    cursor.execute("SELECT ConfigValue FROM Sec.SystemConfig WHERE ConfigKey = 'AllowUploads'")
    uploads_allowed = cursor.fetchone()[0]
    
    projects = []
    audit_logs = []
    milestones = {}

    # Fetch Projects (RLS in SQL Server will automatically filter this based on session context!)
    if session['role'] == 3: # Student
        cursor.execute("SELECT * FROM App.Assignments WHERE SubmittedBy = ?", (session['user_id'],))
    else: # Staff/Admin/Examiner
        cursor.execute("SELECT A.*, U.Username FROM App.Assignments A JOIN App.Users U ON A.SubmittedBy = U.UserID")
    
    projects = cursor.fetchall()

    # Admin Only: Fetch Audit Logs
    if session['role'] == 1:
        cursor.execute("SELECT TOP 15 * FROM Sec.AuditLog ORDER BY Timestamp DESC")
        audit_logs = cursor.fetchall()

    # Fetch Milestones for displayed projects
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
    
    # Check "Attack Surface" switch before allowing insert
    cursor.execute("SELECT ConfigValue FROM Sec.SystemConfig WHERE ConfigKey = 'AllowUploads'")
    if cursor.fetchone()[0] == 'FALSE':
        flash("Submissions currently disabled by Admin.")
    else:
        # Use Stored Procedure or Parameterized Query
        cursor.execute("INSERT INTO App.Assignments (ProjectTitle, Description, GitHubLink, SubmittedBy) VALUES (?, ?, ?, ?)", 
                       (request.form['title'], request.form['desc'], request.form['link'], session['user_id']))
        conn.commit()
        flash("Project Submitted.")
        
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:id>')
def delete_project(id):
    # RBAC: Only Admin (1) or Lecturer (2)
    if session.get('role') in [1, 2]: 
        conn = get_db()
        # SQL Trigger 'trg_AuditAssignments' will log this automatically
        conn.cursor().execute("DELETE FROM App.Assignments WHERE AssignmentID = ?", (id,))
        conn.commit()
        conn.close()
        flash("Project Deleted (Logged in Audit Trail).")
    return redirect(url_for('dashboard'))

@app.route('/toggle_security')
def toggle_security():
    if session.get('role') == 1: # Admin Only
        conn = get_db()
        conn.cursor().execute("UPDATE Sec.SystemConfig SET ConfigValue = CASE WHEN ConfigValue = 'TRUE' THEN 'FALSE' ELSE 'TRUE' END WHERE ConfigKey = 'AllowUploads'")
        conn.commit()
        conn.close()
    return redirect(url_for('dashboard'))

# --- EXTRA FEATURES: Milestones, Notifications, Feedback ---

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
    # Mark all as read
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