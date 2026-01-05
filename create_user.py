import pyodbc
import hashlib
import os

# 1. Database Connection (Same as app.py)
def get_db():
    conn = pyodbc.connect(
        'DRIVER={ODBC Driver 18 for SQL Server};'
        'SERVER=localhost;'  # Ensure this matches your app.py
        'DATABASE=StudentProjectDB;'
        'Trusted_Connection=yes;'
        'TrustServerCertificate=yes;'
    )
    return conn

# 2. Security Utils (Same as app.py)
def hash_password(password, salt=None):
    if not salt:
        salt = os.urandom(16).hex()
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return pwd_hash, salt

def create_user():
    print("--- INTERNAL USER CREATION TOOL ---")
    username = input("Enter Username: ")
    password = input("Enter Password: ")
    email = input("Enter Email: ")
    phone = input("Enter Phone: ")
    
    print("\nSelect Role:")
    print("1 - Admin")
    print("2 - Lecturer")
    print("3 - Student")
    print("4 - External Examiner")
    role = input("Role ID: ")

    # Generate Secure Hash
    pwd_hash, salt = hash_password(password)

    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Call the existing secure Stored Procedure
        cursor.execute("{CALL Sec.sp_RegisterUser (?, ?, ?, ?, ?, ?)}", 
                       (username, pwd_hash, salt, email, phone, role))
        conn.commit()
        print(f"\nSUCCESS! User '{username}' created with Role ID {role}.")
        
    except Exception as e:
        print(f"\nERROR: {e}")
        print("(Username might already exist)")
    finally:
        conn.close()

if __name__ == "__main__":
    create_user()