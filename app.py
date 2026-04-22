import streamlit as st
import sqlite3
import hashlib
import pandas as pd
import os

# ---------------- CONFIG ----------------
st.set_page_config(page_title="SOC Platform", layout="wide")

# ---------------- DB (PERSISTENT FIX) ----------------
DB_PATH = "soc.db"

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users(
username TEXT PRIMARY KEY,
password TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS alerts(
username TEXT,
message TEXT,
risk REAL,
status TEXT
)
""")
conn.commit()

# ---------------- HASH ----------------
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

# ---------------- CREATE ADMIN ----------------
def create_admin():
    admin_user = "admin"
    admin_pass = hash_password("admin@123")

    c.execute("SELECT * FROM users WHERE username=?", (admin_user,))
    if not c.fetchone():
        c.execute("INSERT INTO users VALUES (?,?)", (admin_user, admin_pass))
        conn.commit()

create_admin()

# ---------------- SESSION ----------------
if "user" not in st.session_state:
    st.session_state.user = None

# ---------------- AUTH ----------------
def auth():
    st.title("🔐 Login System")

    menu = st.radio("Choose", ["Login", "Signup", "Reset Password"])

    username = st.text_input("Username")

    if menu == "Signup":
        password = st.text_input("Password", type="password")

        if st.button("Create"):
            if len(password) < 6:
                st.error("Password too weak")
                return

            c.execute("SELECT * FROM users WHERE username=?", (username,))
            if c.fetchone():
                st.error("User already exists")
            else:
                c.execute("INSERT INTO users VALUES (?,?)",
                          (username, hash_password(password)))
                conn.commit()
                st.success("Account created")

    elif menu == "Login":
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            c.execute("SELECT * FROM users WHERE username=? AND password=?",
                      (username, hash_password(password)))
            user = c.fetchone()

            if user:
                st.session_state.user = username
                st.success("Login success")
                st.rerun()
            else:
                st.error("Invalid credentials")

    elif menu == "Reset Password":
        new_pass = st.text_input("New Password", type="password")

        if st.button("Reset"):
            c.execute("SELECT * FROM users WHERE username=?", (username,))
            if c.fetchone():
                c.execute("UPDATE users SET password=? WHERE username=?",
                          (hash_password(new_pass), username))
                conn.commit()
                st.success("Password updated")
            else:
                st.error("User not found")

# ---------------- DASHBOARD ----------------
def dashboard():
    st.sidebar.title(f"👤 {st.session_state.user}")

    menu = st.sidebar.radio("Menu", ["Home","Add Dummy Alert","View Alerts","Logout"])

    if menu == "Home":
        st.title("🛡 SOC Dashboard")
        st.success("System Running")

    elif menu == "Add Dummy Alert":
        if st.button("Generate Alert"):
            c.execute("INSERT INTO alerts VALUES (?,?,?,?)",
                      (st.session_state.user, "Test phishing message", 85, "PHISHING"))
            conn.commit()
            st.success("Alert added")

    elif menu == "View Alerts":
        df = pd.read_sql_query(
            f"SELECT * FROM alerts WHERE username='{st.session_state.user}'", conn)
        st.dataframe(df)

    elif menu == "Logout":
        st.session_state.user = None
        st.rerun()

# ---------------- MAIN ----------------
if st.session_state.user:
    dashboard()
else:
    auth()

st.markdown("---")
st.caption("Built by Priya")
