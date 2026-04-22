import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import re
import joblib
import os
import plotly.express as px

# ---------------- CONFIG ----------------
st.set_page_config(page_title="SOC Threat Hunting Platform", layout="wide")

# ---------------- DB ----------------
conn = sqlite3.connect("soc.db", check_same_thread=False)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS users(
username TEXT PRIMARY KEY,
password TEXT,
role TEXT
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

# ---------------- DEFAULT ADMIN ----------------
def create_admin():
    admin_user = "admin"
    admin_pass = hashlib.sha256("Admin@123".encode()).hexdigest()
    c.execute("SELECT * FROM users WHERE username=?", (admin_user,))
    if not c.fetchone():
        c.execute("INSERT INTO users VALUES (?,?,?)",
                  (admin_user, admin_pass, "admin"))
        conn.commit()

create_admin()

# ---------------- HASH ----------------
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

# ---------------- MODEL ----------------
@st.cache_resource
def load_model():
    if os.path.exists("model.pkl"):
        return joblib.load("model.pkl"), joblib.load("vectorizer.pkl")

    data = pd.read_csv("sms.tsv", sep="\t", names=["label", "message"])
    data["label"] = data["label"].map({"ham":0,"spam":1})

    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB

    vec = TfidfVectorizer(stop_words="english")
    X = vec.fit_transform(data["message"])
    y = data["label"]

    model = MultinomialNB()
    model.fit(X,y)

    joblib.dump(model,"model.pkl")
    joblib.dump(vec,"vectorizer.pkl")

    return model, vec

model, vectorizer = load_model()

# ---------------- SESSION ----------------
if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None

# ---------------- AUTH ----------------
def auth():
    st.title("🔐 SOC Login")

    choice = st.selectbox("Choose", ["Login", "Signup"])

    username = st.text_input("Username")

    if choice == "Signup":
        password = st.text_input("Password", type="password")

        if st.button("Create Account"):
            c.execute("SELECT * FROM users WHERE username=?", (username,))
            if c.fetchone():
                st.error("User already exists ❌")
            else:
                c.execute("INSERT INTO users VALUES (?,?,?)",
                          (username, hash_password(password), "user"))
                conn.commit()
                st.success("Account created ✅")

    elif choice == "Login":
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            c.execute("SELECT * FROM users WHERE username=? AND password=?",
                      (username, hash_password(password)))
            user = c.fetchone()

            if user:
                st.session_state.user = user[0]
                st.session_state.role = user[2]
                st.success("Login successful ✅")
                st.rerun()
            else:
                st.error("Invalid credentials ❌")

# ---------------- DASHBOARD ----------------
def dashboard():
    st.sidebar.title(f"👤 {st.session_state.user}")

    menu = st.sidebar.radio("Menu",
                            ["Home","Analyze","History","Trends","Profile","Admin","Logout"])

    # ---------------- HOME ----------------
    if menu == "Home":
        st.title("🛡 SOC Dashboard")

        total = pd.read_sql_query("SELECT COUNT(*) as c FROM alerts", conn)["c"][0]
        phishing = pd.read_sql_query("SELECT COUNT(*) as c FROM alerts WHERE status='PHISHING'", conn)["c"][0]

        col1, col2 = st.columns(2)
        col1.metric("Total Alerts", total)
        col2.metric("Phishing Attacks", phishing)

        st.info("System Monitoring Active 🚀")

    # ---------------- ANALYZE ----------------
    elif menu == "Analyze":
        st.title("🔍 Analyze Message")

        msg = st.text_area("Enter message")

        if st.button("Analyze"):
            vec = vectorizer.transform([msg])
            prob = model.predict_proba(vec)[0][1]*100

            if prob > 70:
                status = "PHISHING"
                st.error("🔴 High Risk")
            elif prob > 40:
                status = "SUSPICIOUS"
                st.warning("🟠 Medium Risk")
            else:
                status = "SAFE"
                st.success("🟢 Safe")

            st.write(f"Risk Score: {prob:.2f}%")

            c.execute("INSERT INTO alerts VALUES (?,?,?,?)",
                      (st.session_state.user, msg, prob, status))
            conn.commit()

    # ---------------- HISTORY ----------------
    elif menu == "History":
        df = pd.read_sql_query(
            f"SELECT * FROM alerts WHERE username='{st.session_state.user}'", conn)
        st.dataframe(df)

    # ---------------- TRENDS ----------------
    elif menu == "Trends":
        df = pd.read_sql_query("SELECT status FROM alerts", conn)
        fig = px.bar(df["status"].value_counts(), title="Threat Trends")
        st.plotly_chart(fig)

    # ---------------- PROFILE ----------------
    elif menu == "Profile":
        st.write(f"Username: {st.session_state.user}")
        st.write(f"Role: {st.session_state.role}")

    # ---------------- ADMIN ----------------
    elif menu == "Admin":
        if st.session_state.role == "admin":
            st.title("👑 Admin Panel")
            users = pd.read_sql_query("SELECT * FROM users", conn)
            st.dataframe(users)
        else:
            st.error("Access denied ❌")

    # ---------------- LOGOUT ----------------
    elif menu == "Logout":
        st.session_state.user = None
        st.rerun()

# ---------------- MAIN ----------------
if st.session_state.user:
    dashboard()
else:
    auth()
   ---------------- FOOTER ----------------

st.markdown("---")
st.markdown("🚀 Built by Priyadharshini L | Cybersecurity SOC Project") 
