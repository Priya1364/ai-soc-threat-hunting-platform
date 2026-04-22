import streamlit as st
import sqlite3
import hashlib
import pandas as pd
import re
import joblib
import os
import plotly.express as px

# ---------------- CONFIG ----------------
st.set_page_config(page_title="SOC Platform", layout="wide")

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
    admin_pass = hashlib.sha256("admin@123".encode()).hexdigest()

    c.execute("SELECT * FROM users WHERE username=?", (admin_user,))
    if not c.fetchone():
        c.execute("INSERT INTO users VALUES (?, ?, ?)", (admin_user, admin_pass, "admin"))
        conn.commit()

create_admin()

# ---------------- HASH ----------------
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

# ---------------- SESSION ----------------
if "user" not in st.session_state:
    st.session_state.user = None

# ---------------- MODEL ----------------
@st.cache_resource
def load_model():
    if os.path.exists("model.pkl"):
        return joblib.load("model.pkl"), joblib.load("vectorizer.pkl")

    data = pd.read_csv("sms.tsv", sep="\t", names=["label", "message"])
    data["label"] = data["label"].map({"ham":0,"spam":1})

    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB

    vec = TfidfVectorizer()
    X = vec.fit_transform(data["message"])
    y = data["label"]

    model = MultinomialNB()
    model.fit(X,y)

    joblib.dump(model,"model.pkl")
    joblib.dump(vec,"vectorizer.pkl")

    return model, vec

model, vectorizer = load_model()

# ---------------- AUTH ----------------
def auth():
    st.title("🔐 Secure Login System")

    choice = st.radio("Select", ["Login", "Signup"])

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if choice == "Signup":
        if st.button("Create Account"):
            if len(password) < 6:
                st.error("Weak password ❌")
                return

            c.execute("SELECT * FROM users WHERE username=?", (username,))
            if c.fetchone():
                st.error("User exists ❌")
            else:
                c.execute("INSERT INTO users VALUES (?, ?, ?)",
                          (username, hash_password(password), "user"))
                conn.commit()
                st.success("Account created ✅")

    if choice == "Login":
        if st.button("Login"):
            c.execute("SELECT * FROM users WHERE username=? AND password=?",
                      (username, hash_password(password)))
            user = c.fetchone()

            if user:
                st.session_state.user = username
                st.success("Login success ✅")
                st.rerun()
            else:
                st.error("Invalid credentials ❌")

# ---------------- DASHBOARD ----------------
def dashboard():
    st.sidebar.title(f"👤 {st.session_state.user}")

    menu = st.sidebar.radio("Menu", ["Home","Analyze","History","Trends","Logout"])

    if menu == "Home":
        st.title("🛡 SOC Dashboard")
        st.success("System Active")

    elif menu == "Analyze":
        msg = st.text_area("Enter Message")

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

            st.metric("Risk Score", f"{prob:.2f}%")

            c.execute("INSERT INTO alerts VALUES(?,?,?,?)",
                      (st.session_state.user,msg,prob,status))
            conn.commit()

    elif menu == "History":
        df = pd.read_sql_query(
            f"SELECT * FROM alerts WHERE username='{st.session_state.user}'", conn)
        st.dataframe(df)

    elif menu == "Trends":
        df = pd.read_sql_query("SELECT status FROM alerts", conn)
        st.plotly_chart(px.bar(df["status"].value_counts()))

    elif menu == "Logout":
        st.session_state.user = None
        st.rerun()

# ---------------- MAIN ----------------
if st.session_state.user:
    dashboard()
else:
    auth()

# ---------------- FOOTER ----------------
st.markdown("---")
st.markdown("🚀 Built by Priyadharshini L | Cybersecurity SOC Project")
