import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import time
import re
import joblib
import os
import plotly.express as px
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# ---------------- CONFIG ----------------
st.set_page_config(page_title="AI SOC Threat Hunting", layout="wide")

# ---------------- DATABASE ----------------
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

# ---------------- HASH ----------------
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

# ---------------- ADMIN CREATE ----------------
def create_admin():
    c.execute("SELECT * FROM users WHERE username=?", ("admin",))
    if not c.fetchone():
        c.execute("INSERT INTO users VALUES (?,?,?)",
                  ("admin", hash_password("admin@123"), "admin"))
        conn.commit()

create_admin()

# ---------------- SESSION ----------------
if "user" not in st.session_state:
    st.session_state["user"] = None
if "role" not in st.session_state:
    st.session_state["role"] = None

# ---------------- ML MODEL ----------------
@st.cache_resource
def load_model():
    if os.path.exists("model.pkl"):
        return joblib.load("model.pkl"), joblib.load("vectorizer.pkl")

    data = pd.read_csv("https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv",
                       sep="\t", names=["label","message"])

    data["label"] = data["label"].map({"ham":0,"spam":1})

    vectorizer = TfidfVectorizer(stop_words="english")
    X = vectorizer.fit_transform(data["message"])
    y = data["label"]

    model = MultinomialNB()
    model.fit(X, y)

    joblib.dump(model, "model.pkl")
    joblib.dump(vectorizer, "vectorizer.pkl")

    return model, vectorizer

model, vectorizer = load_model()

# ---------------- AUTH ----------------
def auth():
    st.title("🔐 SOC Login System")

    menu = st.radio("Select", ["Login", "Signup"])

    username = st.text_input("Username")

    if menu == "Signup":
        password = st.text_input("Password", type="password")

        if st.button("Create Account"):
            c.execute("SELECT * FROM users WHERE username=?", (username,))
            if c.fetchone():
                st.warning("User already exists")
            else:
                c.execute("INSERT INTO users VALUES (?,?,?)",
                          (username, hash_password(password), "user"))
                conn.commit()
                st.success("Account created")

    elif menu == "Login":
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            c.execute("SELECT * FROM users WHERE username=? AND password=?",
                      (username, hash_password(password)))
            user = c.fetchone()

            if user:
                st.session_state["user"] = user[0]
                st.session_state["role"] = user[2]
                st.success("Login successful")
                st.rerun()
            else:
                st.error("Invalid credentials")

# ---------------- DASHBOARD ----------------
def dashboard():
    st.sidebar.title(f"👤 {st.session_state['user']}")

    menu = st.sidebar.radio("Menu", [
        "Home", "Analyze", "History", "Trends", "Logout"
    ])

    if menu == "Home":
        st.title("🛡 AI SOC Dashboard")
        st.success("System Active")

    elif menu == "Analyze":
        st.title("📧 Phishing Detection")

        msg = st.text_area("Enter Email / Message")

        if st.button("Analyze"):
            if not msg:
                st.warning("Enter message")
                return

            vec = vectorizer.transform([msg])
            prob = model.predict_proba(vec)[0][1] * 100

            if prob > 70:
                status = "PHISHING"
                st.error("🚨 High Risk")
            elif prob > 40:
                status = "SUSPICIOUS"
                st.warning("⚠ Medium Risk")
            else:
                status = "SAFE"
                st.success("✅ Safe")

            st.write(f"Risk Score: {prob:.2f}%")

            c.execute("INSERT INTO alerts VALUES (?,?,?,?)",
                      (st.session_state["user"], msg, prob, status))
            conn.commit()

    elif menu == "History":
        df = pd.read_sql_query(
            "SELECT * FROM alerts WHERE username=?",
            conn,
            params=(st.session_state["user"],)
        )
        st.dataframe(df)

    elif menu == "Trends":
        df = pd.read_sql_query("SELECT status FROM alerts", conn)

        if not df.empty:
            fig = px.pie(df, names="status", title="Threat Distribution")
            st.plotly_chart(fig)

    elif menu == "Logout":
        st.session_state["user"] = None
        st.session_state["role"] = None
        st.rerun()

# ---------------- MAIN ----------------
if st.session_state["user"]:
    dashboard()
else:
    auth()

st.markdown("---")
st.caption("🚀 Built by Priya | AI SOC Platform")
