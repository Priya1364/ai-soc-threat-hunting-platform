import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import re
import joblib
import os
import requests
import plotly.express as px
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# ---------------- CONFIG ----------------
st.set_page_config(page_title="SOC Platform", layout="wide")

# ---------------- STYLE ----------------
st.markdown("""
<style>
body {background-color:#0e1117; color:white;}
h1,h2,h3 {color:#00ffcc;}
.stButton>button {background-color:#00ffcc; color:black;}
</style>
""", unsafe_allow_html=True)

# ---------------- DB ----------------
conn = sqlite3.connect("soc.db", check_same_thread=False)
c = conn.cursor()

c.execute("""CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY,
    password TEXT,
    role TEXT,
    question TEXT,
    answer TEXT
)""")

c.execute("""CREATE TABLE IF NOT EXISTS alerts(
    username TEXT,
    message TEXT,
    risk REAL,
    status TEXT
)""")
conn.commit()

# ---------------- HASH ----------------
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

# ---------------- PASSWORD RULE ----------------
def strong_password(p):
    return (
        len(p) >= 8 and
        re.search(r"[A-Z]", p) and
        re.search(r"[0-9]", p) and
        re.search(r"[!@#$%^&*]", p)
    )

# ---------------- MODEL ----------------
@st.cache_resource
def load_model():
    if os.path.exists("model.pkl"):
        return joblib.load("model.pkl"), joblib.load("vectorizer.pkl")

    data = pd.read_csv("sms.tsv", sep="\t", names=["label", "message"])
    data["label"] = data["label"].map({"ham":0,"spam":1})

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
if "reset_user" not in st.session_state:
    st.session_state.reset_user = None

# ---------------- AUTH ----------------
def auth():
    st.title("🔐 SOC Authentication")

    menu = st.selectbox("Choose", ["Login", "Signup", "Forgot Password"])

    username = st.text_input("Username")

    # -------- SIGNUP --------
    if menu == "Signup":
        password = st.text_input("Password", type="password")
        question = st.text_input("Security Question")
        answer = st.text_input("Answer")

        if st.button("Create Account"):
            if not strong_password(password):
                st.error("Weak password ❌ (8+ chars, uppercase, number, symbol)")
            else:
                c.execute("SELECT * FROM users WHERE username=?", (username,))
                if c.fetchone():
                    st.error("User already exists")
                else:
                    c.execute("INSERT INTO users VALUES(?,?,?,?,?)",
                              (username, hash_password(password), "user", question, answer))
                    conn.commit()
                    st.success("Account created ✅")

    # -------- LOGIN --------
    elif menu == "Login":
        password = st.text_input("Password", type="password")

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

    # -------- FORGOT PASSWORD --------
    elif menu == "Forgot Password":

        if st.button("Get Question"):
            c.execute("SELECT question FROM users WHERE username=?", (username,))
            q = c.fetchone()

            if q:
                st.session_state.reset_user = username
                st.session_state.question = q[0]
            else:
                st.error("User not found")

        if "question" in st.session_state:
            st.write("🔐", st.session_state.question)

            answer = st.text_input("Answer")
            new_pass = st.text_input("New Password", type="password")

            if st.button("Reset Password"):
                c.execute("SELECT * FROM users WHERE username=? AND answer=?",
                          (st.session_state.reset_user, answer))
                user = c.fetchone()

                if user:
                    if not strong_password(new_pass):
                        st.error("Weak password ❌")
                    else:
                        c.execute("UPDATE users SET password=? WHERE username=?",
                                  (hash_password(new_pass), st.session_state.reset_user))
                        conn.commit()
                        st.success("Password updated ✅")
                else:
                    st.error("Wrong answer ❌")

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
        fig = px.pie(df, names="status", title="Threat Distribution")
        st.plotly_chart(fig)

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
st.caption("🚀 Built by Priyadharshini L | SOC Platform")
