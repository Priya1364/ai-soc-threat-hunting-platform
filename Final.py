import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import time
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
</style>
""", unsafe_allow_html=True)

# ---------------- DB ----------------
conn = sqlite3.connect("soc.db", check_same_thread=False)
c = conn.cursor()

c.execute("CREATE TABLE IF NOT EXISTS users(username TEXT, password TEXT, role TEXT, question TEXT, answer TEXT)")
c.execute("CREATE TABLE IF NOT EXISTS alerts(username TEXT, message TEXT, risk REAL, status TEXT)")
conn.commit()

# ---------------- HASH ----------------
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

# ---------------- SESSION TIMEOUT ----------------
if "last_active" not in st.session_state:
    st.session_state.last_active = time.time()

if time.time() - st.session_state.last_active > 900:
    st.session_state.user = None
    st.warning("Session expired")

st.session_state.last_active = time.time()

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

# ---------------- URL ----------------
def extract_urls(text):
    return re.findall(r'(https?://\S+)', text)

def scan_url(url):
    try:
        api_key = st.secrets["VIRUSTOTAL_API_KEY"]
        headers = {"x-apikey": api_key}
        r = requests.get("https://www.virustotal.com/api/v3/urls", headers=headers)
        return "Checked"
    except:
        return "API not configured"

# ---------------- AUTH ----------------
if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None

def auth():
    st.title("🔐 SOC Login System")

    choice = st.selectbox("Choose", ["Login", "Signup", "Forgot Password"])

    username = st.text_input("Username")

    if choice == "Signup":
        password = st.text_input("Password", type="password")
        question = st.text_input("Security Question")
        answer = st.text_input("Answer")

        if st.button("Create Account"):
            c.execute("INSERT INTO users VALUES(?,?,?,?,?)",
                      (username, hash_password(password), "user", question, answer))
            conn.commit()
            st.success("Account created")

    elif choice == "Login":
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            c.execute("SELECT * FROM users WHERE username=? AND password=?",
                      (username, hash_password(password)))
            user = c.fetchone()

            if user:
                st.session_state.user = user[0]
                st.session_state.role = user[2]
                st.success("Login success")
            else:
                st.error("Invalid credentials")

    elif choice == "Forgot Password":
        if st.button("Get Question"):
            c.execute("SELECT question FROM users WHERE username=?", (username,))
            q = c.fetchone()

            if q:
                st.session_state.q = q[0]
                st.session_state.reset_user = username

        if "q" in st.session_state:
            st.write(st.session_state.q)
            ans = st.text_input("Answer")

            if st.button("Reset"):
                c.execute("SELECT * FROM users WHERE username=? AND answer=?",
                          (st.session_state.reset_user, ans))
                if c.fetchone():
                    new_pass = "Temp@123"
                    c.execute("UPDATE users SET password=? WHERE username=?",
                              (hash_password(new_pass), st.session_state.reset_user))
                    conn.commit()
                    st.success(f"New Password: {new_pass}")

# ---------------- DASHBOARD ----------------
def dashboard():
    st.sidebar.title(f"👤 {st.session_state.user}")

    menu = st.sidebar.radio("Menu", ["Home","Analyze","History","Trends","Profile","Admin","Logout"])

    if menu == "Home":
        st.title("🛡 SOC Dashboard")
        st.success("System Active")

    elif menu == "Analyze":
        msg = st.text_area("Enter Message")

        if st.button("Analyze"):
            vec = vectorizer.transform([msg])
            prob = model.predict_proba(vec)[0][1]*100

            if prob>70:
                status="PHISHING"
                st.error("High Risk")
            elif prob>40:
                status="SUSPICIOUS"
                st.warning("Medium Risk")
            else:
                status="SAFE"
                st.success("Safe")

            st.write(f"Risk Score: {prob:.2f}%")

            urls = extract_urls(msg)
            for u in urls:
                st.write(f"{u} → {scan_url(u)}")

            c.execute("INSERT INTO alerts VALUES(?,?,?,?)",
                      (st.session_state.user,msg,prob,status))
            conn.commit()

    elif menu == "History":
        df = pd.read_sql_query(f"SELECT * FROM alerts WHERE username='{st.session_state.user}'", conn)
        st.dataframe(df)

        csv = df.to_csv(index=False)
        st.download_button("Download Report", csv)

    elif menu == "Trends":
        df = pd.read_sql_query("SELECT status FROM alerts", conn)
        fig = px.pie(df, names="status", title="Threat Distribution")
        st.plotly_chart(fig)

    elif menu == "Profile":
        st.write(f"Username: {st.session_state.user}")
        st.write(f"Role: {st.session_state.role}")

    elif menu == "Admin":
        if st.session_state.role == "admin":
            df = pd.read_sql_query("SELECT * FROM users", conn)
            st.dataframe(df)
        else:
            st.error("Access denied")

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
