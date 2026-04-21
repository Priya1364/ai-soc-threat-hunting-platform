import streamlit as st
import sqlite3
import hashlib
import time
import requests
import pandas as pd
import re
import joblib
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import plotly.express as px

# ---------------- CONFIG ----------------
st.set_page_config(page_title="SOC Platform", layout="wide")

# ---------------- DB ----------------
conn = sqlite3.connect("soc.db", check_same_thread=False)
c = conn.cursor()

c.execute("CREATE TABLE IF NOT EXISTS users(username TEXT, password TEXT, role TEXT)")
c.execute("CREATE TABLE IF NOT EXISTS alerts(username TEXT, message TEXT, risk REAL, status TEXT)")
conn.commit()

# ---------------- HASH ----------------
def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()

# ---------------- SESSION TIMEOUT ----------------
if "last_active" not in st.session_state:
    st.session_state.last_active = time.time()

if time.time() - st.session_state.last_active > 600:
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

# ---------------- URL SCAN ----------------
def scan_url(url):
    api_key = st.secrets["VIRUSTOTAL_API_KEY"]
    headers = {"x-apikey": api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers)

    if response.status_code == 200:
        return "Checked"
    return "Error"

# ---------------- AUTH ----------------
if "user" not in st.session_state:
    st.session_state.user = None

def login():
    st.title("🔐 SOC Login")

    choice = st.selectbox("Select",["Login","Signup"])

    user = st.text_input("Username")
    pwd = st.text_input("Password",type="password")

    if choice=="Signup":
        if st.button("Create"):
            c.execute("INSERT INTO users VALUES(?,?,?)",(user,hash_password(pwd),"user"))
            conn.commit()
            st.success("Account created")

    if choice=="Login":
        if st.button("Login"):
            c.execute("SELECT * FROM users WHERE username=? AND password=?",(user,hash_password(pwd)))
            res=c.fetchone()
            if res:
                st.session_state.user=res[0]
                st.session_state.role=res[2]
            else:
                st.error("Invalid login")

# ---------------- DASHBOARD ----------------
def dashboard():
    st.sidebar.title("SOC MENU")

    menu = st.sidebar.radio("Navigate",["Home","Analyze","Trends","Admin","Logout"])

    if menu=="Home":
        st.title("🛡 SOC Dashboard")
        st.success("System Active")

    if menu=="Analyze":
        msg = st.text_area("Enter message")

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

            urls = re.findall(r'(https?://\S+)', msg)
            for u in urls:
                st.write("URL Scan:", scan_url(u))

            c.execute("INSERT INTO alerts VALUES(?,?,?,?)",(st.session_state.user,msg,prob,status))
            conn.commit()

    if menu=="Trends":
        df = pd.read_sql_query("SELECT status FROM alerts",conn)
        fig = px.bar(df["status"].value_counts(),title="Threat Distribution")
        st.plotly_chart(fig)

    if menu=="Admin":
        if st.session_state.role=="admin":
            df = pd.read_sql_query("SELECT * FROM users",conn)
            st.dataframe(df)
        else:
            st.error("Access denied")

    if menu=="Logout":
        st.session_state.user=None
        st.rerun()

# ---------------- MAIN ----------------
if st.session_state.user:
    dashboard()
else:
    login()

# ---------------- FOOTER ----------------
st.markdown("---")
st.markdown("🚀 Built by Priyadharshini L | Cybersecurity SOC Project")
