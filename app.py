import streamlit as st
import sqlite3
import bcrypt
import requests
import fitz  # PyMuPDF
import os
from datetime import datetime
import time

# OpenRouter Setup
API_KEY = "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"
MODEL = "mistralai/mistral-7b-instruct"
API_URL = "https://openrouter.ai/api/v1/chat/completions"

# DB Setup
conn = sqlite3.connect("users.db", check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS history (username TEXT, message TEXT, response TEXT, timestamp TEXT)''')
conn.commit()

# Utility
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def register_user(username, password):
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    if c.fetchone():
        return False
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
    conn.commit()
    return True

def login_user(username, password):
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    result = c.fetchone()
    if result and check_password(password, result[0]):
        return True
    return False

def save_chat(username, user_input, ai_response):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO history (username, message, response, timestamp) VALUES (?, ?, ?, ?)",
              (username, user_input, ai_response, timestamp))
    conn.commit()

def get_user_history(username):
    c.execute("SELECT message, response, timestamp FROM history WHERE username=? ORDER BY timestamp DESC", (username,))
    return c.fetchall()

def get_response(messages):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": MODEL,
        "messages": messages
    }
    res = requests.post(API_URL, headers=headers, json=payload)
    res.raise_for_status()
    return res.json()['choices'][0]['message']['content']

def extract_text_from_pdfs(uploaded_files):
    full_text = ""
    for file in uploaded_files:
        with fitz.open(stream=file.read(), filetype="pdf") as doc:
            for page in doc:
                full_text += page.get_text()
    return full_text

# App Layout
st.set_page_config("🤖 ShekarAI Assistant", layout="centered")

with st.container():
    st.markdown("<h1 style='text-align: center; color: #4F8BF9;'>🤖 Welcome to ShekarAI</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>Your personalized AI assistant — powered by Shekar</p>", unsafe_allow_html=True)

# Session
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.chat_history = [{"role": "system", "content": "You are ShekarAI, a helpful, friendly assistant created by Shekar."}]

# Login/Signup
if not st.session_state.logged_in:
    choice = st.radio("Login / Signup", ["Login", "Signup"])
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if choice == "Signup":
        if st.button("Register"):
            if register_user(username, password):
                st.success("✅ Registered! Please login.")
            else:
                st.error("🚫 Username already exists.")
    else:
        if st.button("Login"):
            if login_user(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.success(f"👋 Welcome back, {username}!")
            else:
                st.error("❌ Invalid login.")

# Main App
if st.session_state.logged_in:
    st.subheader("📁 Upload PDFs and Chat with ShekarAI")

    uploaded_files = st.file_uploader("Upload PDF(s)", type="pdf", accept_multiple_files=True)
    if uploaded_files:
        pdf_text = extract_text_from_pdfs(uploaded_files)
        prompt = f"Summarize this document:\n\n{pdf_text[:2000]}"
        st.session_state.chat_history.append({"role": "user", "content": prompt})
        try:
            with st.spinner("📚 Analyzing PDF(s)..."):
                time.sleep(1)
                summary = get_response(st.session_state.chat_history)
                st.session_state.chat_history.append({"role": "assistant", "content": summary})
                st.markdown("### ✅ PDF Summary")
                st.markdown(summary)
                save_chat(st.session_state.username, prompt, summary)
        except Exception as e:
            st.error(f"❌ PDF Error: {e}")

    prompt = st.chat_input("💬 Ask something to ShekarAI...")
    if prompt:
        st.session_state.chat_history.append({"role": "user", "content": prompt})
        with st.spinner("✍️ ShekarAI is typing..."):
            time.sleep(1)
            try:
                reply = get_response(st.session_state.chat_history)
                st.session_state.chat_history.append({"role": "assistant", "content": reply})
                save_chat(st.session_state.username, prompt, reply)
            except Exception as e:
                reply = f"❌ Error: {e}"
                st.session_state.chat_history.append({"role": "assistant", "content": reply})

    for msg in st.session_state.chat_history[1:]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    with st.expander("📜 Chat History"):
        history = get_user_history(st.session_state.username)
        for msg, resp, ts in history:
            st.markdown(f"🕒 {ts}")
            st.markdown(f"**You:** {msg}")
            st.markdown(f"**ShekarAI:** {resp}")
            st.markdown("---")

    if st.button("🔒 Logout"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.chat_history = [{"role": "system", "content": "You are ShekarAI, a helpful assistant created by Shekar."}]
        st.rerun()
