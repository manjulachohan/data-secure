import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64decode
from hashlib import pbkdf2_hmac

# data imformation of user
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60 

# section login detalis
if 'authenticated_user' not in st.session_state:
    st.session_state.authenticated_user = None
    
if 'falied_attempts' not in st.session_state:
    st.session_state.failed_attempte = 0    

if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0
   
# if data is load

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}    

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data)
        
def generate_key(passkey):
    key = pbkdf2_hmac("sha256" ,passkey.encode(), SALT, 100000)
    return urlsafe_b64decode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

# cryptograpyh.fernet use
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text, key):
    try:
        cipher= Fernet(generate_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None
    
stored_data = load_data()    
    
# navigation bar
st.title("🔒 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# ---- Home Page ----

if choice == "Home":
    st.subheader("🏠 Welcome To My 🔏 Data Encryption System Using Streamlit!")
    st.markdown("""Develop a Streamlit-based secure data storage and retrieval system where:Users store 
    data with a unique passkey.Users decrypt Users decrypt data by providing the correct passkey. Multiple
    failed attempts result in a forced reauthorization (login page).The system operates entirely in memory 
    without external databases.""")
    
# user registration 
elif choice == "Register":
    st.subheader("📝Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input(" Choose password:", type="password")

    if st.button("Register "):
        if username and password:
            if username in stored_data:
                st.warning("⚠️  User already exisits.")
            else:
                stored_data[username] = {
                   "password": hash_password(password),
                   "data" : []
                }
                save_data(stored_data)
                st.success("✅ User register sucessfull!")
        else:
            st.error("Both fields are required.")  
            
    # --- Login Page  ---      
    elif choice == "Login":
        st.subheader("🔑User Login")          

        if time.time() < st.session_state.lockout_time:
            remaining = int(st. session_state.lockout_time - time.time())
            st.error(f" Too many failed attempts. please wait {remaining} seconds.")
            st.stop()
            
        username = st.text_input("Username")
        password = st.text_input("password", tpye="password")     

        if st.button("Login"):
           if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.filed_attempts = 0
                st.success (f"✅ Wellcome {username}!")

        else:
            st.session_state.failed_attempts += 1
            remaining_attempts = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid Cresentials! Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔒 To many failed attempts! Locked for 60 seconds")
                st.stop()
                 
 # data store section      
elif choice == "Store Data":
    if not st.session_state.authenicated_user:
        st.warning("Please login first.")
    else:
        st.subheader("📦 Store Encrypted Data")  
        data = st.text_area("Enter data to encrpty")  
        passkey = st.text_input("Encryption key (passphrase)", type="password")
    
        if st.button("Encrpyt And Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and save successfully!")    
        else:
            st.error("❌ All fields are required to fill.")
            
# data retieve data section           
elif choice == "Retieve Data":
    if not st.session_state.authenicated_user:
        st.warning("Please login first!")
    else:
        st.subheader("📦 Retieve Data")  
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data",[])
    
        if not user_data:
            st.into("No data entries found.")
        else:
            st.write("Encrypted Data Enteries:")
            for i, item in enumerate(user_data):
                st.code(item,language="text")
            
                
        encrypted_input = st.text_area("Enter Encrypted Text")
        passkey = st.text_input("Enter Passkey T Decrypt", type="password")
            
        if st.button("Decrypt"):
            result = decrypt_text(encrypted_input, passkey)
            if result:
                st.success("f✅ Decrypted : {result}")
            else:
                st.error(" ❌Incorrect passkey or corrupted data. ")    
              

