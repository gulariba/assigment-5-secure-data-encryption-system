import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ---------- 0.  ONE‑TIME APP INITIALISATION ----------
# Put things that must persist across reruns into st.session_state
if "cipher" not in st.session_state:
    KEY = Fernet.generate_key()           # Don’t recreate each rerun
    st.session_state.cipher = Fernet(KEY)
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}     # {enc_text: {"enc": enc_text, "pass": hash}}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

cipher = st.session_state.cipher
stored_data = st.session_state.stored_data


# ---------- 1.  HELPERS ----------
def hash_passkey(passkey: str) -> str:
    """Return SHA‑256 hex digest of a passkey."""
    return hashlib.sha256(passkey.encode()).hexdigest()


def encrypt_data(plaintext: str) -> str:
    """Encrypt text with Fernet; result is url‑safe base64 string."""
    return cipher.encrypt(plaintext.encode()).decode()


def decrypt_data(enc_text: str, passkey: str) -> str | None:
    """Return plaintext if hash matches, else None and count failure."""
    hashed = hash_passkey(passkey)
    data = stored_data.get(enc_text)

    if data and data["pass"] == hashed:
        st.session_state.failed_attempts = 0       # reset counter
        return cipher.decrypt(enc_text.encode()).decode()

    # ---- bad attempt
    st.session_state.failed_attempts += 1
    return None


# ---------- 2.  UI ----------
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# ---- HOME
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write(
        "Use this app to **securely store and retrieve small snippets of text**.\n\n"
        "The demo keeps everything in memory so it resets when the server restarts."
    )

# ---- STORE
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")

    with st.form("store_form", clear_on_submit=True):
        user_text = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Passkey", type="password")
        submitted = st.form_submit_button("Encrypt & Save")

    if submitted:
        if user_text and passkey:
            hashed = hash_passkey(passkey)
            enc_text = encrypt_data(user_text)
            stored_data[enc_text] = {"enc": enc_text, "pass": hashed}
            st.success("✅ Data stored!")
            st.code(enc_text, language="bash")
        else:
            st.error("Both fields are required.")

# ---- RETRIEVE
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")

    if st.session_state.failed_attempts >= 3:
        st.warning("🔒 Too many failed attempts – please log in again.")
        st.switch_page("app.py", anchor="Login")     # jump to login tab
        st.stop()

    with st.form("retrieve_form"):
        enc_text = st.text_area("Paste encrypted text")
        passkey = st.text_input("Passkey", type="password")
        submitted = st.form_submit_button("Decrypt")

    if submitted:
        if enc_text and passkey:
            result = decrypt_data(enc_text, passkey)
            if result:
                st.success("✅ Decrypted:")
                st.write(result)
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
        else:
            st.error("Both fields are required.")

# ---- LOGIN / REAUTHORISE
elif choice == "Login":
    st.subheader("🔑 Reauthorise")
    with st.form("login_form"):
        master = st.text_input("Master password", type="password")
        submit = st.form_submit_button("Log in")

    if submit:
        if master == "admin123":  # demo only!
            st.session_state.failed_attempts = 0
            st.success("✅ Logged in. Go to **Retrieve Data**.")
        else:
            st.error("Incorrect password.")
