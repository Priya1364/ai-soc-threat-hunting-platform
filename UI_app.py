if "user" not in st.session_state:
    st.session_state.user = None

st.title("🔐 Login System")

option = st.radio("Choose", ["Login", "Signup"])

username = st.text_input("Username")
password = st.text_input("Password", type="password")

if option == "Signup":
    if st.button("Create Account"):
        if signup(username, password):
            st.success("Account created! Now login")
        else:
            st.error("User already exists")

if option == "Login":
    if st.button("Login"):
        user = login_user(username, password)
        if user:
            st.session_state.user = username
            st.success("Login successful")
        else:
            st.error("Invalid credentials")
