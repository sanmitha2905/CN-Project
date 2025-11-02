import streamlit as st
import pandas as pd
import joblib

# ---------- Title Section ----------
st.title("🛡️ AI-Based Intrusion Detection System (IDS)")
st.write("Detect network intrusions using trained Machine Learning models (Decision Tree & Random Forest).")

# ---------- Load Models ----------
rf_model = joblib.load("rf_model.pkl")
dt_model = joblib.load("dt_model.pkl")

# ---------- Sidebar Input ----------
st.sidebar.header("📥 Input Network Parameters")
duration = st.sidebar.number_input("Duration", min_value=0, max_value=1000, value=0)
src_bytes = st.sidebar.number_input("Source Bytes", min_value=0, max_value=100000, value=100)
dst_bytes = st.sidebar.number_input("Destination Bytes", min_value=0, max_value=100000, value=50)
count = st.sidebar.number_input("Count", min_value=0, max_value=100, value=5)
srv_count = st.sidebar.number_input("Service Count", min_value=0, max_value=100, value=5)
same_srv_rate = st.sidebar.slider("Same Service Rate", 0.0, 1.0, 0.5)
dst_host_same_srv_rate = st.sidebar.slider("Host Same Service Rate", 0.0, 1.0, 0.5)

# ---------- Model Selection ----------
model_choice = st.sidebar.radio("Select Model", ["Decision Tree", "Random Forest"])

# ---------- Prediction Button ----------
if st.button("🔍 Predict", key="predict_button"):
    # Recreate all 41 features with defaults (0)
    all_features = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
                    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
                    'num_compromised', 'root_shell', 'su_attempted', 'num_root',
                    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
                    'is_host_login', 'is_guest_login', 'count', 'srv_count',
                    'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
                    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
                    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']

    # Make a dict with zeros
    input_dict = {col: 0 for col in all_features}

    # Fill actual values for selected inputs
    input_dict.update({
        'duration': duration,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes,
        'count': count,
        'srv_count': srv_count,
        'same_srv_rate': same_srv_rate,
        'dst_host_same_srv_rate': dst_host_same_srv_rate
    })

    input_data = pd.DataFrame([input_dict])

    # Choose model
    if model_choice == "Decision Tree":
        pred = dt_model.predict(input_data)[0]
    else:
        pred = rf_model.predict(input_data)[0]

    # ---------- Output Display ----------
    if pred == 1:
        st.error("🚨 Suspicious Activity Detected! (Possible Attack)")
    else:
        st.success("✅ Normal Network Traffic Detected.")

# ---------- Footer ----------
st.write("---")
st.caption("Developed by Team 3B9| AI-Based IDS | CN Project 2025")
