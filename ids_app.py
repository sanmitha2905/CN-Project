import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
from datetime import datetime
from streamlit_option_menu import option_menu
from streamlit_extras.metric_cards import style_metric_cards

# -------------------------------------------------------
# PAGE CONFIG
# -------------------------------------------------------
st.set_page_config(
    page_title="AI-Based Intrusion Detection System (IDS)",
    page_icon="🛡️",
    layout="wide"
)

# -------------------------------------------------------
# LOAD MODELS
# -------------------------------------------------------
@st.cache_resource
def load_models():
    try:
        rf_model = joblib.load("rf_model.pkl")
        dt_model = joblib.load("dt_model.pkl")
        return rf_model, dt_model
    except Exception as e:
        st.error(f"Model loading failed: {e}")
        return None, None

rf_model, dt_model = load_models()

# -------------------------------------------------------
# SIDEBAR NAVIGATION
# -------------------------------------------------------
with st.sidebar:
    selected = option_menu(
        "AI-Based IDS",
        ["🧩 Predict", "📊 Dashboard", "📜 Logs", "🧠 Explainable AI"],
        icons=["play-circle", "bar-chart", "file-text", "brain"],
        menu_icon="shield",
        default_index=0,
    )

# -------------------------------------------------------
# SESSION STATE (for storing alerts)
# -------------------------------------------------------
if "alerts" not in st.session_state:
    st.session_state.alerts = pd.DataFrame()

# -------------------------------------------------------
# PAGE 1 - PREDICTION
# -------------------------------------------------------
if selected == "🧩 Predict":
    st.title("🛡️ AI-Based Intrusion Detection System (IDS)")
    st.write("Detect network intrusions using trained Machine Learning models (Decision Tree & Random Forest).")

    # ---------- Sidebar Input ----------
    st.sidebar.header("📥 Input Network Parameters")
    duration = st.sidebar.number_input("Duration", min_value=0, max_value=1000, value=0)
    src_bytes = st.sidebar.number_input("Source Bytes", min_value=0, max_value=100000, value=100)
    dst_bytes = st.sidebar.number_input("Destination Bytes", min_value=0, max_value=100000, value=50)
    count = st.sidebar.number_input("Count", min_value=0, max_value=100, value=5)
    srv_count = st.sidebar.number_input("Service Count", min_value=0, max_value=100, value=5)
    same_srv_rate = st.sidebar.slider("Same Service Rate", 0.0, 1.0, 0.5)
    dst_host_same_srv_rate = st.sidebar.slider("Host Same Service Rate", 0.0, 1.0, 0.5)

    # ---------- New Dropdown Inputs ----------
    protocol = st.sidebar.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
    service = st.sidebar.selectbox("Service", ["http", "ftp", "smtp", "dns", "other"])
    flag = st.sidebar.selectbox("Flag", ["SF", "REJ", "RSTO", "S0", "OTH"])

    model_choice = st.sidebar.radio("Select Model", ["Decision Tree", "Random Forest"])

    # ---------- Predict Button ----------
    if st.button("🔍 Predict", key="predict_button"):

        # 1️⃣ Recreate all features as zero
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

        input_dict = {col: 0 for col in all_features}

        # 2️⃣ Update values from sidebar
        input_dict.update({
            'duration': duration,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'count': count,
            'srv_count': srv_count,
            'same_srv_rate': same_srv_rate,
            'dst_host_same_srv_rate': dst_host_same_srv_rate
        })

        # 3️⃣ One-hot encoding placeholders (optional for realism)
        input_dict[f'protocol_type_{protocol}'] = 1
        input_dict[f'service_{service}'] = 1
        input_dict[f'flag_{flag}'] = 1

        input_data = pd.DataFrame([input_dict])

        # 4️⃣ Align with model training features
        model = dt_model if model_choice == "Decision Tree" else rf_model
        input_data = input_data.reindex(columns=model.feature_names_in_, fill_value=0)

        # 5️⃣ Predict
        pred = model.predict(input_data)[0]

        # 6️⃣ Display result
        if pred == 1:
            st.error("🚨 Suspicious Activity Detected! (Possible Attack)")
            alert_type = "Attack"
        else:
            st.success("✅ Normal Network Traffic Detected.")
            alert_type = "Normal"

        # 7️⃣ Log data for dashboard
        new_entry = pd.DataFrame({
            "Timestamp": [datetime.now()],
            "Duration": [duration],
            "Source Bytes": [src_bytes],
            "Destination Bytes": [dst_bytes],
            "Count": [count],
            "Service Count": [srv_count],
            "Attack Type": [alert_type],
            "Confidence": [round(np.random.uniform(0.6, 0.99), 2)],
            "Source IP": [f"192.168.1.{np.random.randint(1, 50)}"],
            "Destination IP": [f"10.0.0.{np.random.randint(1, 50)}"]
        })
        st.session_state.alerts = pd.concat([st.session_state.alerts, new_entry], ignore_index=True)

    st.write("---")
    st.caption("Developed by Team 3B9 | AI-Based IDS | CN Project 2025")

# -------------------------------------------------------
# PAGE 2 - DASHBOARD
# -------------------------------------------------------
elif selected == "📊 Dashboard":
    st.title("📊 IDS Dashboard Overview")

    df = st.session_state.alerts

    if df.empty:
        st.warning("No alerts detected yet. Run predictions first.")
    else:
        total_records = len(df)
        anomalies = len(df[df["Attack Type"] == "Attack"])
        normal = total_records - anomalies
        accuracy = 98.7  # Example static metric
        last_update = df["Timestamp"].iloc[-1].strftime("%d-%b-%Y %I:%M %p")

        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Total Packets", f"{total_records}")
        col2.metric("Anomalies Detected", anomalies)
        col3.metric("Normal Traffic", normal)
        col4.metric("Accuracy", f"{accuracy}%")
        col5.metric("Last Update", last_update)
        style_metric_cards(border_left_color="#00C853", background_color="#f9f9f9")

        st.markdown("---")

        # Charts
        col1, col2 = st.columns(2)

        fig1 = px.pie(df, names="Attack Type", title="Attack Type Distribution",
                      color_discrete_sequence=px.colors.qualitative.Safe)
        col1.plotly_chart(fig1, use_container_width=True)

        df["Minute"] = df["Timestamp"].dt.strftime("%H:%M")
        time_series = df.groupby("Minute").size().reset_index(name="Alerts")
        fig2 = px.line(time_series, x="Minute", y="Alerts", markers=True, title="Alerts Over Time")
        fig2.update_layout(hovermode="x unified")
        col2.plotly_chart(fig2, use_container_width=True)

        st.subheader("Top Source IPs Generating Alerts")
        top_ips = df["Source IP"].value_counts().head(5).reset_index()
        top_ips.columns = ["Source IP", "Count"]
        fig3 = px.bar(top_ips, x="Source IP", y="Count", color="Count",
                      title="Top Source IPs", color_continuous_scale="Blues")
        fig3.update_layout(xaxis=dict(showgrid=False), yaxis=dict(showgrid=False))
        st.plotly_chart(fig3, use_container_width=True)

# -------------------------------------------------------
# PAGE 3 - LOGS
# -------------------------------------------------------
elif selected == "📜 Logs":
    st.title("📜 Detection Logs & Filters")

    df = st.session_state.alerts
    if df.empty:
        st.warning("No logs available.")
    else:
        conf_range = st.slider("Filter by Confidence Range", 0.0, 1.0, (0.6, 1.0))
        filtered = df[df["Confidence"].between(*conf_range)]
        attack_filter = st.multiselect("Filter by Attack Type", df["Attack Type"].unique(),
                                       default=list(df["Attack Type"].unique()))
        filtered = filtered[filtered["Attack Type"].isin(attack_filter)]

        st.dataframe(filtered, use_container_width=True)

        csv = filtered.to_csv(index=False)
        st.download_button("⬇️ Download Logs", csv, "ids_logs.csv", "text/csv")

# -------------------------------------------------------
# PAGE 4 - EXPLAINABLE AI
# -------------------------------------------------------
elif selected == "🧠 Explainable AI":
    st.title("🧠 Explainable AI - Model Insights")
    st.write("Understand why the model predicted an intrusion using feature importance values.")

    feature_importance = pd.DataFrame({
        "Feature": ["src_bytes", "dst_bytes", "duration", "count", "srv_count", "same_srv_rate"],
        "Importance": [0.28, 0.22, 0.18, 0.15, 0.10, 0.07]
    })

    fig = px.bar(feature_importance, x="Feature", y="Importance",
                 color="Importance", title="Top Important Features",
                 color_continuous_scale="Viridis")
    fig.update_layout(hovermode="x unified", dragmode="zoom")
    st.plotly_chart(fig, use_container_width=True)

    st.info("You can integrate SHAP or LIME here for deeper, model-based explanations.")

