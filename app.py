import os
import io
import json
import time
import mimetypes
import requests
import streamlit as st

# ---------- Config ----------
DEFAULT_BASE = os.getenv("CAREPULSE_API_BASE", "https://healthcare-00zk.onrender.com")
st.set_page_config(page_title="CarePulse", page_icon="🫀", layout="wide")

# ---------- State ----------
if "base_url" not in st.session_state: st.session_state.base_url = DEFAULT_BASE
if "api_key"  not in st.session_state: st.session_state.api_key  = ""
if "admin_key" not in st.session_state: st.session_state.admin_key = ""
if "token" not in st.session_state: st.session_state.token = ""
if "me" not in st.session_state: st.session_state.me = None
if "patient_id" not in st.session_state: st.session_state.patient_id = ""

# ---------- Helpers ----------
def headers(extra=None):
    h = {}
    if st.session_state.api_key:
        h["x-api-key"] = st.session_state.api_key
    if st.session_state.token:
        h["Authorization"] = f"Bearer {st.session_state.token}"
    if extra:
        h.update(extra)
    return h

def api_url(path: str) -> str:
    base = st.session_state.base_url.rstrip("/")
    return f"{base}{path}"

def get_json(path: str, hdr=None, params=None):
    r = requests.get(api_url(path), headers=headers(hdr), params=params, timeout=60)
    if not r.ok:
        raise RuntimeError(f"{r.status_code} {r.text}")
    return r.json()

def post_json(path: str, payload: dict, hdr=None, params=None):
    r = requests.post(api_url(path), headers=headers({"Content-Type":"application/json", **(hdr or {})}), json=payload, params=params, timeout=120)
    if not r.ok:
        raise RuntimeError(f"{r.status_code} {r.text}")
    return r.json()

def post_form(path: str, fields: dict, file_field=None):
    files = None
    if file_field is not None:
        up = file_field  # (filename, bytes, mimetype)
        files = {"file": up}
    r = requests.post(api_url(path), headers=headers(), data=fields, files=files, timeout=300)
    if not r.ok:
        raise RuntimeError(f"{r.status_code} {r.text}")
    return r.json()

def login(email: str, password: str):
    data = post_json("/auth/login", {"email": email, "password": password})
    st.session_state.token = data["access_token"]
    me = get_json("/v1/me")
    st.session_state.me = me
    if me.get("patient_id"):
        st.session_state.patient_id = me["patient_id"]

def logout():
    st.session_state.token = ""
    st.session_state.me = None
    st.session_state.patient_id = ""

# ---------- Sidebar ----------
with st.sidebar:
    st.markdown("## 🔧 Settings")
    st.session_state.base_url = st.text_input("API Base URL", st.session_state.base_url, help="Your Render URL (no trailing slash)")
    st.session_state.api_key  = st.text_input("x-api-key (optional)", st.session_state.api_key, help="Only if you added API key guard")
    st.session_state.admin_key = st.text_input("x-admin-key (for cron)", st.session_state.admin_key, type="password")

    st.markdown("---")
    st.markdown("### 👤 Login")
    if not st.session_state.token:
        email = st.text_input("Email", key="email")
        password = st.text_input("Password", type="password", key="password")
        if st.button("Login"):
            try:
                login(email, password)
                st.success("Logged in")
            except Exception as e:
                st.error(f"Login failed: {e}")
    else:
        me = st.session_state.me or {}
        st.caption(f"Signed in as **{me.get('email','user')}** ({me.get('role','patient')})")
        colx1, colx2 = st.columns(2)
        if colx1.button("Refresh /v1/me"):
            try:
                st.session_state.me = get_json("/v1/me")
                if st.session_state.me.get("patient_id"):
                    st.session_state.patient_id = st.session_state.me["patient_id"]
                st.success("Refreshed")
            except Exception as e:
                st.error(e)
        if colx2.button("Logout"):
            logout()
            st.info("Logged out")

st.title("🫀 CarePulse Dashboard")

# Tabs
tabs = st.tabs(["Patient", "Admin"])

# ---------- Patient Tab ----------
with tabs[0]:
    st.subheader("Patient Context")

    # Patient selection / display
    if st.session_state.me and st.session_state.me.get("patient_id"):
        st.info(f"Using patient from /v1/me: `{st.session_state.me['patient_id']}`")
    else:
        st.session_state.patient_id = st.text_input("Patient UUID", st.session_state.patient_id, help="Paste a patient id if user not linked")

    pid = st.session_state.patient_id or (st.session_state.me.get("patient_id") if st.session_state.me else "")

    cols = st.columns(3)
    with cols[0]:
        if st.button("Load Risk", disabled=not pid):
            try:
                risk = get_json("/v1/risk", params={"patient_id": pid, "store": "false"})
                st.session_state["risk"] = risk
                st.success("Risk loaded")
            except Exception as e:
                st.error(e)
    with cols[1]:
        if st.button("Load Meds", disabled=not pid):
            try:
                meds = get_json("/v1/meds", params={"patient_id": pid})
                st.session_state["meds"] = meds
                st.success("Meds loaded")
            except Exception as e:
                st.error(e)
    with cols[2]:
        if st.button("Load Alerts", disabled=not pid):
            try:
                alerts = get_json(f"/v1/alerts/{pid}")
                st.session_state["alerts"] = alerts
                st.success("Alerts loaded")
            except Exception as e:
                st.error(e)

    st.markdown("---")

    # Risk
    st.markdown("### 📈 Readmission Risk")
    risk = st.session_state.get("risk")
    if risk:
        score = float(risk.get("score", 0))
        pct = int(round(score * 100))
        col1, col2, col3 = st.columns([1, 2, 3])
        with col1:
            st.metric("Risk", f"{pct}%", help=f"Bucket: {risk.get('bucket','—')}")
        with col2:
            st.write("**Model**:", risk.get("model_version","—"))
            st.write("**Bucket**:", risk.get("bucket","—"))
        with col3:
            st.write("**Factors**")
            st.json(risk.get("factors", {}))
    else:
        st.info("Click **Load Risk** to view the score and factors.")

    st.markdown("---")

    # Meds table + Ack
    st.markdown("### 💊 Medications")
    meds = st.session_state.get("meds", [])
    if meds:
        st.dataframe(
            [{"id": m["id"], "drug": m["drug_name"], "dose": m.get("dose"), "freq": m["freq"],
              "times": ", ".join(m.get("times_local", []) or []), "tz": m["timezone"]} for m in meds],
            use_container_width=True,
            hide_index=True
        )
        med_ids = [m["id"] for m in meds]
        sel = st.selectbox("Select a medication to acknowledge the most recent scheduled dose", med_ids)
        if st.button("Ack recent dose", disabled=not sel):
            try:
                r = post_json(f"/v1/meds/{sel}/ack", {"source":"ui"})
                st.success(f"Acknowledged dose at {r.get('scheduled_time')}")
                # reload meds
                st.session_state["meds"] = get_json("/v1/meds", params={"patient_id": pid})
            except Exception as e:
                st.error(e)
    else:
        st.info("No meds loaded yet.")

    st.markdown("---")

    # Alerts
    st.markdown("### 🚨 Alerts")
    alerts = st.session_state.get("alerts", [])
    if alerts:
        for a in alerts:
            st.write(f"- **{a['type']}** ({a['severity']}) — {a['message']}  \n  _{a['created_at']}_")
    else:
        st.info("No alerts loaded.")

    st.markdown("---")

    # Uploads
    st.markdown("### 📤 Upload Documents")
    st.caption("Plain text or scans (.txt/.pdf/.jpg). Scans use Google Document AI if configured on the backend.")
    c1, c2 = st.columns(2)

    with c1:
        st.write("**Discharge Summary → Diagnoses**")
        disc_text = st.text_area("Paste discharge text (optional)", key="disc_text", height=120)
        disc_file = st.file_uploader("Or attach .txt/.pdf/.jpg", type=["txt", "pdf", "jpg", "jpeg", "png"], key="disc_file")
        if st.button("Upload Discharge", disabled=not pid):
            try:
                file_tuple = None
                if disc_file is not None:
                    mime = mimetypes.guess_type(disc_file.name)[0] or "application/octet-stream"
                    file_tuple = (disc_file.name, disc_file.getvalue(), mime)
                out = post_form("/v1/docs/discharge_text", {"patient_id": pid, **({"text": disc_text} if disc_text.strip() else {})}, file_tuple)
                st.success(f"Diagnoses created: {out.get('diagnoses_created', 0)}")
            except Exception as e:
                st.error(e)

    with c2:
        st.write("**Pharmacy Sheet → Medications**")
        pharm_text = st.text_area("Paste pharmacy text (optional)", key="pharm_text", height=120)
        pharm_file = st.file_uploader("Or attach .txt/.pdf/.jpg", type=["txt", "pdf", "jpg", "jpeg", "png"], key="pharm_file")
        if st.button("Upload Pharmacy", disabled=not pid):
            try:
                file_tuple = None
                if pharm_file is not None:
                    mime = mimetypes.guess_type(pharm_file.name)[0] or "application/octet-stream"
                    file_tuple = (pharm_file.name, pharm_file.getvalue(), mime)
                out = post_form("/v1/docs/meds_text", {"patient_id": pid, **({"text": pharm_text} if pharm_text.strip() else {})}, file_tuple)
                st.success(f"Medications created: {out.get('medications_created', 0)}")
                # refresh meds list
                st.session_state["meds"] = get_json("/v1/meds", params={"patient_id": pid})
            except Exception as e:
                st.error(e)

# ---------- Admin Tab ----------
with tabs[1]:
    role = (st.session_state.me or {}).get("role")
    if role != "admin":
        st.warning("Admin area is restricted. Log in as an admin, or provide x-admin-key in the sidebar for cron calls.")

    st.subheader("Cron Triggers")
    colA, colB, colC = st.columns(3)
    with colA:
        win = st.number_input("Window (minutes) for reminders", min_value=1, max_value=60, value=10, step=1, key="cron_win")
        if st.button("Trigger Reminders"):
            try:
                out = get_json("/cron/meds/remind_now", hdr={"x-admin-key": st.session_state.admin_key}, params={"window": win})
                st.success(out)
            except Exception as e:
                st.error(e)
    with colB:
        if st.button("Escalate Missed"):
            try:
                out = get_json("/cron/meds/escalate_missed", hdr={"x-admin-key": st.session_state.admin_key})
                st.success(out)
            except Exception as e:
                st.error(e)
    with colC:
        if st.button("Recompute Risk (all)"):
            try:
                out = get_json("/cron/risk/recompute_all", hdr={"x-admin-key": st.session_state.admin_key})
                st.success(out)
            except Exception as e:
                st.error(e)

    st.markdown("---")
    st.subheader("Quick Patient Lookup")
    lookup_pid = st.text_input("Patient UUID", key="admin_lookup_pid")
    if st.button("Load Patient", disabled=not lookup_pid):
        try:
            p = get_json(f"/v1/patients/{lookup_pid}")
            st.json(p)
        except Exception as e:
            st.error(e)
