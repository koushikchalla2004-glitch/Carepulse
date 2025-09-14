import os
import json
import mimetypes
import requests
import streamlit as st

# ================== CONFIG ==================
DEFAULT_BASE = os.getenv("CAREPULSE_API_BASE", "https://healthcare-00zk.onrender.com")
st.set_page_config(page_title="CarePulse", page_icon="🫀", layout="wide")

# ================== STATE ==================
def init_state():
    ss = st.session_state
    ss.setdefault("base_url", DEFAULT_BASE.rstrip("/"))
    ss.setdefault("api_key", "")
    ss.setdefault("admin_key", "")
    ss.setdefault("token", "")
    ss.setdefault("me", None)
    ss.setdefault("risk", None)
    ss.setdefault("meds", [])
    ss.setdefault("alerts", [])

init_state()

# ================== HELPERS ==================
def api_url(path: str) -> str:
    return f"{st.session_state.base_url}{path}"

def headers(extra=None):
    h = {}
    if st.session_state.api_key:
        h["x-api-key"] = st.session_state.api_key
    if st.session_state.token:
        h["Authorization"] = f"Bearer {st.session_state.token}"
    if extra: h.update(extra)
    return h

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

def post_form(path: str, fields: dict, file_tuple=None):
    files = {"file": file_tuple} if file_tuple else None
    r = requests.post(api_url(path), headers=headers(), data=fields, files=files, timeout=300)
    if not r.ok:
        raise RuntimeError(f"{r.status_code} {r.text}")
    return r.json()

def login(email: str, password: str):
    tok = post_json("/auth/login", {"email": email, "password": password})
    st.session_state.token = tok["access_token"]
    st.session_state.me = get_json("/v1/me")

def logout():
    st.session_state.token = ""
    st.session_state.me = None
    st.session_state.risk = None
    st.session_state.meds = []
    st.session_state.alerts = []

def require_login() -> bool:
    if not st.session_state.token or not st.session_state.me:
        st.info("Please login in the sidebar to continue.")
        return False
    return True

def patient_id_from_me() -> str | None:
    me = st.session_state.me or {}
    return me.get("patient_id")

def refresh_me():
    st.session_state.me = get_json("/v1/me")

# ================== SIDEBAR ==================
with st.sidebar:
    st.markdown("## 🔧 Settings")
    st.session_state.base_url = st.text_input("API Base URL", st.session_state.base_url, help="Your Render URL (no trailing slash)").rstrip("/")
    st.session_state.api_key  = st.text_input("x-api-key (optional)", st.session_state.api_key)
    st.session_state.admin_key = st.text_input("x-admin-key (for cron)", st.session_state.admin_key, type="password")

    st.markdown("---")
    st.markdown("### 👤 Login")
    if not st.session_state.token:
        email = st.text_input("Email", key="email")
        pwd = st.text_input("Password", type="password", key="pwd")
        if st.button("Login"):
            try:
                login(email, pwd)
                st.success("Logged in")
            except Exception as e:
                st.error(f"Login failed: {e}")
    else:
        me = st.session_state.me or {}
        st.caption(f"Signed in as **{me.get('email','user')}** ({me.get('role','patient')})")
        c1, c2 = st.columns(2)
        if c1.button("Refresh /v1/me"):
            try:
                refresh_me()
                st.success("Refreshed")
            except Exception as e:
                st.error(e)
        if c2.button("Logout"):
            logout()
            st.info("Logged out")

st.title("🫀 CarePulse Dashboard")

# ================== TABS ==================
tabs = st.tabs(["Patient", "Admin"])

# ================== PATIENT TAB ==================
with tabs[0]:
    st.subheader("Patient")

    # Require login
    if not require_login():
        st.stop()

    # Ensure we have a patient_id (no manual UUID entry)
    pid = patient_id_from_me()

    if not pid:
        st.warning("No patient record linked to this user yet. Create one below.")
        with st.form("create_patient"):
            c1, c2 = st.columns(2)
            name = c1.text_input("Full name", placeholder="Jane Doe", value="")
            dob  = c2.text_input("DOB (YYYY-MM-DD)", placeholder="1950-01-01", value="")
            c3, c4 = st.columns(2)
            phone = c3.text_input("Patient phone (E.164)", placeholder="+12145551234", value="")
            tz    = c4.text_input("Timezone (IANA)", value="America/Chicago")
            submitted = st.form_submit_button("Create & Link Patient", type="primary", use_container_width=True)
            if submitted:
                if not name or not dob:
                    st.error("Name and DOB are required.")
                else:
                    try:
                        # 1) create patient
                        resp = post_json("/v1/patients", {
                            "name": name, "dob": dob,
                            "sex_at_birth": None,
                            "patient_phone": phone or None,
                            "caregiver_phone": None,
                            "timezone": tz or "America/Chicago"
                        })
                        new_pid = resp["id"]
                        # 2) link to logged-in user
                        try:
                            post_json("/auth/link_patient", {"patient_id": new_pid})
                        except Exception as e:
                            st.warning(f"Linked endpoint failed; ask admin to map user->patient. {e}")
                        # 3) refresh /v1/me
                        refresh_me()
                        st.success(f"Patient created & linked ✔  ID: {new_pid}")
                    except Exception as e:
                        st.error(f"Create/link failed: {e}")
        st.stop()

    # From here, we have a patient id
    st.success(f"Patient linked: `{pid}`")

    cA, cB, cC = st.columns(3)
    if cA.button("Load Risk"): 
        try:
            st.session_state.risk = get_json("/v1/risk", params={"patient_id": pid, "store": "false"})
            st.success("Risk loaded")
        except Exception as e: st.error(e)
    if cB.button("Load Meds"):
        try:
            st.session_state.meds = get_json("/v1/meds", params={"patient_id": pid})
            st.success("Meds loaded")
        except Exception as e: st.error(e)
    if cC.button("Load Alerts"):
        try:
            st.session_state.alerts = get_json(f"/v1/alerts/{pid}")
            st.success("Alerts loaded")
        except Exception as e: st.error(e)

    st.markdown("---")

    # Risk
    st.markdown("### 📈 Readmission Risk")
    risk = st.session_state.get("risk")
    if risk:
        score = float(risk.get("score", 0)); pct = int(round(score * 100))
        col1, col2, col3 = st.columns([1, 2, 3])
        with col1: st.metric("Risk", f"{pct}%", help=f"Bucket: {risk.get('bucket','—')}")
        with col2:
            st.write("**Model**:", risk.get("model_version","—"))
            st.write("**Bucket**:", risk.get("bucket","—"))
        with col3:
            st.write("**Factors**"); st.json(risk.get("factors", {}))
    else:
        st.info("Click **Load Risk**.")

    st.markdown("---")

    # Meds
    st.markdown("### 💊 Medications")
    meds = st.session_state.get("meds", [])
    if meds:
        st.dataframe(
            [{"id": m["id"], "drug": m["drug_name"], "dose": m.get("dose"),
              "freq": m["freq"], "times": ", ".join(m.get("times_local", []) or []),
              "tz": m["timezone"]} for m in meds],
            use_container_width=True, hide_index=True
        )
        med_ids = [m["id"] for m in meds]
        sel = st.selectbox("Select a medication to acknowledge the most recent scheduled dose", med_ids)
        if st.button("Ack recent dose", disabled=not sel):
            try:
                post_json(f"/v1/meds/{sel}/ack", {"source":"ui"})
                st.success("Dose acknowledged")
                st.session_state.meds = get_json("/v1/meds", params={"patient_id": pid})
            except Exception as e: st.error(e)
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
        if st.button("Upload Discharge"):
            try:
                file_tuple = None
                if disc_file is not None:
                    mime = mimetypes.guess_type(disc_file.name)[0] or "application/octet-stream"
                    file_tuple = (disc_file.name, disc_file.getvalue(), mime)
                out = post_form("/v1/docs/discharge_text", {"patient_id": pid, **({"text": disc_text} if disc_text.strip() else {})}, file_tuple)
                st.success(f"Diagnoses created: {out.get('diagnoses_created', 0)}")
            except Exception as e: st.error(e)

    with c2:
        st.write("**Pharmacy Sheet → Medications**")
        pharm_text = st.text_area("Paste pharmacy text (optional)", key="pharm_text", height=120)
        pharm_file = st.file_uploader("Or attach .txt/.pdf/.jpg", type=["txt", "pdf", "jpg", "jpeg", "png"], key="pharm_file")
        if st.button("Upload Pharmacy"):
            try:
                file_tuple = None
                if pharm_file is not None:
                    mime = mimetypes.guess_type(pharm_file.name)[0] or "application/octet-stream"
                    file_tuple = (pharm_file.name, pharm_file.getvalue(), mime)
                out = post_form("/v1/docs/meds_text", {"patient_id": pid, **({"text": pharm_text} if pharm_text.strip() else {})}, file_tuple)
                st.success(f"Medications created: {out.get('medications_created', 0)}")
                st.session_state.meds = get_json("/v1/meds", params={"patient_id": pid})
            except Exception as e: st.error(e)

# ================== ADMIN TAB ==================
with tabs[1]:
    role = (st.session_state.me or {}).get("role")
    if role != "admin":
        st.warning("Admin area is restricted. Log in as an admin (and provide x-admin-key for cron).")
        st.stop()

    st.subheader("Cron Triggers")
    colA, colB, colC = st.columns(3)
    with colA:
        win = st.number_input("Window (minutes) for reminders", min_value=1, max_value=60, value=10, step=1)
        if st.button("Trigger Reminders"):
            try:
                out = get_json("/cron/meds/remind_now", hdr={"x-admin-key": st.session_state.admin_key}, params={"window": win})
                st.success(out)
            except Exception as e: st.error(e)
    with colB:
        if st.button("Escalate Missed"):
            try:
                out = get_json("/cron/meds/escalate_missed", hdr={"x-admin-key": st.session_state.admin_key})
                st.success(out)
            except Exception as e: st.error(e)
    with colC:
        if st.button("Recompute Risk (all)"):
            try:
                out = get_json("/cron/risk/recompute_all", hdr={"x-admin-key": st.session_state.admin_key})
                st.success(out)
            except Exception as e: st.error(e)

    st.markdown("---")
    st.subheader("Quick Patient Lookup")
    lookup_pid = st.text_input("Patient UUID")
    if st.button("Load Patient", disabled=not lookup_pid):
        try:
            p = get_json(f"/v1/patients/{lookup_pid}")
            st.json(p)
        except Exception as e: st.error(e)
