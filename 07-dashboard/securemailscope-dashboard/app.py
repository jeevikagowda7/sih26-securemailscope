"""
SecureMailScope — Dashboard
SIH'26 | PS 159 (SIH26159)

Reads the real pipeline output (Sumaiya -> Jeevika -> Krithiksha -> Gowri)
from data/real_data.csv and renders it as an incident-report-style dashboard.
"""

import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ----------------------------------------------------------------------
# Page config
# ----------------------------------------------------------------------
st.set_page_config(
    page_title="SecureMailScope",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

DATA_PATH = Path(__file__).parent / "data" / "real_data.csv"

# ----------------------------------------------------------------------
# Theme: fonts + colors
# ----------------------------------------------------------------------
ACCENT = {
    "ink": "#101014",
    "paper": "#FAFAF7",
    "card": "#FFFFFF",
    "line": "#E7E5DF",
    "mono": "#6B6B66",
    "low": "#1E8E5A",     # forensic green
    "medium": "#C9821A",  # amber
    "high": "#C4342B",    # incident red
    "accent": "#3A4CB8",  # evidence blue
}

st.markdown(
    f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

    html, body, [class*="css"]  {{
        font-family: 'Space Grotesk', sans-serif;
    }}
    code, .mono, .stMetric [data-testid="stMetricValue"] {{
        font-family: 'IBM Plex Mono', monospace !important;
    }}

    .stApp {{
        background-color: {ACCENT['paper']};
    }}

    section[data-testid="stSidebar"] {{
        background-color: {ACCENT['ink']};
    }}
    section[data-testid="stSidebar"] * {{
        color: {ACCENT['paper']} !important;
    }}

    .case-header {{
        border-bottom: 2px solid {ACCENT['ink']};
        padding-bottom: 0.5rem;
        margin-bottom: 1.5rem;
    }}
    .case-header h1 {{
        font-weight: 700;
        letter-spacing: -0.02em;
        margin-bottom: 0;
    }}
    .case-header p {{
        font-family: 'IBM Plex Mono', monospace;
        color: {ACCENT['mono']};
        font-size: 0.85rem;
        margin-top: 0.15rem;
    }}

    .incident-card {{
        background: {ACCENT['card']};
        border: 1px solid {ACCENT['line']};
        border-left: 6px solid var(--stripe, {ACCENT['accent']});
        border-radius: 6px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.9rem;
        transition: transform 0.12s ease, box-shadow 0.12s ease;
    }}
    .incident-card:hover {{
        transform: translateY(-2px);
        box-shadow: 0 6px 18px rgba(16,16,20,0.08);
    }}
    .incident-card .sid {{
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.8rem;
        color: {ACCENT['mono']};
    }}
    .incident-card .verdict {{
        font-weight: 700;
        font-size: 1.05rem;
        margin: 0.15rem 0 0.4rem 0;
    }}
    .badge {{
        display: inline-block;
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.72rem;
        padding: 0.15rem 0.5rem;
        border-radius: 999px;
        margin-right: 0.35rem;
        border: 1px solid {ACCENT['line']};
    }}
    </style>
    """,
    unsafe_allow_html=True,
)


# ----------------------------------------------------------------------
# Data loading
# ----------------------------------------------------------------------
@st.cache_data
def load_data(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    bool_cols = ["weak_cipher", "starttls_used", "cert_valid"]
    for c in bool_cols:
        if c in df.columns:
            df[c] = df[c].astype(str).str.strip().str.lower().map(
                {"true": True, "false": False}
            )
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce")
    df["risk_level"] = df["risk_level"].str.upper().str.strip()
    return df


if not DATA_PATH.exists():
    st.error(
        f"Couldn't find real_data.csv at `{DATA_PATH}`. "
        "Drop the pipeline's real_data.csv into the `data/` folder next to app.py."
    )
    st.stop()

df = load_data(DATA_PATH)

RISK_COLOR = {"LOW": ACCENT["low"], "MEDIUM": ACCENT["medium"], "HIGH": ACCENT["high"]}

# ----------------------------------------------------------------------
# Sidebar nav
# ----------------------------------------------------------------------
st.sidebar.markdown("### 🔐 SecureMailScope")
st.sidebar.markdown(
    "<span class='mono'>PS 159 · SIH26159</span>", unsafe_allow_html=True
)
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Navigate",
    ["Overview", "Server Reports", "Raw Data"],
    label_visibility="collapsed",
)
st.sidebar.markdown("---")
st.sidebar.markdown(
    "<span class='mono' style='font-size:0.75rem;'>Live pipeline data — "
    "Sumaiya (PCAPs) → Jeevika (TLS parse) → Krithiksha (risk rules) → Gowri (ML)</span>",
    unsafe_allow_html=True,
)

# ----------------------------------------------------------------------
# Header
# ----------------------------------------------------------------------
st.markdown(
    """
    <div class="case-header">
        <h1>SecureMailScope — Forensic Summary</h1>
        <p>Passive network forensics on SMTP/IMAP/POP3 traffic · case file compiled from real captures</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ----------------------------------------------------------------------
# Overview page
# ----------------------------------------------------------------------
if page == "Overview":
    total = len(df)
    high = (df["risk_level"] == "HIGH").sum()
    medium = (df["risk_level"] == "MEDIUM").sum()
    low = (df["risk_level"] == "LOW").sum()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Sessions analyzed", total)
    c2.metric("🔴 High risk", high)
    c3.metric("🟡 Medium risk", medium)
    c4.metric("🟢 Low risk", low)

    if high and not (medium or low):
        pass  # mixed dataset — no special-case copy needed
    st.caption(
        "Every session below actually passed through the pipeline — no placeholders, "
        "no synthetic captures. What you see is what got sniffed."
    )

    st.markdown("### Risk breakdown")
    col_a, col_b = st.columns([1, 1])

    with col_a:
        counts = df["risk_level"].value_counts().reindex(["LOW", "MEDIUM", "HIGH"]).fillna(0)
        fig_bar = go.Figure(
            go.Bar(
                x=counts.index,
                y=counts.values,
                marker_color=[RISK_COLOR[l] for l in counts.index],
            )
        )
        fig_bar.update_layout(
            plot_bgcolor="white",
            paper_bgcolor="white",
            font_family="IBM Plex Mono",
            title="Sessions by risk level",
            yaxis_title="count",
            margin=dict(t=50, b=20, l=20, r=20),
            height=360,
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    with col_b:
        pie_counts = df["risk_level"].value_counts()
        fig_pie = px.pie(
            names=pie_counts.index,
            values=pie_counts.values,
            color=pie_counts.index,
            color_discrete_map=RISK_COLOR,
            hole=0.45,
        )
        fig_pie.update_layout(
            font_family="IBM Plex Mono",
            title="Share of sessions",
            margin=dict(t=50, b=20, l=20, r=20),
            height=360,
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    st.markdown("### TLS posture")
    col_c, col_d = st.columns([1, 1])
    with col_c:
        starttls_counts = df["starttls_used"].value_counts()
        fig_st = px.bar(
            x=["STARTTLS used" if v else "No STARTTLS" for v in starttls_counts.index],
            y=starttls_counts.values,
            color=["STARTTLS used" if v else "No STARTTLS" for v in starttls_counts.index],
            color_discrete_map={"STARTTLS used": ACCENT["low"], "No STARTTLS": ACCENT["high"]},
        )
        fig_st.update_layout(
            showlegend=False,
            plot_bgcolor="white",
            paper_bgcolor="white",
            font_family="IBM Plex Mono",
            title="STARTTLS adoption",
            yaxis_title="sessions",
            margin=dict(t=50, b=20, l=20, r=20),
            height=320,
        )
        st.plotly_chart(fig_st, use_container_width=True)

    with col_d:
        tls_counts = df["tls_version"].value_counts().sort_index()
        labels = ["No TLS" if v == 0 else f"TLS {v}" for v in tls_counts.index]
        fig_tls = px.bar(
            x=labels,
            y=tls_counts.values,
            color=labels,
            color_discrete_sequence=[ACCENT["accent"], ACCENT["low"], ACCENT["medium"]],
        )
        fig_tls.update_layout(
            showlegend=False,
            plot_bgcolor="white",
            paper_bgcolor="white",
            font_family="IBM Plex Mono",
            title="TLS version observed",
            yaxis_title="sessions",
            margin=dict(t=50, b=20, l=20, r=20),
            height=320,
        )
        st.plotly_chart(fig_tls, use_container_width=True)

# ----------------------------------------------------------------------
# Server Reports page — incident-report-style cards
# ----------------------------------------------------------------------
elif page == "Server Reports":
    st.markdown("### Case files, one per session")
    st.caption("Each card is this session's field report: what we saw, what it means.")

    level_filter = st.multiselect(
        "Filter by risk level", ["LOW", "MEDIUM", "HIGH"], default=["LOW", "MEDIUM", "HIGH"]
    )
    view = df[df["risk_level"].isin(level_filter)].sort_values("risk_score", ascending=False)

    if view.empty:
        st.info("No sessions match that filter. The case file is intact — just empty here.")

    for _, row in view.iterrows():
        color = RISK_COLOR.get(row["risk_level"], ACCENT["accent"])
        verdict = {
            "HIGH": "Compromised in transit — plaintext, no cover.",
            "MEDIUM": "Partially protected — some gaps left open.",
            "LOW": "Encrypted end to end, cert checks out.",
        }.get(row["risk_level"], "Status unclear.")

        st.markdown(
            f"""
            <div class="incident-card" style="--stripe:{color};">
                <div class="sid">SESSION · {row['session_id']}</div>
                <div class="verdict" style="color:{color};">
                    {row['risk_level']} RISK — {row['risk_score']}/100
                </div>
                <div>{verdict}</div>
                <div style="margin-top:0.6rem;">
                    <span class="badge">TLS: {row['tls_version'] if row['tls_version'] else 'none'}</span>
                    <span class="badge">STARTTLS: {'yes' if row['starttls_used'] else 'no'}</span>
                    <span class="badge">Weak cipher: {'yes' if row['weak_cipher'] else 'no'}</span>
                    <span class="badge">Cert valid: {'yes' if row['cert_valid'] else 'no'}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("### Export this case file")
    report = view.to_dict(orient="records")
    st.download_button(
        "⬇ Download as JSON",
        data=json.dumps(report, indent=2, default=str),
        file_name="securemailscope_report.json",
        mime="application/json",
    )

# ----------------------------------------------------------------------
# Raw Data page
# ----------------------------------------------------------------------
else:
    st.markdown("### Raw pipeline output")
    st.caption(f"Loaded from `data/real_data.csv` · {len(df)} rows")
    st.dataframe(df, use_container_width=True, hide_index=True)
    st.download_button(
        "⬇ Download CSV",
        data=df.to_csv(index=False),
        file_name="real_data.csv",
        mime="text/csv",
    )
