"""
SecureMailScope — Investigation Console
SIH'26 | PS 159 (SIH26159)

Cyber-detective themed dashboard: reads the real pipeline output
(Sumaiya -> Jeevika -> Krithiksha -> Gowri) from data/real_data.csv
and renders it as a network-forensics investigation console.
"""

import json
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# ----------------------------------------------------------------------
# Page config
# ----------------------------------------------------------------------
st.set_page_config(
    page_title="SecureMailScope — Investigation Console",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DATA_PATH = Path(__file__).parent / "data" / "real_data.csv"

# ----------------------------------------------------------------------
# Theme: cyber-detective palette
# ----------------------------------------------------------------------
C = {
    "bg0": "#0B1220",       # deepest navy — page background
    "bg1": "#131C2E",       # panel background
    "bg2": "#1A2438",       # card background
    "line": "#243049",      # hairline borders
    "text": "#E6ECF5",      # primary text
    "muted": "#8A97AD",     # secondary text
    "blue": "#3B82F6",      # electric blue accent
    "cyan": "#22D3EE",      # cyan glow accent
    "amber": "#F59E0B",     # medium-risk / warning
    "red": "#EF4444",       # high-risk / flagged
    "green": "#22C55E",     # secure / low-risk
}

st.markdown(
    f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

    html, body, [class*="css"] {{
        font-family: 'Space Grotesk', sans-serif;
        color: {C['text']};
    }}
    code, .mono, .stMetric [data-testid="stMetricValue"] {{
        font-family: 'IBM Plex Mono', monospace !important;
    }}

    .stApp {{
        background:
            radial-gradient(ellipse 900px 500px at 15% -10%, rgba(59,130,246,0.14), transparent 60%),
            radial-gradient(ellipse 700px 500px at 100% 10%, rgba(34,211,238,0.10), transparent 55%),
            repeating-linear-gradient(0deg, rgba(255,255,255,0.02) 0px, rgba(255,255,255,0.02) 1px, transparent 1px, transparent 42px),
            repeating-linear-gradient(90deg, rgba(255,255,255,0.02) 0px, rgba(255,255,255,0.02) 1px, transparent 1px, transparent 42px),
            {C['bg0']};
    }}

    section[data-testid="stSidebar"] {{
        background-color: {C['bg1']};
        border-right: 1px solid {C['line']};
    }}
    section[data-testid="stSidebar"] * {{
        color: {C['text']} !important;
    }}

    /* ---- Hero ---- */
    .hero {{
        position: relative;
        border: 1px solid {C['line']};
        border-radius: 14px;
        padding: 2.2rem 2.4rem;
        margin-bottom: 1.8rem;
        background:
            radial-gradient(ellipse 500px 260px at 85% 0%, rgba(34,211,238,0.16), transparent 65%),
            linear-gradient(135deg, {C['bg1']} 0%, {C['bg0']} 100%);
        overflow: hidden;
    }}
    .hero::before {{
        content: "01001101 01000001 01001001 01001100  01010011 01000101 01000011";
        position: absolute;
        top: -10px; right: 20px;
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.7rem;
        letter-spacing: 3px;
        color: rgba(34,211,238,0.14);
        white-space: nowrap;
    }}
    .hero .eyebrow {{
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.78rem;
        letter-spacing: 0.12em;
        color: {C['cyan']};
        text-transform: uppercase;
        margin-bottom: 0.6rem;
    }}
    .hero h1 {{
        font-weight: 700;
        font-size: 2.1rem;
        letter-spacing: -0.01em;
        line-height: 1.15;
        margin: 0 0 0.6rem 0;
        color: {C['text']};
    }}
    .hero p {{
        color: {C['muted']};
        font-size: 0.95rem;
        max-width: 640px;
        margin: 0;
    }}

    /* ---- Section titles ---- */
    .section-title {{
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.8rem;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: {C['cyan']};
        border-bottom: 1px solid {C['line']};
        padding-bottom: 0.4rem;
        margin: 1.6rem 0 1rem 0;
    }}

    /* ---- Suspect / server cards ---- */
    .case-card {{
        background: {C['bg2']};
        border: 1px solid {C['line']};
        border-radius: 10px;
        padding: 1.1rem 1.3rem;
        margin-bottom: 1rem;
        position: relative;
        transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
    }}
    .case-card:hover {{
        transform: translateY(-3px);
        border-color: var(--glow, {C['blue']});
        box-shadow: 0 10px 30px rgba(0,0,0,0.35), 0 0 0 1px var(--glow, {C['blue']}) inset;
    }}
    .case-card .sid {{
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.78rem;
        color: {C['muted']};
        letter-spacing: 0.03em;
    }}
    .stamp {{
        position: absolute;
        top: 1rem; right: 1.1rem;
        font-family: 'IBM Plex Mono', monospace;
        font-weight: 700;
        font-size: 0.68rem;
        letter-spacing: 0.12em;
        padding: 0.28rem 0.6rem;
        border-radius: 4px;
        border: 1.5px solid var(--stamp-color);
        color: var(--stamp-color);
        transform: rotate(3deg);
        background: rgba(0,0,0,0.15);
    }}
    .case-card .verdict {{
        font-weight: 700;
        font-size: 1.1rem;
        margin: 0.3rem 0 0.5rem 0;
        color: var(--glow, {C['blue']});
    }}
    .case-card .desc {{
        color: {C['muted']};
        font-size: 0.88rem;
        margin-bottom: 0.7rem;
    }}
    .badge {{
        display: inline-block;
        font-family: 'IBM Plex Mono', monospace;
        font-size: 0.72rem;
        padding: 0.2rem 0.55rem;
        border-radius: 999px;
        margin-right: 0.35rem;
        margin-bottom: 0.3rem;
        border: 1px solid {C['line']};
        background: rgba(255,255,255,0.03);
        color: {C['text']};
    }}

    /* ---- Metric tiles ---- */
    div[data-testid="stMetric"] {{
        background: {C['bg2']};
        border: 1px solid {C['line']};
        border-radius: 10px;
        padding: 0.8rem 1rem;
    }}

    hr {{ border-color: {C['line']}; }}
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
    df = df.drop_duplicates(subset=["session_id"], keep="first").reset_index(drop=True)
    return df


if not DATA_PATH.exists():
    st.error(
        f"Couldn't find real_data.csv at `{DATA_PATH}`. "
        "Drop the pipeline's real_data.csv into the `data/` folder next to app.py."
    )
    st.stop()

df = load_data(DATA_PATH)

RISK_COLOR = {"LOW": C["green"], "MEDIUM": C["amber"], "HIGH": C["red"]}
RISK_STAMP = {"LOW": "SECURE", "MEDIUM": "FLAGGED", "HIGH": "VULNERABLE"}

# ----------------------------------------------------------------------
# Sidebar nav
# ----------------------------------------------------------------------
st.sidebar.markdown("### 🕵️ SecureMailScope")
st.sidebar.markdown(
    "<span class='mono' style='font-family:IBM Plex Mono, monospace; font-size:0.78rem; color:#8A97AD;'>"
    "CASE FILE · PS 159 · SIH26159</span>",
    unsafe_allow_html=True,
)
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Navigate",
    ["Overview", "Server Reports", "Raw Data"],
    label_visibility="collapsed",
)
st.sidebar.markdown("---")
st.sidebar.markdown(
    "<span style='font-family:IBM Plex Mono, monospace; font-size:0.72rem; color:#8A97AD;'>"
    "PIPELINE: Sumaiya (PCAPs) → Jeevika (TLS parse) → Krithiksha (risk rules) → Gowri (ML)"
    "</span>",
    unsafe_allow_html=True,
)

# ----------------------------------------------------------------------
# Hero header
# ----------------------------------------------------------------------
st.markdown(
    """
    <div class="hero">
        <div class="eyebrow">🔒 Passive Network Forensics · Case Active</div>
        <h1>UNCOVERING HIDDEN THREATS<br/>IN YOUR MAIL SERVERS</h1>
        <p>Every session below was pulled straight from a real capture — no mock data, no staged
        evidence. Encrypted traffic gets cleared. Everything else gets a case file.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ----------------------------------------------------------------------
# Overview page
# ----------------------------------------------------------------------
if page == "Overview":
    total = len(df)
    high = int((df["risk_level"] == "HIGH").sum())
    medium = int((df["risk_level"] == "MEDIUM").sum())
    low = int((df["risk_level"] == "LOW").sum())

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Sessions investigated", total)
    c2.metric("🔴 Vulnerable", high)
    c3.metric("🟡 Flagged", medium)
    c4.metric("🟢 Secure", low)

    st.markdown('<div class="section-title">Evidence breakdown</div>', unsafe_allow_html=True)
    col_a, col_b = st.columns([1, 1])

    with col_a:
        counts = df["risk_level"].value_counts().reindex(["LOW", "MEDIUM", "HIGH"]).fillna(0)
        fig_bar = go.Figure(
            go.Bar(
                x=counts.index,
                y=counts.values,
                marker_color=[RISK_COLOR[l] for l in counts.index],
                marker_line_width=0,
            )
        )
        fig_bar.update_layout(
            plot_bgcolor=C["bg1"],
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(family="IBM Plex Mono", color=C["text"]),
            title="Sessions by risk level",
            yaxis=dict(title="count", gridcolor=C["line"]),
            xaxis=dict(gridcolor=C["line"]),
            margin=dict(t=50, b=20, l=20, r=20),
            height=340,
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    with col_b:
        pie_counts = df["risk_level"].value_counts()
        fig_pie = go.Figure(
            go.Pie(
                labels=pie_counts.index,
                values=pie_counts.values,
                hole=0.55,
                marker=dict(colors=[RISK_COLOR[l] for l in pie_counts.index]),
                textfont=dict(family="IBM Plex Mono", color=C["text"]),
            )
        )
        fig_pie.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(family="IBM Plex Mono", color=C["text"]),
            title="Share of sessions",
            margin=dict(t=50, b=20, l=20, r=20),
            height=340,
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    st.markdown('<div class="section-title">TLS posture</div>', unsafe_allow_html=True)
    col_c, col_d = st.columns([1, 1])
    with col_c:
        starttls_counts = df["starttls_used"].value_counts()
        labels = ["STARTTLS used" if v else "No STARTTLS" for v in starttls_counts.index]
        fig_st = go.Figure(
            go.Bar(
                x=labels,
                y=starttls_counts.values,
                marker_color=[C["green"] if l == "STARTTLS used" else C["red"] for l in labels],
                marker_line_width=0,
            )
        )
        fig_st.update_layout(
            plot_bgcolor=C["bg1"],
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(family="IBM Plex Mono", color=C["text"]),
            title="STARTTLS adoption",
            yaxis=dict(title="sessions", gridcolor=C["line"]),
            xaxis=dict(gridcolor=C["line"]),
            margin=dict(t=50, b=20, l=20, r=20),
            height=300,
            showlegend=False,
        )
        st.plotly_chart(fig_st, use_container_width=True)

    with col_d:
        tls_counts = df["tls_version"].value_counts().sort_index()
        tls_labels = ["No TLS" if v == 0 else f"TLS {v}" for v in tls_counts.index]
        fig_tls = go.Figure(
            go.Bar(
                x=tls_labels,
                y=tls_counts.values,
                marker_color=[C["blue"], C["cyan"], C["amber"]][: len(tls_labels)],
                marker_line_width=0,
            )
        )
        fig_tls.update_layout(
            plot_bgcolor=C["bg1"],
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(family="IBM Plex Mono", color=C["text"]),
            title="TLS version observed",
            yaxis=dict(title="sessions", gridcolor=C["line"]),
            xaxis=dict(gridcolor=C["line"]),
            margin=dict(t=50, b=20, l=20, r=20),
            height=300,
            showlegend=False,
        )
        st.plotly_chart(fig_tls, use_container_width=True)

# ----------------------------------------------------------------------
# Server Reports page — suspect-profile cards
# ----------------------------------------------------------------------
elif page == "Server Reports":
    st.markdown('<div class="section-title">Suspect profiles</div>', unsafe_allow_html=True)
    st.caption("One case card per session — status stamped, evidence attached.")

    level_filter = st.multiselect(
        "Filter by risk level", ["LOW", "MEDIUM", "HIGH"], default=["LOW", "MEDIUM", "HIGH"]
    )
    view = df[df["risk_level"].isin(level_filter)].sort_values("risk_score", ascending=False)

    if view.empty:
        st.info("No sessions match that filter. The case file is intact — just empty here.")

    for _, row in view.iterrows():
        color = RISK_COLOR.get(row["risk_level"], C["blue"])
        stamp = RISK_STAMP.get(row["risk_level"], "UNKNOWN")
        verdict = {
            "HIGH": "🔓 Compromised in transit — plaintext, no cover.",
            "MEDIUM": "🟡 Partially protected — some gaps left open.",
            "LOW": "🔐 Encrypted end to end, cert checks out.",
        }.get(row["risk_level"], "Status unclear.")

        st.markdown(
            f"""
            <div class="case-card" style="--glow:{color}; --stamp-color:{color};">
                <div class="stamp">{stamp}</div>
                <div class="sid">SESSION · {row['session_id']}</div>
                <div class="verdict">{row['risk_level']} RISK — {row['risk_score']}/100</div>
                <div class="desc">{verdict}</div>
                <div>
                    <span class="badge">TLS: {row['tls_version'] if row['tls_version'] else 'none'}</span>
                    <span class="badge">STARTTLS: {'yes' if row['starttls_used'] else 'no'}</span>
                    <span class="badge">Weak cipher: {'yes' if row['weak_cipher'] else 'no'}</span>
                    <span class="badge">Cert valid: {'yes' if row['cert_valid'] else 'no'}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown('<div class="section-title">Export case file</div>', unsafe_allow_html=True)
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
    st.markdown('<div class="section-title">Raw pipeline output</div>', unsafe_allow_html=True)
    st.caption(f"Loaded from `data/real_data.csv` · {len(df)} unique sessions")
    st.dataframe(df, use_container_width=True, hide_index=True)
    st.download_button(
        "⬇ Download CSV",
        data=df.to_csv(index=False),
        file_name="real_data.csv",
        mime="text/csv",
    )
