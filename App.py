"""
app.py
Streamlit dashboard for the Phishing Detection Tool.
Run with: streamlit run app.py
"""

import streamlit as st
from Url_Checker import analyse_url
from Email_Checker import analyse_email

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Phishing Detector",
    page_icon="🎣",
    layout="wide"
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* ── Full width & base font ── */
    .block-container { max-width: 1400px; padding: 2rem 3rem; }
    html, body, [class*="css"] { font-size: 18px; }

    /* ── Force hero title size — overrides all Streamlit resets ── */
    .big-title, .big-title * {
        font-size: clamp(3rem, 6vw, 5.5rem) !important;
        font-weight: 900 !important;
        line-height: 1.15 !important;
    }

    /* ── Title ── */
    h1 { font-size: 3rem !important; letter-spacing: -0.5px; }

    /* ── Subheaders ── */
    h2, h3 { font-size: 1.8rem !important; }

    /* ── Body text & labels ── */
    p, div, label, span { font-size: 1.1rem !important; line-height: 1.7; }

    /* ── Tab labels ── */
    .stTabs [data-baseweb="tab"] { font-size: 1.2rem !important; padding: 12px 28px; }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }

    /* ── Input fields ── */
    .stTextInput input, .stTextArea textarea {
        font-size: 1.1rem !important;
        background: #13131f !important;
        border: 1.5px solid #3a3a5c !important;
        border-radius: 8px !important;
        color: #e8e8f0 !important;
        padding: 12px 16px !important;
    }
    .stTextInput input:focus, .stTextArea textarea:focus {
        border-color: #7c6af7 !important;
        box-shadow: 0 0 0 2px #7c6af733 !important;
    }

    /* ── Buttons ── */
    .stButton > button {
        font-size: 1.1rem !important;
        padding: 10px 24px !important;
        border-radius: 8px !important;
        border: 1.5px solid #3a3a5c !important;
        background: #1e1e35 !important;
        color: #c8c8e8 !important;
        transition: all 0.2s;
    }
    .stButton > button:hover {
        background: #2a2a4a !important;
        border-color: #7c6af7 !important;
        color: #ffffff !important;
    }
    /* Primary button (Analyse) */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #7c6af7, #5b4de0) !important;
        border: none !important;
        color: white !important;
        font-weight: 600 !important;
        font-size: 1.15rem !important;
        padding: 12px 36px !important;
    }
    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(135deg, #9580ff, #7c6af7) !important;
        transform: translateY(-1px);
        box-shadow: 0 4px 20px #7c6af755 !important;
    }

    /* ── Risk banners ── */
    .risk-high   { background: #ff4b4b18; border-left: 5px solid #ff4b4b;
                   padding: 18px 22px; border-radius: 10px; margin: 12px 0; }
    .risk-medium { background: #ffa50018; border-left: 5px solid #ffa500;
                   padding: 18px 22px; border-radius: 10px; margin: 12px 0; }
    .risk-low    { background: #00c85318; border-left: 5px solid #00c853;
                   padding: 18px 22px; border-radius: 10px; margin: 12px 0; }

    /* ── Risk badges ── */
    .badge-high   { color: #ff4b4b; font-weight: 800; font-size: 1.8rem !important; }
    .badge-medium { color: #ffa500; font-weight: 800; font-size: 1.8rem !important; }
    .badge-low    { color: #00c853; font-weight: 800; font-size: 1.8rem !important; }

    /* ── Rule cards ── */
    .rule-card {
        background: #13131f;
        border: 1px solid #2e2e50;
        padding: 14px 18px;
        border-radius: 10px;
        margin: 8px 0;
        font-size: 1.05rem !important;
        line-height: 1.6;
    }
    .rule-card strong { font-size: 1.1rem !important; color: #d0d0f0; }

    /* ── Divider ── */
    hr { border-color: #2e2e50 !important; margin: 1.5rem 0; }

    /* ── Expander ── */
    .streamlit-expanderHeader { font-size: 1.05rem !important; }

    /* ── Progress bar ── */
    .stProgress > div > div { border-radius: 10px; height: 10px !important; }

    /* ── Success / warning messages ── */
    .stSuccess, .stWarning { font-size: 1.05rem !important; }
</style>
""", unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .big-title { font-size: clamp(3rem, 6vw, 5.5rem) !important; }
</style>
<div style='text-align:center; padding: 2.5rem 0 0.5rem 0;'>
    <p class='big-title' style='font-weight:900; color:#ffffff; margin:0;
       line-height:1.15; text-shadow: 0 0 40px #7c6af755;'>
        🎣 Phishing Detection Tool
    </p>
    <p style='font-size:1rem; color:#6060a0; margin-top:12px; letter-spacing:0.3px;'>
        Rule-based analysis of suspicious URLs and emails &nbsp;·&nbsp;
        Enter a URL or paste a raw email below to get an instant risk score.
    </p>
</div>
""", unsafe_allow_html=True)
st.divider()

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2 = st.tabs(["🔗 URL Checker", "📧 Email Checker"])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 1 — URL CHECKER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
with tab1:
    st.subheader("URL Risk Analysis")
    st.markdown("Paste any URL to check it against 9 phishing detection rules.")

    url_input = st.text_input(
        "Enter URL",
        placeholder="e.g. http://paypal-secure-login.tk/verify?id=user",
        label_visibility="collapsed"
    )

    # Example URLs for quick testing
    st.markdown("**Quick test examples:**")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("🔴 High risk example"):
            url_input = "http://paypal-secure-login.tk/verify?account=user&confirm=password"
            st.session_state["url_example"] = url_input
    with col2:
        if st.button("🟡 Medium risk example"):
            url_input = "http://amazon-account.support/signin/verify"
            st.session_state["url_example"] = url_input
    with col3:
        if st.button("🟢 Low risk example"):
            url_input = "https://www.bbc.co.uk/news"
            st.session_state["url_example"] = url_input

    # Use session state example if button was clicked
    if "url_example" in st.session_state and not url_input:
        url_input = st.session_state["url_example"]

    if st.button("Analyse URL", type="primary", key="url_btn") or url_input:
        if url_input and url_input.strip():
            with st.spinner("Analysing..."):
                result = analyse_url(url_input)

            # Risk banner
            level = result["risk_level"]
            score = result["total_score"]
            colour_class = f"risk-{level.lower()}"
            badge_class = f"badge-{level.lower()}"

            st.markdown(f"""
            <div class="{colour_class}">
                <span class="{badge_class}">{level} RISK</span>
                &nbsp;&nbsp;Risk Score: <strong>{score}/100</strong>
            </div>
            """, unsafe_allow_html=True)

            # Progress bar
            bar_colour = "normal" if level == "LOW" else ("off" if level == "HIGH" else "normal")
            st.progress(score / 100)

            # Triggered rules
            triggered = result["triggered_rules"]
            if triggered:
                st.markdown(f"#### ⚠️ {len(triggered)} rule(s) triggered")
                for rule in triggered:
                    icon = "🔴" if rule["score"] >= 25 else ("🟡" if rule["score"] >= 15 else "🟠")
                    st.markdown(f"""
                    <div class="rule-card">
                        {icon} <strong>{rule['rule']}</strong> &nbsp;
                        <span style="color:#888;">[+{rule['score']} pts]</span><br>
                        <span style="color:#ccc;">{rule['reason']}</span>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.success("✅ No phishing indicators detected in this URL.")

            # All rules summary (expandable)
            with st.expander("See all rules checked"):
                for rule in result["all_results"]:
                    icon = "✅" if not rule["triggered"] else "❌"
                    st.markdown(f"{icon} **{rule['rule']}** — "
                                f"{'Not triggered' if not rule['triggered'] else rule['reason']}")
        else:
            st.warning("Please enter a URL first.")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB 2 — EMAIL CHECKER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
with tab2:
    st.subheader("Email Risk Analysis")
    st.markdown("Paste a raw email (including headers if available) to analyse it.")

    # Example phishing email for testing
    EXAMPLE_PHISHING_EMAIL = """From: PayPal Support <security@random-mailer99.net>
Reply-To: collect@attacker-domain.ru
Subject: Your account has been suspended - Immediate action required

Dear Customer,

We have detected suspicious activity on your PayPal account. Your account has been suspended due to unusual sign-in activity.

Kindly verify your account immediately by clicking the link below or your account will be closed within 24 hours.

Click here to verify: http://192.168.1.1/paypal/confirm?user=victim

Please open the attached document to complete verification.

Failure to respond within 24 hours will result in permanent suspension.

PayPal Security Team"""

    EXAMPLE_LEGIT_EMAIL = """From: GitHub Notifications <noreply@github.com>
Subject: Your pull request has been merged

Hi there,

Your pull request "Fix login bug" has been successfully merged into the main branch of your repository.

You can view the changes at: https://github.com/yourusername/yourrepo/pull/42

Thanks for contributing!

The GitHub Team"""

    EXAMPLE_MEDIUM_EMAIL = """From: Rewards Team <noreply@survey-rewards.com>
Subject: You have been selected for a reward

Dear Customer,

Congratulations! You have been selected to receive a special reward as part of our customer appreciation programme.

To claim your free gift, simply complete a short survey at: http://survey-rewards.com/claim

This offer expires in 48 hours.

Rewards Programme Team"""

    st.markdown("**Quick test examples:**")
    ecol1, ecol2, ecol3 = st.columns(3)
    with ecol1:
        load_phishing = st.button("🔴 Load phishing email example")
    with ecol2:
        load_medium = st.button("🟡 Load medium risk example")
    with ecol3:
        load_legit = st.button("🟢 Load legitimate email example")

    default_email = ""
    if load_phishing:
        default_email = EXAMPLE_PHISHING_EMAIL
        st.session_state["email_example"] = default_email
    elif load_medium:
        default_email = EXAMPLE_MEDIUM_EMAIL
        st.session_state["email_example"] = default_email
    elif load_legit:
        default_email = EXAMPLE_LEGIT_EMAIL
        st.session_state["email_example"] = default_email

    display_email = st.session_state.get("email_example", default_email)

    email_input = st.text_area(
        "Paste email content here",
        value=display_email,
        height=280,
        placeholder="Paste full email here (headers + body)...",
        label_visibility="collapsed"
    )

    if st.button("Analyse Email", type="primary", key="email_btn"):
        if email_input and email_input.strip():
            with st.spinner("Analysing..."):
                result = analyse_email(email_input)

            level = result["risk_level"]
            score = result["total_score"]
            colour_class = f"risk-{level.lower()}"
            badge_class = f"badge-{level.lower()}"

            st.markdown(f"""
            <div class="{colour_class}">
                <span class="{badge_class}">{level} RISK</span>
                &nbsp;&nbsp;Risk Score: <strong>{score}/100</strong>
            </div>
            """, unsafe_allow_html=True)

            st.progress(score / 100)

            triggered = result["triggered_rules"]
            if triggered:
                st.markdown(f"#### ⚠️ {len(triggered)} rule(s) triggered")
                for rule in triggered:
                    icon = "🔴" if rule["score"] >= 25 else ("🟡" if rule["score"] >= 15 else "🟠")
                    st.markdown(f"""
                    <div class="rule-card">
                        {icon} <strong>{rule['rule']}</strong> &nbsp;
                        <span style="color:#888;">[+{rule['score']} pts]</span><br>
                        <span style="color:#ccc;">{rule['reason']}</span>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.success("✅ No phishing indicators detected in this email.")

            with st.expander("See all rules checked"):
                for rule in result["all_results"]:
                    icon = "✅" if not rule["triggered"] else "❌"
                    st.markdown(f"{icon} **{rule['rule']}** — "
                                f"{'Not triggered' if not rule['triggered'] else rule['reason']}")
        else:
            st.warning("Please paste an email first.")

# ── Footer ────────────────────────────────────────────────────────────────────
st.divider()
st.markdown(
    "<div style='text-align:center; color:#444466; font-size:1rem; padding:8px 0;'>"
    "🎣 Rule-based phishing detector &nbsp;·&nbsp; Built with Python &amp; Streamlit &nbsp;·&nbsp; "
    "For educational and portfolio purposes<br>"
    "<strong style='color:#6656c4;'>Built by Ruth Dsouza</strong></div>",
    unsafe_allow_html=True
)
