from __future__ import annotations

import json
import io
from collections import Counter

import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

from core.services import ScanService
from ai_helper        import generate_remediation, generate_risk_summary, generate_batch_report


# Page config

st.set_page_config(
    page_title = 'CloudGuardian AI',
    page_icon  = '☁️',
    layout     = 'wide',
    initial_sidebar_state = 'expanded',
)

# Custom CSS injection

def inject_css() -> None:
    st.markdown("""
    <style>
    /* ── Severity badge pills ──────────────────────────────────────────── */
    .badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }
    .badge-critical { background: #FEE2E2; color: #991B1B; border: 1px solid #FCA5A5; }
    .badge-high     { background: #FFF7ED; color: #9A3412; border: 1px solid #FDBA74; }
    .badge-medium   { background: #FEFCE8; color: #854D0E; border: 1px solid #FDE047; }
    .badge-low      { background: #EFF6FF; color: #1E40AF; border: 1px solid #93C5FD; }

    /* ── Priority band pills ───────────────────────────────────────────── */
    .band-P1 { background: #FEE2E2; color: #991B1B; border: 1px solid #FCA5A5; }
    .band-P2 { background: #FFF7ED; color: #9A3412; border: 1px solid #FDBA74; }
    .band-P3 { background: #FEFCE8; color: #854D0E; border: 1px solid #FDE047; }
    .band-P4 { background: #EFF6FF; color: #1E40AF; border: 1px solid #93C5FD; }

    /* ── Issue cards ───────────────────────────────────────────────────── */
    .issue-card {
        border-left: 4px solid #E5E7EB;
        padding: 12px 16px;
        margin-bottom: 10px;
        border-radius: 0 8px 8px 0;
        background: #F9FAFB;
    }
    .issue-card-critical { border-left-color: #EF4444; background: #FFF5F5; }
    .issue-card-high     { border-left-color: #F97316; background: #FFFAF5; }
    .issue-card-medium   { border-left-color: #EAB308; background: #FEFDF0; }
    .issue-card-low      { border-left-color: #3B82F6; background: #F5F8FF; }

    /* ── KPI metric cards ──────────────────────────────────────────────── */
    div[data-testid="metric-container"] {
        background: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 16px;
        transition: box-shadow .2s;
    }
    div[data-testid="metric-container"]:hover {
        box-shadow: 0 4px 12px rgba(0,0,0,0.08);
    }

    /* ── Empty state boxes ─────────────────────────────────────────────── */
    .empty-state {
        text-align: center;
        padding: 48px 24px;
        color: #94A3B8;
        border: 2px dashed #E2E8F0;
        border-radius: 12px;
        margin: 24px 0;
    }
    .empty-state h3 { color: #64748B; margin-bottom: 8px; }

    /* ── Success state ─────────────────────────────────────────────────── */
    .success-state {
        text-align: center;
        padding: 40px 24px;
        background: linear-gradient(135deg, #F0FDF4 0%, #ECFDF5 100%);
        border: 1px solid #86EFAC;
        border-radius: 12px;
        margin: 24px 0;
    }

    /* ── Error callout ─────────────────────────────────────────────────── */
    .error-callout {
        background: #FEF2F2;
        border: 1px solid #FECACA;
        border-radius: 8px;
        padding: 16px;
        margin: 12px 0;
    }
    .error-callout code { background: #FEE2E2; padding: 2px 6px; border-radius: 4px; }

    /* ── Sidebar polish ────────────────────────────────────────────────── */
    section[data-testid="stSidebar"] { background: #F8FAFC; }
    </style>
    """, unsafe_allow_html=True)


inject_css()


# ── Colour palette (consistent with severity) ─────────────────────────────────
SEV_COLOURS = {
    'critical': '#EF4444',
    'high'    : '#F97316',
    'medium'  : '#EAB308',
    'low'     : '#3B82F6',
}
BAND_COLOURS = {'P1': '#EF4444', 'P2': '#F97316', 'P3': '#EAB308', 'P4': '#3B82F6'}
TYPE_COLOURS = {
    'misconfiguration': '#8B5CF6',
    'waste'           : '#10B981',
    'compliance'      : '#6B7280',
}


# ══════════════════════════════════════════════════════════════════════════════
# Cached AI calls  (avoid re-calling on every Streamlit re-render)
# ══════════════════════════════════════════════════════════════════════════════

@st.cache_data(show_spinner=False)
def cached_remediation(rule_id: str, resource_id: str, issue_json: str) -> str:
    return generate_remediation(json.loads(issue_json))


@st.cache_data(show_spinner=False)
def cached_risk_summary(resource_id: str, issues_json: str, total_rwc: float) -> str:
    return generate_risk_summary(resource_id, json.loads(issues_json), total_rwc)


@st.cache_data(show_spinner=False)
def cached_batch_report(issues_json: str) -> str:
    return generate_batch_report(json.loads(issues_json))


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def severity_badge(sev: str) -> str:
    icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}
    return f'{icons.get(sev, "")} {sev.upper()}'


def severity_badge_html(sev: str) -> str:
    """Inline HTML pill for use inside st.markdown(unsafe_allow_html=True)."""
    labels = {'critical': '🔴 CRITICAL', 'high': '🟠 HIGH',
              'medium': '🟡 MEDIUM', 'low': '🔵 LOW'}
    return (f'<span class="badge badge-{sev}">'
            f'{labels.get(sev, sev.upper())}</span>')


def band_badge(band: str) -> str:
    icons  = {'P1': '🔴', 'P2': '🟠', 'P3': '🟡', 'P4': '🔵'}
    labels = {'P1': 'Immediate', 'P2': 'Urgent', 'P3': 'This Sprint', 'P4': 'Hygiene'}
    return f'{icons.get(band, "")} **{band}** — {labels.get(band, "")}'


def band_badge_html(band: str) -> str:
    labels = {'P1': '🔴 P1 Immediate', 'P2': '🟠 P2 Urgent',
              'P3': '🟡 P3 Sprint', 'P4': '🔵 P4 Hygiene'}
    return (f'<span class="badge band-{band}">'
            f'{labels.get(band, band)}</span>')


def empty_state_html(icon: str, title: str, subtitle: str) -> None:
    st.markdown(
        f'<div class="empty-state"><div style="font-size:3rem">{icon}</div>'
        f'<h3>{title}</h3><p>{subtitle}</p></div>',
        unsafe_allow_html=True,
    )


def success_state_html(title: str, subtitle: str) -> None:
    st.markdown(
        f'<div class="success-state"><div style="font-size:3rem">✅</div>'
        f'<h3 style="color:#15803D">{title}</h3><p style="color:#166534">{subtitle}</p></div>',
        unsafe_allow_html=True,
    )


# ── JSON schema validation ────────────────────────────────────────────────────

REQUIRED_FIELDS = {'id', 'type'}
KNOWN_TYPES     = {'s3_bucket', 'ebs_volume', 'security_group', 'ec2_instance'}

def validate_inventory(data: object) -> tuple[bool, str]:
    """
    Light validation of the uploaded inventory.
    Returns (is_valid, error_message).
    """
    if not isinstance(data, list):
        return False, (
            'Expected a JSON **array** `[...]` at the top level, '
            f'but got `{type(data).__name__}`. '
            'Make sure your file is a list of resource objects.'
        )
    if len(data) == 0:
        return False, (
            'The inventory file is **empty** (the array has 0 items). '
            'Run `python data_generator.py` to generate sample data.'
        )
    if len(data) > 10_000:
        return False, (
            f'The inventory contains **{len(data):,} resources**, which exceeds '
            'the 10,000-resource limit for this MVP. Split the file into smaller batches.'
        )
    errors = []
    for i, item in enumerate(data[:20]):   # check first 20 items
        if not isinstance(item, dict):
            errors.append(f'Item at index {i} is not an object (got `{type(item).__name__}`)')
            continue
        missing = REQUIRED_FIELDS - item.keys()
        if missing:
            errors.append(f'Item at index {i} is missing required fields: {missing}')
        rtype = item.get('type')
        if rtype and rtype not in KNOWN_TYPES:
            pass   # unknown types are fine — engine will skip them gracefully
    if errors:
        return False, (
            f'Found **{len(errors)} schema problem(s)** in the first 20 resources:\n\n'
            + '\n'.join(f'- {e}' for e in errors[:5])
            + ('\n- *(more errors hidden)*' if len(errors) > 5 else '')
        )
    return True, ''


# ── Pandas Styler for color-coded severity ────────────────────────────────────

# Full background colours (light tints so text stays readable)
SEV_BG: dict[str, str] = {
    'CRITICAL': '#FEE2E2',
    'HIGH'    : '#FFF7ED',
    'MEDIUM'  : '#FEFCE8',
    'LOW'     : '#EFF6FF',
}
SEV_FG: dict[str, str] = {
    'CRITICAL': '#991B1B',
    'HIGH'    : '#9A3412',
    'MEDIUM'  : '#854D0E',
    'LOW'     : '#1E40AF',
}


def style_severity_row(row: pd.Series) -> list[str]:
    """Apply a subtle full-row tint based on the severity column."""
    sev = str(row.get('severity', '')).upper()
    bg  = SEV_BG.get(sev, '')
    fg  = SEV_FG.get(sev, '')
    base = f'background-color: {bg}; color: {fg};' if bg else ''
    return [base] * len(row)


def style_severity_cell(val: str) -> str:
    """Bold + coloured text for the severity cell itself."""
    key = str(val).upper()
    bg  = SEV_BG.get(key, '')
    fg  = SEV_FG.get(key, '')
    if bg:
        return (f'background-color: {bg}; color: {fg}; '
                'font-weight: 700; border-radius: 4px; padding: 2px 6px;')
    return ''


def apply_table_style(df_in: pd.DataFrame, sev_col: str = 'severity') -> pd.io.formats.style.Styler:
    """Return a styled DataFrame with color-coded severity rows and cell."""
    styler = df_in.style
    styler = styler.apply(style_severity_row, axis=1)
    if sev_col in df_in.columns:
        styler = styler.map(style_severity_cell, subset=[sev_col])
    return styler


def run_scan(inventory: list[dict]):
    """Full pipeline: detect → score → return scored issue dicts + rollups."""
    service = ScanService()
    result = service.execute_scan(inventory)
    return result.issues, result.resource_rollups




# Sidebar

with st.sidebar:
    st.image('https://img.icons8.com/fluency/96/cloud-checked.png', width=64)
    st.title('CloudGuardian AI')
    st.caption('Cloud risk & waste detection')
    st.divider()

    uploaded_file = st.file_uploader(
        'Upload cloud inventory JSON',
        type   = ['json'],
        help   = 'Generate a sample file by running: python data_generator.py',
    )

    use_sample = st.button('▶ Use built-in sample data', use_container_width=True)

    st.divider()

    # Filters (shown after data is loaded)
    st.subheader('Filters')
    filter_sev  = st.multiselect('Severity',   ['critical', 'high', 'medium', 'low'],
                                  default=['critical', 'high', 'medium', 'low'])
    filter_type = st.multiselect('Issue type', ['misconfiguration', 'waste', 'compliance'],
                                  default=['misconfiguration', 'waste', 'compliance'])
    filter_band = st.multiselect('Priority band', ['P1', 'P2', 'P3', 'P4'],
                                  default=['P1', 'P2', 'P3', 'P4'])

    st.divider()
    st.caption('Built with Streamlit · Phase 5 MVP')

# Load inventory  —  with full error handling

inventory: list[dict] | None = None

if uploaded_file is not None:
    # ── Parse JSON (catch malformed files) ────────────────────────────────────
    try:
        raw_bytes = uploaded_file.read()
        inventory = json.loads(raw_bytes)
    except json.JSONDecodeError as e:
        st.error('**Invalid JSON file** — could not parse the uploaded file.')
        st.markdown(
            f'<div class="error-callout">'
            f'<strong>Parse error:</strong> <code>{e}</code><br><br>'
            f'Common causes:<br>'
            f'• Trailing commas (not valid in JSON)<br>'
            f'• Single quotes instead of double quotes<br>'
            f'• Missing closing bracket or brace<br><br>'
            f'Tip: validate your file at <a href="https://jsonlint.com" target="_blank">jsonlint.com</a>'
            f'</div>',
            unsafe_allow_html=True,
        )
        inventory = None

    # ── Schema validation ─────────────────────────────────────────────────────
    if inventory is not None:
        valid, err_msg = validate_inventory(inventory)
        if not valid:
            st.error('**Inventory validation failed**')
            st.markdown(
                f'<div class="error-callout">{err_msg}<br><br>'
                f'Run <code>python data_generator.py</code> to generate a valid sample file.'
                f'</div>',
                unsafe_allow_html=True,
            )
            inventory = None
        else:
            st.session_state['inventory_name'] = uploaded_file.name

elif use_sample or st.session_state.get('use_sample'):
    st.session_state['use_sample'] = True
    try:
        with open('data/sample_inventory.json') as f:
            inventory = json.load(f)
        st.session_state['inventory_name'] = 'sample_inventory.json (built-in)'
    except FileNotFoundError:
        st.error('**Sample file not found.**')
        st.markdown(
            '<div class="error-callout">'
            'Run <code>python data_generator.py</code> first to create '
            '<code>data/sample_inventory.json</code>.'
            '</div>',
            unsafe_allow_html=True,
        )
    except json.JSONDecodeError as e:
        st.error(f'**Sample file is corrupted:** `{e}`')
        st.info('Re-run `python data_generator.py` to regenerate it.')


# Landing screen (no data yet)

if inventory is None:
    st.markdown('## ☁️ CloudGuardian AI Copilot')
    st.markdown('#### Detect, prioritise, and fix cloud risks & waste')
    st.info('👈 Upload a cloud inventory JSON or click **Use built-in sample data** to get started.')

    with st.expander('What does this dashboard do?'):
        st.markdown("""
**CloudGuardian AI** scans your AWS resource inventory and surfaces:

| Category | Examples |
|---|---|
| 🔒 Security misconfigurations | Public S3 buckets, open SSH/RDP ports, unencrypted volumes |
| 💸 Cost waste | Unattached EBS volumes, idle buckets, gp2→gp3 upgrade opportunities |
| 📋 Compliance gaps | Missing tags, default security groups in use, no access logging |

Each finding is scored using **Risk-Weighted Cost (RWC)** — a composite score that
factors in severity, data sensitivity, issue type, financial waste, and region risk.

**How to generate sample data:**
```bash
python data_generator.py        # creates data/sample_inventory.json
```
        """)
    st.stop()


# Run scan (cached by inventory fingerprint)

inventory_key = json.dumps(inventory, sort_keys=True)

@st.cache_data(show_spinner='🔍 Scanning inventory for issues…')
def cached_scan(inv_key: str) -> tuple[list[dict], list[dict]]:
    return run_scan(json.loads(inv_key))

try:
    scored_all, rollups_all = cached_scan(inventory_key)
except Exception as e:
    st.error('**Scan failed unexpectedly.**')
    st.markdown(
        f'<div class="error-callout">'
        f'<strong>Error:</strong> <code>{e}</code><br><br>'
        f'This is likely a bug in the detection engine. '
        f'Check that <code>detection_engine.py</code> and <code>rwc_calculator.py</code> '
        f'are in the same directory as <code>app.py</code>.'
        f'</div>',
        unsafe_allow_html=True,
    )
    st.stop()

# ── Zero issues — clean inventory ─────────────────────────────────────────────
if len(scored_all) == 0:
    st.markdown(f'## ☁️ CloudGuardian AI Copilot')
    st.caption(f'Inventory: **{st.session_state.get("inventory_name", "unknown")}** · '
               f'{len(inventory)} resources scanned')
    success_state_html(
        'No issues found — your inventory looks clean! 🎉',
        f'Scanned {len(inventory)} resources across all detection rules with zero findings.',
    )
    st.info('If you expected to see issues, check that your inventory includes '
            '`s3_bucket`, `ebs_volume`, or `security_group` resource types.')
    st.stop()


scored = [
    s for s in scored_all
    if s['severity']     in filter_sev
    and s['issue_type']  in filter_type
    and s['priority_band'] in filter_band
]

df = pd.DataFrame(scored)



# Header

st.markdown(f'## ☁️ CloudGuardian AI Copilot')
st.caption(f'Inventory: **{st.session_state.get("inventory_name", "unknown")}** · '
           f'{len(inventory)} resources · {len(scored_all)} issues found '
           f'({len(scored)} shown after filters)')


# KPI row

total_waste    = sum(s['waste_cost']  for s in scored)
critical_count = sum(1 for s in scored if s['severity']      == 'critical')
p1_count       = sum(1 for s in scored if s['priority_band'] == 'P1')
avg_rwc        = round(sum(s['rwc'] for s in scored) / max(len(scored), 1), 1)

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric('💸 Monthly Waste',    f'${total_waste:,.2f}')
k2.metric('🔴 Critical Issues',  critical_count)
k3.metric('🚨 P1 (Immediate)',   p1_count)
k4.metric('📋 Total Issues',     len(scored))
k5.metric('📊 Avg RWC Score',    avg_rwc)

st.divider()

# Charts row

tab_overview, tab_issues, tab_resources, tab_ai = st.tabs([
    '📊 Overview', '🔍 Issue Explorer', '🖥️ Resource Risk', '🤖 AI Copilot'
])


# ── Tab 1: Overview ────────────────────────────────────────────────────────────

with tab_overview:
    c1, c2, c3 = st.columns(3)

    # Severity donut
    with c1:
        sev_counts = Counter(s['severity'] for s in scored)
        fig = go.Figure(go.Pie(
            labels = list(sev_counts.keys()),
            values = list(sev_counts.values()),
            hole   = 0.55,
            marker_colors = [SEV_COLOURS.get(k, '#999') for k in sev_counts],
        ))
        fig.update_layout(title='Issues by Severity', height=300,
                          margin=dict(t=40, b=0, l=0, r=0),
                          showlegend=True, legend=dict(orientation='h'))
        st.plotly_chart(fig, use_container_width=True)

    # Priority band bar
    with c2:
        band_counts = Counter(s['priority_band'] for s in scored)
        bands = ['P1', 'P2', 'P3', 'P4']
        fig = go.Figure(go.Bar(
            x     = bands,
            y     = [band_counts.get(b, 0) for b in bands],
            marker_color = [BAND_COLOURS[b] for b in bands],
            text  = [band_counts.get(b, 0) for b in bands],
            textposition = 'outside',
        ))
        fig.update_layout(title='Issues by Priority Band', height=300,
                          margin=dict(t=40, b=0, l=0, r=0),
                          yaxis_title='Count', xaxis_title='Band')
        st.plotly_chart(fig, use_container_width=True)

    # Issue type bar
    with c3:
        type_counts = Counter(s['issue_type'] for s in scored)
        fig = go.Figure(go.Bar(
            x     = list(type_counts.keys()),
            y     = list(type_counts.values()),
            marker_color = [TYPE_COLOURS.get(k, '#999') for k in type_counts],
            text  = list(type_counts.values()),
            textposition = 'outside',
        ))
        fig.update_layout(title='Issues by Type', height=300,
                          margin=dict(t=40, b=0, l=0, r=0),
                          yaxis_title='Count')
        st.plotly_chart(fig, use_container_width=True)

    # RWC scatter: waste_cost vs rwc, coloured by severity
    st.subheader('RWC Score vs Monthly Waste')
    if len(df) > 0:
        fig = px.scatter(
            df,
            x         = 'waste_cost',
            y         = 'rwc',
            color     = 'severity',
            symbol    = 'issue_type',
            hover_data= ['resource_id', 'rule_id', 'description', 'priority_band'],
            color_discrete_map = SEV_COLOURS,
            labels    = {'waste_cost': 'Monthly Waste ($)', 'rwc': 'RWC Score'},
            height    = 400,
        )
        fig.update_traces(marker=dict(size=9, opacity=0.8))
        fig.update_layout(margin=dict(t=20, b=40))
        st.plotly_chart(fig, use_container_width=True)

    # Top rules triggered
    st.subheader('Most Triggered Rules')
    rule_counts = Counter(s['rule_id'] for s in scored)
    rule_df = pd.DataFrame(rule_counts.most_common(10),
                           columns=['rule_id', 'count'])
    fig = px.bar(rule_df, x='count', y='rule_id', orientation='h',
                 color='count', color_continuous_scale='Reds',
                 height=350, labels={'count': 'Occurrences', 'rule_id': 'Rule'})
    fig.update_layout(margin=dict(t=10, b=10), yaxis=dict(autorange='reversed'))
    st.plotly_chart(fig, use_container_width=True)


# ── Tab 2: Issue Explorer ──────────────────────────────────────────────────────

with tab_issues:
    st.subheader('All Issues — sorted by RWC (highest first)')

    if df.empty:
        empty_state_html(
            '🔍',
            'No issues match your current filters',
            'Try relaxing the Severity, Issue type, or Priority band filters in the sidebar.',
        )
    else:
        # ── Color-coded styled table ──────────────────────────────────────────
        display_cols = ['rank', 'rwc', 'priority_band', 'severity', 'rule_id',
                        'resource_id', 'resource_type', 'region',
                        'issue_type', 'waste_cost', 'description']
        display_df = df[display_cols].copy()
        display_df['severity']      = display_df['severity'].str.upper()
        display_df['waste_cost_fmt']= display_df['waste_cost'].apply(
                                          lambda x: f'${x:.2f}' if x else '—')
        display_df['rwc_fmt']       = display_df['rwc'].apply(lambda x: f'{x:.2f}')

        show_cols = ['rank', 'rwc_fmt', 'priority_band', 'severity', 'rule_id',
                     'resource_id', 'resource_type', 'region',
                     'issue_type', 'waste_cost_fmt', 'description']
        rename_map = {'rwc_fmt': 'RWC ↓', 'waste_cost_fmt': 'Waste/mo',
                      'priority_band': 'Band', 'resource_id': 'Resource',
                      'resource_type': 'Type', 'rule_id': 'Rule'}

        styled = apply_table_style(display_df[show_cols].rename(columns=rename_map),
                                   sev_col='severity')
        st.dataframe(styled, use_container_width=True, hide_index=True)

        st.caption(f'Showing {len(df)} issues · '
                   f'{sum(1 for s in scored if s["severity"] == "critical")} critical · '
                   f'${sum(s["waste_cost"] for s in scored):,.2f} total waste')

    # ── Issue detail panel ────────────────────────────────────────────────────
    st.divider()
    st.subheader('Issue Detail & AI Remediation')
    if not df.empty:
        rule_options = df[['rule_id', 'resource_id', 'severity']].apply(
            lambda r: f"[{r['severity'].upper()}] {r['rule_id']} → {r['resource_id']}", axis=1
        ).tolist()
        selected_label = st.selectbox('Select an issue', rule_options)
        selected_idx   = rule_options.index(selected_label)
        selected_issue = scored[selected_idx]

        sev = selected_issue['severity']
        st.markdown(
            f'<div class="issue-card issue-card-{sev}">'
            f'{severity_badge_html(sev)} &nbsp; {band_badge_html(selected_issue["priority_band"])}'
            f'<br><br><strong>{selected_issue["description"]}</strong>'
            f'</div>',
            unsafe_allow_html=True,
        )

        ic1, ic2 = st.columns([1, 2])

        with ic1:
            st.markdown(f'**Resource:** `{selected_issue["resource_id"]}`')
            st.markdown(f'**Type:** {selected_issue["resource_type"]}')
            st.markdown(f'**Region:** {selected_issue.get("region", "—")}')
            st.markdown(f'**RWC Score:** `{selected_issue["rwc"]}`')
            if selected_issue['waste_cost'] > 0:
                st.markdown(f'**Monthly waste:** 💸 `${selected_issue["waste_cost"]:.2f}`')

            with st.expander('📊 Score breakdown'):
                sb = {k: selected_issue[k] for k in
                      ['severity_score', 'sensitivity_mult', 'pii_boost',
                       'type_mult', 'urgency_boost', 'cost_factor', 'region_factor', 'rwc']}
                st.json(sb)

        with ic2:
            st.markdown(f'**Static remediation:**')
            st.info(selected_issue["remediation"])

            if st.button('🤖 Generate AI remediation plan', key='btn_remediate'):
                with st.spinner('Asking Claude for a remediation plan…'):
                    try:
                        plan = cached_remediation(
                            selected_issue['rule_id'],
                            selected_issue['resource_id'],
                            json.dumps(selected_issue),
                        )
                        st.session_state['ai_plan'] = plan
                        st.session_state['ai_plan_for'] = selected_issue['resource_id']
                    except Exception as e:
                        st.session_state['ai_plan'] = (
                            f'⚠️ AI unavailable: `{e}`. '
                            'Use the static remediation above.'
                        )

            if 'ai_plan' in st.session_state:
                st.markdown('**🤖 AI Remediation Plan:**')
                st.markdown(st.session_state['ai_plan'])


# ── Tab 3: Resource Risk ───────────────────────────────────────────────────────

with tab_resources:
    st.subheader('Most At-Risk Resources')
    st.caption('Total RWC is the sum of all issue scores for that resource — '
               'the higher the number, the more urgently it needs attention.')

    if not rollups_all:
        empty_state_html('🖥️', 'No resources to display',
                         'Run the scan with a valid inventory file to see resource-level risk.')
    else:
        rollup_display = []
        for r in rollups_all:
            rollup_display.append({
                'resource_id'   : r['resource_id'],
                'resource_type' : r['resource_type'],
                'region'        : r['region'],
                'total_rwc'     : r['total_rwc'],
                'issue_count'   : r['issue_count'],
                'severity'      : r['worst_severity'].upper(),   # reuse severity styler
                'worst_band'    : r['worst_band'],
                'monthly_waste' : r['total_waste_cost'],
            })

        rollup_df = pd.DataFrame(rollup_display)
        rollup_df['monthly_waste_fmt'] = rollup_df['monthly_waste'].apply(
            lambda x: f'${x:.2f}' if x else '—'
        )
        styled_rollup = apply_table_style(
            rollup_df[['resource_id', 'resource_type', 'region', 'total_rwc',
                        'issue_count', 'severity', 'worst_band', 'monthly_waste_fmt']]
            .rename(columns={'monthly_waste_fmt': 'Waste/mo',
                             'worst_band': 'Band',
                             'total_rwc': 'Total RWC ↓'}),
            sev_col='severity'
        )
        st.dataframe(styled_rollup, use_container_width=True, hide_index=True)

        # Top 10 resource bar chart
        top10 = rollup_df.head(10)
        fig = px.bar(top10, x='total_rwc', y='resource_id', orientation='h',
                     color='severity', color_discrete_map={
                         'CRITICAL': SEV_COLOURS['critical'],
                         'HIGH'    : SEV_COLOURS['high'],
                         'MEDIUM'  : SEV_COLOURS['medium'],
                         'LOW'     : SEV_COLOURS['low'],
                     },
                     height=400, labels={'total_rwc': 'Total RWC', 'resource_id': 'Resource'},
                     title='Top 10 Most At-Risk Resources')
        fig.update_layout(yaxis=dict(autorange='reversed'), margin=dict(t=40))
        st.plotly_chart(fig, use_container_width=True)

        # ── Per-resource drill-down ───────────────────────────────────────────
        st.subheader('Resource Drill-Down')
        res_ids = [r['resource_id'] for r in rollups_all]
        selected_res = st.selectbox('Select resource', res_ids, key='res_drill')

        if selected_res:
            rollup = next(r for r in rollups_all if r['resource_id'] == selected_res)
            res_issues = rollup['issues']

            rc1, rc2, rc3 = st.columns(3)
            rc1.metric('Total RWC',     rollup['total_rwc'])
            rc2.metric('Issues',        rollup['issue_count'])
            rc3.metric('Monthly Waste', f'${rollup["total_waste_cost"]:.2f}')

            if not res_issues:
                empty_state_html('🎉', 'No issues on this resource',
                                 'This resource passed all detection rules.')
            else:
                for iss in res_issues:
                    sev = iss['severity']
                    with st.expander(
                        f'{severity_badge(sev)}  [{iss["rule_id"]}]  '
                        f'RWC={iss["rwc"]}  —  {iss["description"][:70]}'
                        + ('…' if len(iss["description"]) > 70 else '')
                    ):
                        st.markdown(
                            f'<div class="issue-card issue-card-{sev}">'
                            f'{severity_badge_html(sev)} &nbsp; {band_badge_html(iss["priority_band"])}'
                            f'</div>',
                            unsafe_allow_html=True,
                        )
                        st.markdown(f'**Remediation:** {iss["remediation"]}')
                        if iss['waste_cost'] > 0:
                            st.markdown(f'**Waste:** 💸 ${iss["waste_cost"]:.2f}/mo')

            if st.button('🤖 Generate AI risk summary', key='btn_summary'):
                with st.spinner('Claude is analysing this resource…'):
                    try:
                        summary = cached_risk_summary(
                            selected_res,
                            json.dumps(res_issues),
                            rollup['total_rwc'],
                        )
                        st.session_state['res_summary'] = summary
                    except Exception as e:
                        st.session_state['res_summary'] = (
                            f'⚠️ AI unavailable: `{e}`. '
                            'Use the issue details above for context.'
                        )

            if 'res_summary' in st.session_state:
                st.info(st.session_state['res_summary'])


# ── Tab 4: AI Copilot ──────────────────────────────────────────────────────────

with tab_ai:
    st.subheader('🤖 AI Executive Report')
    st.markdown(
        'Generate a plain-English executive summary of the full scan — '
        'suitable for a team standup, Slack message, or management brief.'
    )

    if st.button('Generate executive summary', use_container_width=True):
        with st.spinner('Claude is writing the executive summary…'):
            try:
                report = cached_batch_report(json.dumps(scored_all[:20]))
                st.session_state['exec_report'] = report
            except Exception as e:
                st.session_state['exec_report'] = (
                    f'⚠️ AI unavailable (`{e}`). '
                    'Check your API key and network connection.'
                )

    if 'exec_report' in st.session_state:
        report_text = st.session_state['exec_report']
        if report_text.startswith('⚠️'):
            st.warning(report_text)
        else:
            st.success(report_text)

    st.divider()
    st.subheader('💸 Waste Summary')

    waste_issues = [s for s in scored_all if s['waste_cost'] > 0]
    if not waste_issues:
        success_state_html(
            'No cost waste detected!',
            'All resources appear to be actively used and appropriately sized.',
        )
    else:
        total_monthly = sum(s['waste_cost'] for s in waste_issues)
        st.metric('Total recoverable waste', f'${total_monthly:,.2f} / month',
                  delta=f'~${total_monthly * 12:,.0f} / year', delta_color='inverse')

        waste_df = pd.DataFrame([{
            'resource_id' : s['resource_id'],
            'rule_id'     : s['rule_id'],
            'severity'    : s['severity'].upper(),
            'waste_cost'  : s['waste_cost'],
            'description' : s['description'],
        } for s in sorted(waste_issues, key=lambda x: x['waste_cost'], reverse=True)])

        st.dataframe(
            apply_table_style(waste_df, sev_col='severity'),
            use_container_width=True, hide_index=True,
        )

    st.divider()
    st.subheader('📥 Export')

    col_e1, col_e2 = st.columns(2)
    with col_e1:
        csv_buf = io.StringIO()
        df.to_csv(csv_buf, index=False)
        st.download_button(
            '⬇ Download issues CSV',
            data      = csv_buf.getvalue(),
            file_name = 'cloudguardian_issues.csv',
            mime      = 'text/csv',
            use_container_width = True,
        )
    with col_e2:
        st.download_button(
            '⬇ Download issues JSON',
            data      = json.dumps(scored_all, indent=2),
            file_name = 'cloudguardian_scored_issues.json',
            mime      = 'application/json',
            use_container_width = True,
        )
