"""
Example: How to integrate the new config system into existing code

This shows how to refactor detection_engine.py and rwc_calculator.py
to use the external config instead of hardcoded values.
"""

# ════════════════════════════════════════════════════════════════════════════
# EXAMPLE 1: Update rwc_calculator.py to use config
# ════════════════════════════════════════════════════════════════════════════

# OLD (hardcoded):
# ───────────────
# SEVERITY_SCORES: dict[str, float] = {
#     'critical': 10.0,
#     'high'    :  7.0,
#     'medium'  :  4.0,
#     'low'     :  1.0,
# }

# NEW (config-driven):
# ────────────────────
from core.config import get_config

def calculate_rwc(issue: dict):
    config = get_config()
    
    severity = issue.get('severity', 'low')
    sensitivity = issue.get('data_sensitivity')
    issue_type = issue.get('issue_type', 'compliance')
    rule_id = issue.get('rule_id', '')
    waste_cost = float(issue.get('waste_cost', 0.0))
    region = issue.get('region', '')
    
    # Get scoring values from config
    sev_score = config.severity_scores.get(severity, 1.0)
    sens_mult = config.data_sensitivity_multipliers.get(sensitivity, 1.0)
    type_mult = config.issue_type_multipliers.get(issue_type, 1.0)
    
    # Check if rule is high-urgency (from config)
    urgency_b = 1.0 if rule_id in config.high_urgency_rules_set else 0.0
    pii_b = config.severity.pii_tag_boost if issue.get('extra', {}).get('contains_pii') else 0.0
    
    # Get region risk factor from config
    region_f = config.region_risk_factors.get(region, 0.0)
    
    # Calculate RWC
    risk_core = sev_score * sens_mult * type_mult
    rwc = round(risk_core + pii_b + urgency_b + cost_f + region_f, 2)
    
    # Get priority band from config
    priority_band = config.priority_band_for_rwc(rwc)
    
    return rwc, priority_band


# ════════════════════════════════════════════════════════════════════════════
# EXAMPLE 2: Gating rules based on config
# ════════════════════════════════════════════════════════════════════════════

# detection_engine.py would check if rules are enabled:

from core.config import get_config

def scan_inventory(data: list[dict]):
    config = get_config()
    all_issues = []
    
    for res in data:
        rtype = res.get('type', '')
        
        # Only run S3 checks if S3 rules are enabled
        if rtype == 's3_bucket' and config.is_rule_enabled('S3_PUBLIC_BUCKET'):
            all_issues.extend(check_s3_bucket(res, config))
        
        # Only run EBS checks if EBS rules are enabled
        elif rtype == 'ebs_volume' and config.is_rule_enabled('EBS_UNATTACHED'):
            all_issues.extend(check_ebs_volume(res, config))
        
        # Only run SG checks if SG rules are enabled
        elif rtype == 'security_group' and config.is_rule_enabled('SG_OPEN_SSH'):
            all_issues.extend(check_security_group(res, config))
    
    return all_issues


# ════════════════════════════════════════════════════════════════════════════
# EXAMPLE 3: Use config in app.py
# ════════════════════════════════════════════════════════════════════════════

import streamlit as st
from core.config import get_config

# Initialize config once at app startup
config = get_config()

st.title('CloudGuardian AI')

# Show scoring info from config
with st.expander('ℹ️ Scoring Configuration'):
    col1, col2 = st.columns(2)
    with col1:
        st.subheader('Severity Scores')
        st.write(config.severity_scores)
    with col2:
        st.subheader('Sensitivity Multipliers')
        st.write(config.data_sensitivity_multipliers)


# ════════════════════════════════════════════════════════════════════════════
# USAGE GUIDE
# ════════════════════════════════════════════════════════════════════════════

"""
QUICK START:

1. Import config:
   from core.config import Config, get_config, init_config

2. Initialize at application startup (if using custom path):
   init_config('config.yaml')

3. Get config anywhere:
   config = get_config()

4. Query configuration:
   config.severity_scores                          # {'critical': 10.0, ...}
   config.is_rule_enabled('S3_PUBLIC_BUCKET')      # True/False
   config.priority_band_for_rwc(27)                # 'P1'
   config.data_sensitivity_multipliers             # {'high': 2.5, ...}
   config.region_risk_factors                      # {'eu-west-1': 0.5, ...}
   config.high_urgency_rules_set                   # {'S3_PUBLIC_BUCKET', ...}
   config.get_rule_threshold('S3_IDLE_BUCKET', 'idle_days_threshold')  # 90

5. Modify config.yaml and restart app (no code changes needed!)
"""
