
from __future__ import annotations

import json
import math
import argparse
import os
from dataclasses import dataclass, asdict, field
from typing import Optional
from collections import defaultdict

from core.config import Config, get_config


# 3.1  Scoring tables

# Base severity scores
SEVERITY_SCORES: dict[str, float] = {
    'critical': 10.0,
    'high'    :  7.0,
    'medium'  :  4.0,
    'low'     :  1.0,
}

# Data sensitivity multiplier — how much more dangerous is an issue
# when the resource holds sensitive / PII data?
SENSITIVITY_MULTIPLIERS: dict[str | None, float] = {
    'high'  : 2.5,    # e.g. PII-tagged or high-sensitivity resource
    'medium': 1.5,
    'low'   : 1.0,
    None    : 1.0,    # unknown / untagged — no boost, but no penalty
}

# Extra boost when the contains_pii tag is explicitly 'true'
PII_BOOST: float = 1.5

# Issue-type multiplier — misconfigurations score higher than compliance gaps;
# pure waste issues are scored primarily by cost_factor
ISSUE_TYPE_MULTIPLIERS: dict[str, float] = {
    'misconfiguration': 1.2,
    'waste'           : 0.8,
    'compliance'      : 1.0,
}

# Region risk factor — some regions may have stricter regulatory requirements
# (e.g. eu-west-1 is GDPR territory)
REGION_RISK: dict[str, float] = {
    'eu-west-1'   : 0.5,   # GDPR — slightly higher regulatory risk
    'eu-central-1': 0.5,
    'ap-south-1'  : 0.3,   # PDPA / local regulations
    'us-east-1'   : 0.0,
    'us-west-2'   : 0.0,
    'ap-southeast-1': 0.2,
}

# Rules that get an extra urgency boost (known to be actively exploited)
HIGH_URGENCY_RULES: set[str] = {
    'S3_PUBLIC_BUCKET',
    'SG_OPEN_SSH',
    'SG_OPEN_RDP',
    'SG_ALLOW_ALL_INBOUND',
    'COM_HIGH_SENSITIVITY_UNENCRYPTED',
    'EBS_UNENCRYPTED',
}
URGENCY_BOOST: float = 1.0


# 3.2  Scored issue dataclass

@dataclass
class ScoredIssue:
    # ── all original Issue fields ──────────────────────────────────────────────
    resource_id     : str
    resource_type   : str
    issue_type      : str
    severity        : str
    rule_id         : str
    description     : str
    remediation     : str
    waste_cost      : float          = 0.0
    data_sensitivity: Optional[str]  = None
    region          : Optional[str]  = None
    extra           : dict           = field(default_factory=dict)

    # ── RWC scoring breakdown ──────────────────────────────────────────────────
    rwc             : float          = 0.0   # final composite score
    severity_score  : float          = 0.0   # base severity component
    sensitivity_mult: float          = 1.0   # data sensitivity multiplier
    pii_boost       : float          = 0.0   # PII tag extra boost
    type_mult       : float          = 1.0   # issue type multiplier
    urgency_boost   : float          = 0.0   # high-urgency rule boost
    cost_factor     : float          = 0.0   # log-scaled waste cost component
    region_factor   : float          = 0.0   # regional regulatory risk
    priority_band   : str            = ''    # 'P1' … 'P4' for easy filtering
    rank            : int            = 0     # rank within full scan (1 = worst)


# 3.3  Core RWC calculation

def calculate_rwc(issue: dict, cfg: Config | None = None) -> ScoredIssue:
   
    cfg = cfg or get_config()

    # ── pull fields ───────────────────────────────────────────────────────────
    severity    = issue.get('severity', 'low')
    sensitivity = issue.get('data_sensitivity')          # 'high' | 'medium' | 'low' | None
    issue_type  = issue.get('issue_type', 'compliance')
    rule_id     = issue.get('rule_id', '')
    waste_cost  = float(issue.get('waste_cost', 0.0))
    region      = issue.get('region', '')
    tags        = issue.get('extra', {})
    has_pii     = (tags.get('contains_pii') is True
                   or issue.get('extra', {}).get('contains_pii') is True)

    # ── score components ──────────────────────────────────────────────────────
    sev_score = cfg.severity_scores.get(severity, 1.0)
    sensitivity_key = sensitivity if sensitivity in cfg.data_sensitivity_multipliers else 'unknown'
    sens_mult = cfg.data_sensitivity_multipliers.get(sensitivity_key, 1.0)
    type_mult = cfg.issue_type_multipliers.get(issue_type, 1.0)
    pii_b = cfg.severity.pii_tag_boost if has_pii else 0.0
    urgency_b = cfg.scoring.urgency_boost if rule_id in cfg.high_urgency_rules_set else 0.0
    cost_f = round(math.log(waste_cost + 1), 4) if cfg.scoring.cost_dampening else round(waste_cost, 4)
    region_f = cfg.region_risk_factors.get(region, cfg.region_risk_factors.get('default', 0.0))

    risk_core    = sev_score * sens_mult * type_mult
    rwc          = round(risk_core + pii_b + urgency_b + cost_f + region_f, 2)

    # ── priority band ─────────────────────────────────────────────────────────
    # Thresholds tuned so that genuine critical-PII issues land in P1,
    # pure compliance/tagging issues land in P4.
    band = cfg.priority_band_for_rwc(rwc)

    return ScoredIssue(
        # original fields
        resource_id      = issue.get('resource_id', ''),
        resource_type    = issue.get('resource_type', ''),
        issue_type       = issue_type,
        severity         = severity,
        rule_id          = rule_id,
        description      = issue.get('description', ''),
        remediation      = issue.get('remediation', ''),
        waste_cost       = waste_cost,
        data_sensitivity = sensitivity,
        region           = region,
        extra            = issue.get('extra', {}),
        # scoring fields
        rwc              = rwc,
        severity_score   = sev_score,
        sensitivity_mult = sens_mult,
        pii_boost        = pii_b,
        type_mult        = type_mult,
        urgency_boost    = urgency_b,
        cost_factor      = cost_f,
        region_factor    = region_f,
        priority_band    = band,
    )


# 3.4  Batch scoring + per-resource aggregation

def score_all(issues: list[dict]) -> list[ScoredIssue]:
    """
    Score every issue and assign a global rank (1 = highest RWC).
    Returns list sorted highest → lowest RWC.
    """
    cfg = get_config()
    scored = [calculate_rwc(i, cfg=cfg) for i in issues]
    scored.sort(key=lambda s: s.rwc, reverse=True)
    for rank, s in enumerate(scored, start=1):
        s.rank = rank
    return scored


@dataclass
class ResourceRollup:
    """Aggregated risk picture for a single cloud resource."""
    resource_id     : str
    resource_type   : str
    region          : str
    total_rwc       : float
    issue_count     : int
    worst_severity  : str
    worst_band      : str
    total_waste_cost: float
    issues          : list[ScoredIssue]


def rollup_by_resource(scored: list[ScoredIssue]) -> list[ResourceRollup]:
    """
    Aggregate scored issues by resource_id.
    Returns list sorted by total_rwc descending — your 'most dangerous resources' list.
    """
    sev_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    band_rank = {'P1': 0, 'P2': 1, 'P3': 2, 'P4': 3}

    groups: dict[str, list[ScoredIssue]] = defaultdict(list)
    for s in scored:
        groups[s.resource_id].append(s)

    rollups: list[ResourceRollup] = []
    for res_id, items in groups.items():
        worst_sev  = min(items, key=lambda x: sev_rank.get(x.severity, 9)).severity
        worst_band = min(items, key=lambda x: band_rank.get(x.priority_band, 9)).priority_band
        rollups.append(ResourceRollup(
            resource_id      = res_id,
            resource_type    = items[0].resource_type,
            region           = items[0].region or '',
            total_rwc        = round(sum(i.rwc for i in items), 2),
            issue_count      = len(items),
            worst_severity   = worst_sev,
            worst_band       = worst_band,
            total_waste_cost = round(sum(i.waste_cost for i in items), 2),
            issues           = sorted(items, key=lambda x: x.rwc, reverse=True),
        ))

    rollups.sort(key=lambda r: r.total_rwc, reverse=True)
    return rollups


# Reporting

BAND_ICONS = {'P1': '🔴', 'P2': '🟠', 'P3': '🟡', 'P4': '🔵'}
SEV_ICONS  = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}


def print_score_breakdown(s: ScoredIssue) -> None:
    """Print a detailed score breakdown for one issue — great for debugging rules."""
    print(f'\n  {"─"*58}')
    print(f'  Issue   : [{s.rule_id}] on {s.resource_id}')
    print(f'  Severity: {SEV_ICONS.get(s.severity,"")} {s.severity}')
    print(f'  Band    : {BAND_ICONS.get(s.priority_band,"")} {s.priority_band}')
    print(f'  {"─"*58}')
    print(f'  {"Component":<28} {"Value":>8}')
    print(f'  {"─"*28}  {"─"*8}')
    print(f'  {"severity_score":<28} {s.severity_score:>8.2f}')
    print(f'  {"× sensitivity_mult":<28} {s.sensitivity_mult:>8.2f}')
    print(f'  {"× type_mult":<28} {s.type_mult:>8.2f}')
    risk_core = s.severity_score * s.sensitivity_mult * s.type_mult
    print(f'  {"  = risk_core":<28} {risk_core:>8.2f}')
    print(f'  {"+ pii_boost":<28} {s.pii_boost:>8.2f}')
    print(f'  {"+ urgency_boost":<28} {s.urgency_boost:>8.2f}')
    print(f'  {"+ cost_factor (log)":<28} {s.cost_factor:>8.4f}  (waste=${s.waste_cost}/mo)')
    print(f'  {"+ region_factor":<28} {s.region_factor:>8.2f}  ({s.region})')
    print(f'  {"─"*28}  {"─"*8}')
    print(f'  {"RWC (final)":<28} {s.rwc:>8.2f}')
    print(f'  {"─"*58}\n')


def print_full_report(scored: list[ScoredIssue], top_n: int | None = None) -> None:
    """Print ranked issue table + summary stats."""
    from collections import Counter

    display = scored[:top_n] if top_n else scored
    total_waste = sum(s.waste_cost for s in scored)

    band_counts = Counter(s.priority_band for s in scored)
    type_counts = Counter(s.issue_type    for s in scored)

    print('\n' + '═' * 70)
    print('  RISK-WEIGHTED COST (RWC) REPORT')
    print('═' * 70)
    print(f'  Issues scored     : {len(scored)}')
    print(f'  Total waste/month : ${total_waste:,.2f}')
    print()
    print('  Priority distribution:')
    for band in ('P1', 'P2', 'P3', 'P4'):
        count = band_counts.get(band, 0)
        icon  = BAND_ICONS[band]
        bar   = '█' * min(count, 40)
        label = {'P1':'Immediate','P2':'Urgent','P3':'Important','P4':'Hygiene'}[band]
        print(f'    {icon} {band} {label:<12} {count:>4}  {bar}')
    print()
    print('  By issue type:')
    for itype, count in type_counts.most_common():
        print(f'    • {itype:<20} {count}')

    print()
    header = f'  {"Rank":>4}  {"RWC":>6}  {"Band"}  {"Severity":<10}  {"Rule ID":<35}  {"Resource":<12}'
    print(header)
    print('  ' + '─' * (len(header) - 2))

    for s in display:
        icon = BAND_ICONS.get(s.priority_band, '')
        cost_tag = f'  💸${s.waste_cost:.0f}' if s.waste_cost > 0 else ''
        print(
            f'  {s.rank:>4}  {s.rwc:>6.2f}  '
            f'{icon}{s.priority_band}  {s.severity:<10}  '
            f'{s.rule_id:<35}  {s.resource_id:<12}{cost_tag}'
        )

    print()

    # Top 5 most at-risk resources
    rollups = rollup_by_resource(scored)
    print('  Top 5 most at-risk resources:')
    print('  ' + '─' * 60)
    for r in rollups[:5]:
        icon = BAND_ICONS.get(r.worst_band, '')
        print(f'  {icon} {r.resource_id:<14} ({r.resource_type})')
        print(f'     Total RWC: {r.total_rwc:.2f}  |  Issues: {r.issue_count}  |  '
              f'Waste: ${r.total_waste_cost:.2f}/mo  |  Region: {r.region}')
        for iss in r.issues[:3]:
            print(f'       └─ [{iss.rule_id}]  RWC={iss.rwc}  ({iss.severity})')
        print()

    print('═' * 70 + '\n')


def print_resource_breakdown(scored: list[ScoredIssue], resource_id: str) -> None:
    """Deep-dive score breakdown for every issue on a specific resource."""
    issues = [s for s in scored if s.resource_id == resource_id]
    if not issues:
        print(f'\n  ❌  No issues found for resource: {resource_id}')
        return
    print(f'\n  Score breakdown for resource: {resource_id}')
    for s in issues:
        print_score_breakdown(s)
    total = round(sum(s.rwc for s in issues), 2)
    print(f'  Total RWC for {resource_id}: {total}  ({len(issues)} issues)\n')


# Integration helper — use this from other modules

def score_from_detection(issues_raw: list) -> list[ScoredIssue]:
    """
    Accept either a list of Issue dataclass objects (from detection_engine)
    or plain dicts, and return scored results.

    Usage:
        from detection_engine import scan_inventory
        from rwc_calculator import score_from_detection

        issues  = scan_inventory(inventory)
        scored  = score_from_detection(issues)
    """
    dicts = []
    for item in issues_raw:
        # Handle both dataclass objects and plain dicts
        if hasattr(item, '__dataclass_fields__'):
            from dataclasses import asdict
            dicts.append(asdict(item))
        else:
            dicts.append(item)
    return score_all(dicts)


# Entry point

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Compute RWC scores for detected issues.')
    parser.add_argument('--file',      default='data/issues.json',
                        help='Path to issues JSON (default: data/issues.json). '
                             'Generate with: python detection_engine.py --save data/issues.json')
    parser.add_argument('--save',      metavar='OUTPUT_FILE',
                        help='Save scored issues JSON to a file')
    parser.add_argument('--top',       type=int, metavar='N',
                        help='Show only the top-N issues by RWC')
    parser.add_argument('--breakdown', metavar='RESOURCE_ID',
                        help='Print detailed score breakdown for a specific resource')
    parser.add_argument('--json',      action='store_true',
                        help='Output scored issues as raw JSON')
    args = parser.parse_args()

    # ── load issues ────────────────────────────────────────────────────────────
    if not os.path.exists(args.file):
        print(f'\n❌  Issues file not found: {args.file}')
        print('    Run first:  python detection_engine.py --save data/issues.json\n')
        raise SystemExit(1)

    with open(args.file) as f:
        raw_issues = json.load(f)

    scored = score_all(raw_issues)

    # ── output ────────────────────────────────────────────────────────────────
    if args.breakdown:
        print_resource_breakdown(scored, args.breakdown)

    elif args.json:
        print(json.dumps([asdict(s) for s in scored], indent=2))

    else:
        print_full_report(scored, top_n=args.top)

    if args.save:
        os.makedirs(os.path.dirname(args.save) if os.path.dirname(args.save) else '.', exist_ok=True)
        with open(args.save, 'w') as f:
            json.dump([asdict(s) for s in scored], f, indent=2)
        print(f'✅  Saved {len(scored)} scored issues → {args.save}')
