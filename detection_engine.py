
from __future__ import annotations

import json
import argparse
from dataclasses import dataclass, asdict, field
from typing import Optional

from core.config import get_config
from core.validation import validate_resource


# Issue dataclass  –  the single canonical structure for every finding

@dataclass
class Issue:
    resource_id     : str
    resource_type   : str
    issue_type      : str           # 'misconfiguration' | 'waste' | 'compliance'
    severity        : str           # 'critical' | 'high' | 'medium' | 'low'
    rule_id         : str           # short machine-readable key, e.g. 'S3_PUBLIC_PII'
    description     : str
    remediation     : str
    waste_cost      : float = 0.0   # monthly $ wasted; 0 if not a cost issue
    data_sensitivity: Optional[str] = None   # from tags, if present
    region          : Optional[str] = None
    extra           : dict = field(default_factory=dict)   # rule-specific context


# Helpers

OPEN_CIDR    = '0.0.0.0/0'
OPEN_CIDR_V6 = '::/0'

# Ports that are dangerous when open to the world
SENSITIVE_PORTS: dict[int, str] = {
    22   : 'SSH',
    23   : 'Telnet',
    3389 : 'RDP',
    5432 : 'PostgreSQL',
    3306 : 'MySQL/MariaDB',
    1433 : 'MSSQL',
    6379 : 'Redis',
    27017: 'MongoDB',
    9200 : 'Elasticsearch',
    2375 : 'Docker daemon',
}


def _sensitivity(res: dict) -> Optional[str]:
    """Pull data_sensitivity tag from any resource."""
    return res.get('tags', {}).get('data_sensitivity')


def _has_pii(res: dict) -> bool:
    return res.get('tags', {}).get('contains_pii') == 'true'


def _rule(res: dict,
          rule_id: str,
          issue_type: str,
          severity: str,
          description: str,
          remediation: str,
          waste_cost: float = 0.0,
          extra: dict | None = None) -> Issue:
    """Convenience factory – assembles an Issue from a resource + rule fields."""
    return Issue(
        resource_id      = res['id'],
        resource_type    = res['type'],
        issue_type       = issue_type,
        severity         = severity,
        rule_id          = rule_id,
        description      = description,
        remediation      = remediation,
        waste_cost       = round(waste_cost, 2),
        data_sensitivity = _sensitivity(res),
        region           = res.get('region'),
        extra            = extra or {},
    )


def _is_open_cidr(cidr: str | None) -> bool:
    return cidr in (OPEN_CIDR, OPEN_CIDR_V6)


# S3 Bucket rules

def check_s3_bucket(res: dict) -> list[Issue]:
    issues: list[Issue] = []
    cost = res.get('monthly_cost', 0)
    cfg = get_config()

    # ── S3-01  Public bucket ──────────────────────────────────────────────────
    if res.get('is_public'):
        has_pii  = _has_pii(res)
        severity = 'critical' if has_pii else 'high'
        issues.append(_rule(
            res,
            rule_id     = 'S3_PUBLIC_BUCKET',
            issue_type  = 'misconfiguration',
            severity    = severity,
            description = (
                f'S3 bucket "{res.get("name", res["id"])}" is publicly accessible'
                + (' and contains PII data' if has_pii else '')
            ),
            remediation = (
                'Enable "Block all public access" in the S3 console, '
                'set bucket ACL to private, and review bucket policies. '
                + ('Immediately audit data exposure given PII flag.' if has_pii else '')
            ),
            extra = {
                'acl'            : res.get('acl'),
                'public_access_block': res.get('public_access_block'),
                'contains_pii'   : has_pii,
            }
        ))

    # ── S3-02  Unencrypted bucket ─────────────────────────────────────────────
    if res.get('encryption') is None:
        issues.append(_rule(
            res,
            rule_id     = 'S3_NO_ENCRYPTION',
            issue_type  = 'misconfiguration',
            severity    = 'high' if _has_pii(res) else 'medium',
            description = f'S3 bucket "{res.get("name", res["id"])}" has no server-side encryption',
            remediation = (
                'Enable SSE-S3 (AES256) as a minimum, or SSE-KMS for stricter '
                'key management. Apply a bucket policy to deny unencrypted uploads.'
            ),
            extra = {'encryption': None}
        ))

    # ── S3-03  Access logging disabled ───────────────────────────────────────
    if not res.get('logging_enabled', True):
        issues.append(_rule(
            res,
            rule_id     = 'S3_LOGGING_DISABLED',
            issue_type  = 'compliance',
            severity    = 'low',
            description = f'S3 bucket "{res.get("name", res["id"])}" has access logging disabled',
            remediation = (
                'Enable S3 server access logging to a dedicated log bucket. '
                'Logs are required for audit trails and incident investigation.'
            ),
        ))

    # ── S3-04  Versioning disabled ────────────────────────────────────────────
    if not res.get('versioning_enabled', True):
        issues.append(_rule(
            res,
            rule_id     = 'S3_VERSIONING_DISABLED',
            issue_type  = 'compliance',
            severity    = 'low',
            description = f'S3 bucket "{res.get("name", res["id"])}" does not have versioning enabled',
            remediation = (
                'Enable versioning to protect against accidental deletion and overwrites. '
                'Consider enabling MFA Delete for sensitive buckets.'
            ),
        ))

    # ── S3-05  Idle / stale bucket (cost) ────────────────────────────────────
    idle_days = res.get('last_accessed_days_ago', 0)
    idle_days_threshold = cfg.get_rule_threshold('S3_IDLE_BUCKET', 'idle_days_threshold', 90)
    if idle_days > idle_days_threshold:
        # Estimate cost saving based on storage class
        storage_class = res.get('storage_class', 'STANDARD')
        suggested_class = 'GLACIER' if idle_days > 180 else 'STANDARD_IA'
        issues.append(_rule(
            res,
            rule_id     = 'S3_IDLE_BUCKET',
            issue_type  = 'waste',
            severity    = 'low',
            description = (
                f'S3 bucket "{res.get("name", res["id"])}" has not been accessed '
                f'in {idle_days} days (current class: {storage_class})'
            ),
            remediation = (
                f'Move objects to {suggested_class} storage class via a Lifecycle rule '
                'to reduce storage costs. Consider archiving or deleting if no longer needed.'
            ),
            waste_cost = round(cost * 0.4, 2),   # estimate ~40 % savings from tiering
            extra = {
                'last_accessed_days_ago': idle_days,
                'current_storage_class' : storage_class,
                'suggested_storage_class': suggested_class,
            }
        ))

    # ── S3-06  SSL / HTTPS not enforced ──────────────────────────────────────
    if not res.get('ssl_requests_only', True):
        issues.append(_rule(
            res,
            rule_id     = 'S3_NO_SSL_ENFORCEMENT',
            issue_type  = 'misconfiguration',
            severity    = 'medium',
            description = f'S3 bucket "{res.get("name", res["id"])}" does not enforce HTTPS-only access',
            remediation = (
                'Add a bucket policy with a Deny condition on '
                '"aws:SecureTransport": "false" to block unencrypted HTTP requests.'
            ),
        ))

    return issues

# EBS Volume rules

def check_ebs_volume(res: dict) -> list[Issue]:
    issues: list[Issue] = []
    cost = res.get('monthly_cost', 0)
    cfg = get_config()

    # ── EBS-01  Unattached volume (waste) ─────────────────────────────────────
    if res.get('attached_to') is None:
        idle_days = res.get('last_attached_days_ago')
        idle_days_high_severity = cfg.get_rule_threshold('EBS_UNATTACHED', 'idle_days_high_severity', 30)
        severity  = 'high' if (idle_days or 0) > idle_days_high_severity else 'medium'
        issues.append(_rule(
            res,
            rule_id     = 'EBS_UNATTACHED',
            issue_type  = 'waste',
            severity    = severity,
            description = (
                f'EBS volume {res["id"]} ({res.get("size_gb")} GB {res.get("volume_type")}) '
                f'is unattached'
                + (f' for {idle_days} days' if idle_days else '')
            ),
            remediation = (
                'Create a snapshot for backup, then delete the volume. '
                'If still needed, attach it to an instance or use EBS Snapshot Archive.'
            ),
            waste_cost = cost,
            extra = {
                'size_gb'              : res.get('size_gb'),
                'volume_type'          : res.get('volume_type'),
                'last_attached_days_ago': idle_days,
            }
        ))

    # ── EBS-02  Unencrypted volume ────────────────────────────────────────────
    if not res.get('encrypted', True):
        issues.append(_rule(
            res,
            rule_id     = 'EBS_UNENCRYPTED',
            issue_type  = 'misconfiguration',
            severity    = 'high',
            description = f'EBS volume {res["id"]} is not encrypted at rest',
            remediation = (
                'Create an encrypted snapshot of this volume and restore it as a new '
                'encrypted volume. Enable account-level EBS encryption by default to '
                'prevent future unencrypted volumes.'
            ),
            extra = {'encrypted': False, 'kms_key_id': None}
        ))

    # ── EBS-03  No snapshot (no backup) ──────────────────────────────────────
    if res.get('snapshot_id') is None and res.get('attached_to') is not None:
        issues.append(_rule(
            res,
            rule_id     = 'EBS_NO_SNAPSHOT',
            issue_type  = 'compliance',
            severity    = 'medium',
            description = f'EBS volume {res["id"]} has no associated snapshot / backup',
            remediation = (
                'Create a snapshot immediately and set up an AWS Backup plan or '
                'Data Lifecycle Manager (DLM) policy for automated daily snapshots.'
            ),
        ))

    # ── EBS-04  gp2 volume (should upgrade to gp3) ───────────────────────────
    if res.get('volume_type') == 'gp2':
        size_gb   = res.get('size_gb', 0)
        gp2_cost  = size_gb * 0.10   # $0.10/GB/month for gp2
        gp3_cost  = size_gb * 0.08   # $0.08/GB/month for gp3
        savings   = round(gp2_cost - gp3_cost, 2)
        issues.append(_rule(
            res,
            rule_id     = 'EBS_GP2_UPGRADE',
            issue_type  = 'waste',
            severity    = 'low',
            description = (
                f'EBS volume {res["id"]} uses gp2 type; gp3 offers 20 % cost savings '
                f'and better baseline performance (est. saving: ${savings}/mo)'
            ),
            remediation = (
                'Modify the volume type from gp2 to gp3 directly in the console '
                '(no downtime required). gp3 provides 3000 IOPS baseline at lower cost.'
            ),
            waste_cost = savings,
            extra = {
                'current_type'   : 'gp2',
                'recommended_type': 'gp3',
                'estimated_monthly_savings': savings,
            }
        ))

    # ── EBS-05  Oversized volume (> 500 GB and unattached) ───────────────────
    size_gb = res.get('size_gb', 0)
    oversized_threshold = cfg.get_rule_threshold('EBS_OVERSIZED_UNATTACHED', 'size_gb_threshold', 500)
    if size_gb > oversized_threshold and res.get('attached_to') is None:
        issues.append(_rule(
            res,
            rule_id     = 'EBS_OVERSIZED_UNATTACHED',
            issue_type  = 'waste',
            severity    = 'high',
            description = (
                f'EBS volume {res["id"]} is oversized ({size_gb} GB) and unattached — '
                'significant wasted spend'
            ),
            remediation = (
                'Review whether the full capacity is required. '
                'Snapshot and delete, or right-size before re-attaching.'
            ),
            waste_cost = cost,
            extra = {'size_gb': size_gb}
        ))

    return issues

# Security Group rules

def _rule_open_port(res: dict, rule: dict, port: int, service: str) -> Issue:
    """Helper: generate a finding for a specific open sensitive port."""
    return _rule(
        res,
        rule_id     = f'SG_OPEN_{service.replace("/","_").upper()}',
        issue_type  = 'misconfiguration',
        severity    = 'critical',
        description = (
            f'Security group {res["id"]} ({res.get("name")}) allows inbound '
            f'{service} (port {port}) from {rule.get("cidr_ipv4", "")}'
            + (f' / {rule["cidr_ipv6"]}' if rule.get('cidr_ipv6') else '')
        ),
        remediation = (
            f'Restrict port {port} ({service}) to specific trusted IP ranges. '
            f'Use a bastion host or VPN rather than direct public access. '
            f'Apply least-privilege inbound rules.'
        ),
        extra = {
            'port'     : port,
            'service'  : service,
            'cidr_ipv4': rule.get('cidr_ipv4'),
            'cidr_ipv6': rule.get('cidr_ipv6'),
        }
    )


def check_security_group(res: dict) -> list[Issue]:
    issues: list[Issue] = []
    cfg = get_config()

    inbound = res.get('inbound_rules', [])

    # ── SG-01  Any sensitive port open to the world ───────────────────────────
    seen_open_ports: set[int] = set()
    for rule in inbound:
        from_port = rule.get('from_port', -1)
        to_port   = rule.get('to_port',   -1)
        cidr4     = rule.get('cidr_ipv4')
        cidr6     = rule.get('cidr_ipv6')

        if not (_is_open_cidr(cidr4) or _is_open_cidr(cidr6)):
            continue

        # Check every sensitive port in range [from_port, to_port]
        for port, service in SENSITIVE_PORTS.items():
            if from_port <= port <= to_port and port not in seen_open_ports:
                seen_open_ports.add(port)
                issues.append(_rule_open_port(res, rule, port, service))

    # ── SG-02  All-traffic inbound (protocol = -1, 0.0.0.0/0) ───────────────
    for rule in inbound:
        if (rule.get('protocol') == '-1'
                and (_is_open_cidr(rule.get('cidr_ipv4'))
                     or _is_open_cidr(rule.get('cidr_ipv6')))):
            issues.append(_rule(
                res,
                rule_id     = 'SG_ALLOW_ALL_INBOUND',
                issue_type  = 'misconfiguration',
                severity    = 'critical',
                description = (
                    f'Security group {res["id"]} ({res.get("name")}) allows ALL '
                    f'inbound traffic from the internet (protocol=-1, 0.0.0.0/0)'
                ),
                remediation = (
                    'Remove the catch-all inbound rule immediately. '
                    'Replace with explicit, minimal rules for each required port/service.'
                ),
                extra = {'rule': rule}
            ))
            break   # one finding is enough; avoid duplicates

    # ── SG-03  Wide port range open to internet (e.g., 0-65535) ─────────────
    for rule in inbound:
        from_p = rule.get('from_port', 0)
        to_p   = rule.get('to_port',   0)
        wide_port_threshold = cfg.get_rule_threshold('SG_WIDE_PORT_RANGE', 'port_range_threshold', 1000)
        if (to_p - from_p) > wide_port_threshold and (_is_open_cidr(rule.get('cidr_ipv4'))
                                         or _is_open_cidr(rule.get('cidr_ipv6'))):
            issues.append(_rule(
                res,
                rule_id     = 'SG_WIDE_PORT_RANGE',
                issue_type  = 'misconfiguration',
                severity    = 'high',
                description = (
                    f'Security group {res["id"]} has a very wide inbound port range '
                    f'({from_p}–{to_p}) open to the internet'
                ),
                remediation = (
                    'Replace wide port ranges with specific ports required by your '
                    'application. Audit each open port and remove unnecessary ones.'
                ),
                extra = {'from_port': from_p, 'to_port': to_p}
            ))

    # ── SG-04  Unused / orphaned security group ───────────────────────────────
    if res.get('is_unused', False):
        issues.append(_rule(
            res,
            rule_id     = 'SG_UNUSED',
            issue_type  = 'waste',
            severity    = 'low',
            description = (
                f'Security group {res["id"]} ({res.get("name")}) is not attached '
                f'to any instance'
            ),
            remediation = (
                'Delete unused security groups to reduce attack surface and keep '
                'the environment clean. Use AWS Config rule '
                '"vpc-sg-open-only-to-authorized-ports" for ongoing compliance.'
            ),
            extra = {'attached_to_instances': []}
        ))

    # ── SG-05  Missing description on rules ───────────────────────────────────
    undocumented = [r for r in inbound if not r.get('description')]
    if len(undocumented) >= 2:
        issues.append(_rule(
            res,
            rule_id     = 'SG_UNDOCUMENTED_RULES',
            issue_type  = 'compliance',
            severity    = 'low',
            description = (
                f'Security group {res["id"]} has {len(undocumented)} inbound rules '
                f'with no description — hard to audit'
            ),
            remediation = (
                'Add clear descriptions to every security group rule so that '
                'reviewers can understand the intent without guessing.'
            ),
            extra = {'undocumented_rule_count': len(undocumented)}
        ))

    # ── SG-06  Default security group in use ─────────────────────────────────
    if 'default' in res.get('name', '').lower() and res.get('attached_to_instances'):
        issues.append(_rule(
            res,
            rule_id     = 'SG_DEFAULT_IN_USE',
            issue_type  = 'compliance',
            severity    = 'medium',
            description = (
                f'Default security group {res["id"]} is actively used '
                f'by {len(res["attached_to_instances"])} instance(s)'
            ),
            remediation = (
                'AWS best practice: default security groups should have no rules and '
                'never be assigned to resources. Create purpose-built security groups instead.'
            ),
            extra = {'instance_count': len(res.get('attached_to_instances', []))}
        ))

    return issues


# Cross-resource / compliance rules

def check_common(res: dict) -> list[Issue]:
    """Rules that apply to every resource type."""
    issues: list[Issue] = []
    tags = res.get('tags', {})

    # ── COM-01  Missing cost-allocation tag ───────────────────────────────────
    missing_tags = [t for t in ('project', 'environment', 'owner') if t not in tags]
    if missing_tags:
        issues.append(_rule(
            res,
            rule_id     = 'COM_MISSING_TAGS',
            issue_type  = 'compliance',
            severity    = 'low',
            description = (
                f'{res["type"]} {res["id"]} is missing required tags: '
                f'{", ".join(missing_tags)}'
            ),
            remediation = (
                'Apply required tags: project, environment, owner. '
                'Use AWS Config rule "required-tags" or Tag Policies in AWS Organizations '
                'to enforce tagging going forward.'
            ),
            extra = {'missing_tags': missing_tags}
        ))

    # ── COM-02  High-sensitivity resource with no encryption flag ─────────────
    sensitivity = tags.get('data_sensitivity')
    if sensitivity == 'high' and res['type'] == 's3_bucket' and res.get('encryption') is None:
        issues.append(_rule(
            res,
            rule_id     = 'COM_HIGH_SENSITIVITY_UNENCRYPTED',
            issue_type  = 'misconfiguration',
            severity    = 'critical',
            description = (
                f'{res["type"]} {res["id"]} is tagged as high-sensitivity '
                f'but has no encryption configured'
            ),
            remediation = (
                'Immediately enable SSE-KMS encryption. Review access policies '
                'and audit who has accessed this resource.'
            ),
            extra = {'data_sensitivity': sensitivity}
        ))

    return issues


# Main scan orchestrator

CHECKERS = {
    's3_bucket'     : check_s3_bucket,
    'ebs_volume'    : check_ebs_volume,
    'security_group': check_security_group,
}


def scan_inventory(data: list[dict]) -> list[Issue]:
    """
    Scan all resources and return a flat list of Issues, sorted by severity.
    """
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    all_issues: list[Issue] = []
    cfg = get_config()

    for idx, res in enumerate(data, start=1):
        is_valid, errors = validate_resource(res)
        if not is_valid:
            resource_hint = res.get('id', f'index={idx}') if isinstance(res, dict) else f'index={idx}'
            print(f'⚠️  Skipping invalid resource ({resource_hint}): ' + '; '.join(errors))
            continue

        rtype = res.get('type', '')

        # Type-specific rules
        checker = CHECKERS.get(rtype)
        if checker:
            all_issues.extend(i for i in checker(res) if cfg.is_rule_enabled(i.rule_id))

        # Cross-resource compliance rules (apply to all types)
        all_issues.extend(i for i in check_common(res) if cfg.is_rule_enabled(i.rule_id))

    all_issues.sort(key=lambda i: severity_order.get(i.severity, 99))
    return all_issues


# Reporting helpers

def print_summary(issues: list[Issue]) -> None:
    """Print a human-readable summary table to stdout."""
    from collections import Counter

    sev_counts  = Counter(i.severity   for i in issues)
    type_counts = Counter(i.issue_type for i in issues)
    rule_counts = Counter(i.rule_id    for i in issues)
    total_waste = sum(i.waste_cost for i in issues)

    SEV_ICONS = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}

    print('\n' + '═' * 60)
    print('  CLOUD RESOURCE SCAN RESULTS')
    print('═' * 60)
    print(f'  Total issues found : {len(issues)}')
    print(f'  Estimated waste    : ${total_waste:,.2f} / month')
    print()

    print('  By severity:')
    for sev in ('critical', 'high', 'medium', 'low'):
        count = sev_counts.get(sev, 0)
        icon  = SEV_ICONS[sev]
        bar   = '█' * count
        print(f'    {icon}  {sev:<10}  {count:>4}  {bar}')

    print()
    print('  By issue type:')
    for itype, count in type_counts.most_common():
        print(f'    • {itype:<20}  {count}')

    print()
    print('  Top triggered rules:')
    for rule_id, count in rule_counts.most_common(8):
        print(f'    {count:>4}×  {rule_id}')

    print()
    print('  Critical & High issues:')
    print('  ' + '─' * 56)
    for issue in issues:
        if issue.severity in ('critical', 'high'):
            icon = SEV_ICONS[issue.severity]
            cost = f'  💸 ${issue.waste_cost}/mo' if issue.waste_cost else ''
            print(f'  {icon}  [{issue.rule_id}] {issue.resource_id}{cost}')
            print(f'       {issue.description}')
            print(f'       → {issue.remediation[:90]}...' if len(issue.remediation) > 90
                  else f'       → {issue.remediation}')
            print()

    print('═' * 60 + '\n')


# Entry point

if __name__ == '__main__':
    import os

    parser = argparse.ArgumentParser(description='Scan cloud resource inventory for issues.')
    parser.add_argument('--file', default='data/sample_inventory.json',
                        help='Path to inventory JSON (default: data/sample_inventory.json)')
    parser.add_argument('--json', action='store_true',
                        help='Output issues as JSON instead of summary table')
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'],
                        help='Filter output to a specific severity level')
    parser.add_argument('--save', metavar='OUTPUT_FILE',
                        help='Save issues JSON to a file')
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f'❌  Inventory file not found: {args.file}')
        print('    Run data_generator.py first to create it.')
        raise SystemExit(1)

    with open(args.file) as f:
        inventory = json.load(f)

    issues = scan_inventory(inventory)

    if args.severity:
        issues = [i for i in issues if i.severity == args.severity]

    if args.json or args.save:
        output = json.dumps([asdict(i) for i in issues], indent=2)
        if args.save:
            os.makedirs(os.path.dirname(args.save) if os.path.dirname(args.save) else '.', exist_ok=True)
            with open(args.save, 'w') as f:
                f.write(output)
            print(f'✅  Saved {len(issues)} issues → {args.save}')
        if args.json:
            print(output)
    else:
        print_summary(issues)
