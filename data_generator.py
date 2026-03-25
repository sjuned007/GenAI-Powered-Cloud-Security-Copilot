
import json
import random
import os
from datetime import datetime, timedelta

# ── Reproducibility ────────────────────────────────────────────────────────────
random.seed(42)

# ── Constants ──────────────────────────────────────────────────────────────────
REGIONS        = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-south-1', 'ap-southeast-1']
PROJECTS       = ['alpha', 'beta', 'gamma', 'delta', None]
ENVIRONMENTS   = ['production', 'staging', 'development', None]
OWNERS         = ['team-infra', 'team-data', 'team-backend', 'team-ml', None]
SENSITIVITY    = ['low', 'medium', 'high', None]

ENCRYPTION_TYPES   = ['AES256', 'aws:kms', None]
VOLUME_TYPES       = ['gp2', 'gp3', 'io1', 'st1', 'sc1']
STORAGE_CLASSES    = ['STANDARD', 'STANDARD_IA', 'INTELLIGENT_TIERING', 'GLACIER']
SG_PROTOCOLS       = ['tcp', 'udp', '-1']   # -1 = all traffic
RISKY_PORTS        = [22, 3389, 5432, 3306, 6379, 27017]   # SSH, RDP, PG, MySQL, Redis, Mongo
SAFE_CIDRS         = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
OPEN_CIDR          = '0.0.0.0/0'
OPEN_CIDR_V6       = '::/0'


# ── Helpers ────────────────────────────────────────────────────────────────────

def random_date(days_back: int = 365) -> str:
    """Return an ISO-8601 date string within the last `days_back` days."""
    offset = random.randint(0, days_back)
    return (datetime.utcnow() - timedelta(days=offset)).strftime('%Y-%m-%dT%H:%M:%SZ')


def base_tags(guaranteed_project: str | None = None) -> dict:
    """Return a realistic tag dict; sometimes omit cost-allocation tags (bad practice)."""
    project = guaranteed_project or random.choice(PROJECTS)
    tags: dict = {}
    if project:
        tags['project'] = project
    if random.random() > 0.25:                   # 75 % have environment tag
        tags['environment'] = random.choice(ENVIRONMENTS[:-1])
    if random.random() > 0.35:                   # 65 % have owner tag
        tags['owner'] = random.choice(OWNERS[:-1])
    if random.random() > 0.40:
        tags['data_sensitivity'] = random.choice(SENSITIVITY[:-1])
    return tags


def resource_id(prefix: str, index: int) -> str:
    return f'{prefix}-{index:04d}'


# ── S3 Bucket generator ────────────────────────────────────────────────────────

def make_s3_bucket(index: int, force_issue: str | None = None) -> dict:
    """
    force_issue options:
      'public_with_pii'  – public bucket that also stores PII  (worst case)
      'public'           – public bucket, no PII flag
      'pii_private'      – private bucket with PII
      None               – random
    """
    tags = base_tags()

    is_public       = random.random() < 0.15          # 15 % public by default
    has_pii         = random.random() < 0.25          # 25 % contain PII by default
    versioning      = random.choice([True, False])
    encryption      = random.choice(ENCRYPTION_TYPES)
    logging_enabled = random.random() > 0.4

    if force_issue == 'public_with_pii':
        is_public = True
        has_pii   = True
    elif force_issue == 'public':
        is_public = True
        has_pii   = False
    elif force_issue == 'pii_private':
        is_public = False
        has_pii   = True

    if has_pii:
        tags['contains_pii'] = 'true'

    bucket_name = f"bucket-{['logs','data','assets','backups','archive','reports'][index % 6]}-{index:04d}"

    return {
        'id'              : resource_id('s3', index),
        'name'            : bucket_name,
        'type'            : 's3_bucket',
        'region'          : random.choice(REGIONS),
        'monthly_cost'    : round(random.uniform(2, 300), 2),
        'created_at'      : random_date(730),
        'tags'            : tags,

        # ── security fields ──
        'is_public'               : is_public,
        'public_access_block'     : not is_public,      # blocked when private
        'acl'                     : 'public-read' if is_public else 'private',
        'encryption'              : encryption,          # None = unencrypted (finding!)
        'versioning_enabled'      : versioning,
        'mfa_delete_enabled'      : versioning and random.random() > 0.6,
        'logging_enabled'         : logging_enabled,
        'ssl_requests_only'       : random.random() > 0.3,

        # ── cost / sizing fields ──
        'size_gb'                 : round(random.uniform(0.1, 50_000), 1),
        'object_count'            : random.randint(1, 5_000_000),
        'storage_class'           : random.choice(STORAGE_CLASSES),
        'last_accessed_days_ago'  : random.randint(0, 400),  # >90 = idle candidate
    }


# ── EBS Volume generator ───────────────────────────────────────────────────────

def make_ebs_volume(index: int, force_issue: str | None = None) -> dict:
    """
    force_issue options:
      'unattached'        – volume with no instance attached (wasted cost)
      'unencrypted'       – attached but unencrypted
      None                – random
    """
    tags = base_tags()

    attached_to = random.choice(
        [None, None, f'i-{random.randint(10000,99999):05d}']   # ~33 % unattached
    )
    encrypted   = random.random() > 0.3    # 70 % encrypted by default
    volume_type = random.choice(VOLUME_TYPES)

    if force_issue == 'unattached':
        attached_to = None
    elif force_issue == 'unencrypted':
        encrypted   = False
        attached_to = f'i-{random.randint(10000,99999):05d}'

    iops = None
    if volume_type in ('io1', 'gp3'):
        iops = random.choice([3000, 6000, 10000, 16000])

    return {
        'id'            : resource_id('vol', index),
        'type'          : 'ebs_volume',
        'region'        : random.choice(REGIONS),
        'monthly_cost'  : round(random.uniform(5, 200), 2),
        'created_at'    : random_date(730),
        'tags'          : tags,

        # ── attachment / cost fields ──
        'attached_to'        : attached_to,           # None = unattached = cost finding
        'state'              : 'in-use' if attached_to else 'available',
        'last_attached_days_ago' : None if attached_to else random.randint(0, 365),

        # ── volume spec ──
        'volume_type'        : volume_type,
        'size_gb'            : random.choice([8, 20, 50, 100, 200, 500, 1000]),
        'iops'               : iops,
        'throughput_mbps'    : 125 if volume_type == 'gp3' else None,

        # ── security fields ──
        'encrypted'          : encrypted,             # False = security finding
        'kms_key_id'         : f'arn:aws:kms:{random.choice(REGIONS)}:123456789012:key/mrk-{random.randint(1000,9999)}' if encrypted else None,
        'snapshot_id'        : f'snap-{random.randint(10000,99999):05d}' if random.random() > 0.5 else None,

        # ── multi-attach / delete on termination ──
        'multi_attach_enabled'      : volume_type == 'io1' and random.random() > 0.8,
        'delete_on_termination'     : bool(attached_to) and random.random() > 0.3,
    }


# ── Security Group generator ───────────────────────────────────────────────────

def make_inbound_rule(force_open: bool = False) -> dict:
    port       = random.choice(RISKY_PORTS + [80, 443, 8080, 8443])
    from_port  = port
    to_port    = port
    protocol   = 'tcp' if port != -1 else '-1'
    cidr       = OPEN_CIDR if force_open else random.choice(SAFE_CIDRS + [OPEN_CIDR])
    cidr_v6    = OPEN_CIDR_V6 if force_open and random.random() > 0.5 else None

    return {
        'from_port' : from_port,
        'to_port'   : to_port,
        'protocol'  : protocol,
        'cidr_ipv4' : cidr,
        'cidr_ipv6' : cidr_v6,
        'description': f'Allow port {port}' if random.random() > 0.4 else None,
    }


def make_security_group(index: int, force_issue: str | None = None) -> dict:
    """
    force_issue options:
      'open_ssh'          – inbound SSH (22) open to 0.0.0.0/0
      'open_rdp'          – inbound RDP (3389) open to 0.0.0.0/0
      'open_all_traffic'  – inbound rule with protocol=-1 and 0.0.0.0/0
      None                – random
    """
    tags = base_tags()

    num_inbound  = random.randint(1, 5)
    num_outbound = random.randint(1, 3)

    inbound_rules = [make_inbound_rule(force_open=False) for _ in range(num_inbound)]

    if force_issue == 'open_ssh':
        inbound_rules.append({'from_port': 22, 'to_port': 22, 'protocol': 'tcp',
                               'cidr_ipv4': OPEN_CIDR, 'cidr_ipv6': OPEN_CIDR_V6,
                               'description': 'SSH access'})
    elif force_issue == 'open_rdp':
        inbound_rules.append({'from_port': 3389, 'to_port': 3389, 'protocol': 'tcp',
                               'cidr_ipv4': OPEN_CIDR, 'cidr_ipv6': None,
                               'description': 'RDP access'})
    elif force_issue == 'open_all_traffic':
        inbound_rules.append({'from_port': -1, 'to_port': -1, 'protocol': '-1',
                               'cidr_ipv4': OPEN_CIDR, 'cidr_ipv6': OPEN_CIDR_V6,
                               'description': None})

    outbound_rules = [
        {'from_port': 0, 'to_port': 65535, 'protocol': '-1',
         'cidr_ipv4': OPEN_CIDR, 'cidr_ipv6': OPEN_CIDR_V6,
         'description': 'Allow all outbound'}
    ]

    # Flag derived fields — your detection engine can use these directly
    has_open_ssh  = any(r['from_port'] == 22  and r['cidr_ipv4'] == OPEN_CIDR for r in inbound_rules)
    has_open_rdp  = any(r['from_port'] == 3389 and r['cidr_ipv4'] == OPEN_CIDR for r in inbound_rules)
    has_all_open  = any(r['protocol'] == '-1'  and r['cidr_ipv4'] == OPEN_CIDR for r in inbound_rules)
    attached_to   = [f'i-{random.randint(10000,99999):05d}' for _ in range(random.randint(0, 4))]

    return {
        'id'             : resource_id('sg', index),
        'name'           : f'sg-{"default" if index % 20 == 0 else f"custom-{index:04d}"}',
        'type'           : 'security_group',
        'region'         : random.choice(REGIONS),
        'monthly_cost'   : 0.0,     # SGs are free; cost impact is indirect
        'created_at'     : random_date(730),
        'tags'           : tags,
        'vpc_id'         : f'vpc-{random.randint(10000,99999):05d}',
        'description'    : random.choice(['default VPC security group',
                                          'web tier', 'app tier', 'db tier',
                                          'bastion host', 'internal services']),

        # ── rules ──
        'inbound_rules'  : inbound_rules,
        'outbound_rules' : outbound_rules,

        # ── derived security flags ──
        'has_open_ssh'   : has_open_ssh,
        'has_open_rdp'   : has_open_rdp,
        'allows_all_traffic_inbound': has_all_open,

        # ── cost / orphan detection ──
        'attached_to_instances': attached_to,
        'is_unused'            : len(attached_to) == 0,   # orphaned SG = cost hygiene
    }


# ── Orchestrator ───────────────────────────────────────────────────────────────

def generate_resources(n: int = 100) -> list[dict]:
    resources = []
    idx = 0

    # ── GUARANTEED ISSUE CASES (so detection rules always have something to catch) ──
    guaranteed = [
        # S3
        ('s3',  'public_with_pii'),   # public bucket + PII tag  → critical finding
        ('s3',  'public'),            # public bucket, no PII    → high finding
        ('s3',  'pii_private'),       # private + PII            → medium finding
        # EBS
        ('ebs', 'unattached'),        # unattached volume        → cost finding
        ('ebs', 'unattached'),        # second unattached volume
        ('ebs', 'unencrypted'),       # attached, unencrypted    → security finding
        # SG
        ('sg',  'open_ssh'),          # SSH open to world        → critical finding
        ('sg',  'open_rdp'),          # RDP open to world        → critical finding
        ('sg',  'open_all_traffic'),  # all traffic inbound      → critical finding
    ]

    for rtype, issue in guaranteed:
        if rtype == 's3':
            resources.append(make_s3_bucket(idx, force_issue=issue))
        elif rtype == 'ebs':
            resources.append(make_ebs_volume(idx, force_issue=issue))
        elif rtype == 'sg':
            resources.append(make_security_group(idx, force_issue=issue))
        idx += 1

    # ── RANDOM RESOURCES to fill up to n ──────────────────────────────────────
    makers = {
        's3_bucket'     : make_s3_bucket,
        'ebs_volume'    : make_ebs_volume,
        'security_group': make_security_group,
    }
    type_weights = ['s3_bucket'] * 35 + ['ebs_volume'] * 35 + ['security_group'] * 30

    while len(resources) < n:
        rtype  = random.choice(type_weights)
        maker  = makers[rtype]
        resources.append(maker(idx))
        idx += 1

    random.shuffle(resources)
    return resources


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    os.makedirs('data', exist_ok=True)
    output_path = 'data/sample_inventory.json'

    data = generate_resources(100)
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)

    # ── Summary stats ─────────────────────────────────────────────────────────
    counts = {}
    findings = {
        'public_s3_buckets'        : 0,
        'pii_buckets'              : 0,
        'public_s3_with_pii'       : 0,
        'unattached_ebs'           : 0,
        'unencrypted_ebs'          : 0,
        'sg_open_ssh'              : 0,
        'sg_open_rdp'              : 0,
        'sg_open_all_traffic'      : 0,
        'missing_project_tag'      : 0,
    }

    for r in data:
        counts[r['type']] = counts.get(r['type'], 0) + 1

        if r['type'] == 's3_bucket':
            if r['is_public']:
                findings['public_s3_buckets'] += 1
            if r['tags'].get('contains_pii') == 'true':
                findings['pii_buckets'] += 1
            if r['is_public'] and r['tags'].get('contains_pii') == 'true':
                findings['public_s3_with_pii'] += 1

        elif r['type'] == 'ebs_volume':
            if not r['attached_to']:
                findings['unattached_ebs'] += 1
            if not r['encrypted']:
                findings['unencrypted_ebs'] += 1

        elif r['type'] == 'security_group':
            if r['has_open_ssh']:
                findings['sg_open_ssh'] += 1
            if r['has_open_rdp']:
                findings['sg_open_rdp'] += 1
            if r['allows_all_traffic_inbound']:
                findings['sg_open_all_traffic'] += 1

        if 'project' not in r['tags']:
            findings['missing_project_tag'] += 1

    print(f"\n✅  Generated {len(data)} resources → {output_path}\n")
    print("Resource breakdown:")
    for rtype, count in sorted(counts.items()):
        print(f"  {rtype:<20} {count}")
    print("\nDetection rule coverage:")
    for finding, count in findings.items():
        status = '✅' if count > 0 else '❌'
        print(f"  {status}  {finding:<35} {count} resource(s)")
