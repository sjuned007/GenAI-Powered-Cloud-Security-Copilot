"""
Config Manager for CloudGuardian

Loads configuration from config.yaml with sensible defaults.
Supports environment variable overrides.

Usage:
    from core.config import Config
    
    config = Config.load('config.yaml')
    print(config.severity_scores)           # {'critical': 10.0, 'high': 7.0, ...}
    print(config.is_rule_enabled('S3_PUBLIC_BUCKET'))  # True/False
    print(config.priority_band_for_rwc(27))  # 'P1'
"""

from __future__ import annotations

import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List


# ══════════════════════════════════════════════════════════════════════════════
# Configuration Dataclasses
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SeverityConfig:
    """Severity level configurations."""
    scores: Dict[str, float]
    data_sensitivity_multipliers: Dict[str, float]
    pii_tag_boost: float
    issue_type_multipliers: Dict[str, float]

    @classmethod
    def from_dict(cls, data: dict) -> SeverityConfig:
        return cls(
            scores=data.get('scores', {}),
            data_sensitivity_multipliers=data.get('data_sensitivity_multipliers', {}),
            pii_tag_boost=data.get('pii_tag_boost', 1.5),
            issue_type_multipliers=data.get('issue_type_multipliers', {}),
        )


@dataclass
class ScoringConfig:
    """RWC scoring configuration."""
    region_risk_factors: Dict[str, float]
    high_urgency_rules: List[str]
    urgency_boost: float
    cost_dampening: bool

    @classmethod
    def from_dict(cls, data: dict) -> ScoringConfig:
        return cls(
            region_risk_factors=data.get('region_risk_factors', {}),
            high_urgency_rules=data.get('high_urgency_rules', []),
            urgency_boost=data.get('urgency_boost', 1.0),
            cost_dampening=data.get('cost_dampening', True),
        )


@dataclass
class PriorityBandConfig:
    """Configuration for a single priority band (P1, P2, P3, P4)."""
    min_rwc: float
    label: str
    description: str
    sla_hours: int

    @classmethod
    def from_dict(cls, data: dict) -> PriorityBandConfig:
        return cls(
            min_rwc=data.get('min_rwc', 0),
            label=data.get('label', ''),
            description=data.get('description', ''),
            sla_hours=data.get('sla_hours', 0),
        )


@dataclass
class RuleThresholdsConfig:
    """Rule-specific tunable thresholds."""
    data: Dict[str, Any]

    def get(self, rule_id: str, key: str, default: Any = None) -> Any:
        """Get threshold value for a rule."""
        if rule_id in self.data:
            return self.data[rule_id].get(key, default)
        return default

    @classmethod
    def from_dict(cls, data: dict) -> RuleThresholdsConfig:
        return cls(data=data or {})


@dataclass
class DetectionConfig:
    """Detection engine configuration."""
    strict_mode: bool
    sensitive_tags: List[str]
    required_tags: List[str]

    @classmethod
    def from_dict(cls, data: dict) -> DetectionConfig:
        return cls(
            strict_mode=data.get('strict_mode', True),
            sensitive_tags=data.get('sensitive_tags', ['contains_pii']),
            required_tags=data.get('required_tags', ['project', 'environment', 'owner']),
        )


# ══════════════════════════════════════════════════════════════════════════════
# Main Config Class
# ══════════════════════════════════════════════════════════════════════════════

class Config:
    """
    Central configuration manager for CloudGuardian.
    
    Loads from config.yaml and provides typed access to all config values.
    Supports environment variable overrides.
    """

    def __init__(self, raw_config: dict):
        self.raw = raw_config

        # Parse sections
        rules_data = raw_config.get('rules', {})
        self._rules_enabled = self._parse_rules_enabled(rules_data)

        self.severity = SeverityConfig.from_dict(raw_config.get('severity', {}))
        self.scoring = ScoringConfig.from_dict(raw_config.get('scoring', {}))
        self.detection = DetectionConfig.from_dict(raw_config.get('detection', {}))
        self.rule_thresholds = RuleThresholdsConfig.from_dict(
            raw_config.get('rule_thresholds', {})
        )

        # Parse priority bands (P1, P2, P3, P4)
        self.priority_bands: Dict[str, PriorityBandConfig] = {}
        for band_name, band_data in raw_config.get('priority_bands', {}).items():
            self.priority_bands[band_name] = PriorityBandConfig.from_dict(band_data)

    @staticmethod
    def _parse_rules_enabled(rules_data: dict) -> Dict[str, bool]:
        """
        Flatten nested rules structure into a flat dict of rule_id -> enabled.
        
        Input structure:
            rules:
              s3:
                enabled: true
                rules:
                  S3_PUBLIC_BUCKET:
                    enabled: true
                  ...
        
        Output: {'S3_PUBLIC_BUCKET': True, 'S3_NO_ENCRYPTION': True, ...}
        """
        enabled = {}

        for rule_category, category_data in rules_data.items():
            if not isinstance(category_data, dict):
                continue

            # Check if category itself is enabled
            category_enabled = category_data.get('enabled', True)

            # Parse individual rules in this category
            rules_in_category = category_data.get('rules', {})
            for rule_id, rule_data in rules_in_category.items():
                if isinstance(rule_data, dict):
                    rule_enabled = rule_data.get('enabled', True)
                    enabled[rule_id] = category_enabled and rule_enabled
                else:
                    enabled[rule_id] = category_enabled

        return enabled

    @staticmethod
    def load(config_path: str | Path = 'config.yaml') -> Config:
        """
        Load configuration from YAML file.
        
        Args:
            config_path: Path to config.yaml (defaults to 'config.yaml' in cwd)
        
        Returns:
            Config object
        
        Raises:
            FileNotFoundError: If config file not found
            yaml.YAMLError: If YAML is malformed
        """
        config_path = Path(config_path).expanduser().resolve()

        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_path, 'r', encoding='utf-8') as f:
            raw_config = yaml.safe_load(f)

        if raw_config is None:
            raw_config = {}

        return Config(raw_config)

    @staticmethod
    def load_or_default(config_path: str | Path = 'config.yaml') -> Config:
        """
        Load configuration, falling back to defaults if file not found.
        Useful for development/testing.
        """
        try:
            return Config.load(config_path)
        except FileNotFoundError:
            return Config.default()

    @staticmethod
    def default() -> Config:
        """Return a Config with sensible hardcoded defaults."""
        default_config: dict[str, Any] = {
            'severity': {
                'scores': {
                    'critical': 10.0,
                    'high': 7.0,
                    'medium': 4.0,
                    'low': 1.0,
                },
                'data_sensitivity_multipliers': {
                    'high': 2.5,
                    'medium': 1.5,
                    'low': 1.0,
                    'unknown': 1.0,
                },
                'pii_tag_boost': 1.5,
                'issue_type_multipliers': {
                    'misconfiguration': 1.2,
                    'compliance': 1.0,
                    'waste': 0.8,
                },
            },
            'scoring': {
                'region_risk_factors': {
                    'eu-west-1': 0.5,
                    'eu-central-1': 0.5,
                    'ap-south-1': 0.3,
                    'ap-southeast-1': 0.2,
                    'us-east-1': 0.0,
                    'us-west-2': 0.0,
                },
                'high_urgency_rules': [
                    'S3_PUBLIC_BUCKET',
                    'S3_NO_ENCRYPTION',
                    'EBS_UNENCRYPTED',
                    'SG_OPEN_SSH',
                    'SG_OPEN_RDP',
                    'SG_ALLOW_ALL_INBOUND',
                    'COM_HIGH_SENSITIVITY_UNENCRYPTED',
                ],
                'urgency_boost': 1.0,
                'cost_dampening': True,
            },
            'priority_bands': {
                'P1': {'min_rwc': 25, 'label': 'Immediate', 'description': 'Same-day response', 'sla_hours': 2},
                'P2': {'min_rwc': 15, 'label': 'Urgent', 'description': 'Fix within 48 hours', 'sla_hours': 48},
                'P3': {'min_rwc': 7, 'label': 'This Sprint', 'description': 'Address in sprint', 'sla_hours': 168},
                'P4': {'min_rwc': 0, 'label': 'Hygiene', 'description': 'Best-practice', 'sla_hours': 2592000},
            },
            'detection': {
                'strict_mode': True,
                'sensitive_tags': ['contains_pii'],
                'required_tags': ['project', 'environment', 'owner'],
            },
            'rule_thresholds': {},
            'rules': {},
        }
        return Config(default_config)

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check if a specific rule is enabled."""
        return self._rules_enabled.get(rule_id, True)

    def are_rules_enabled(self, rule_ids: List[str]) -> bool:
        """Check if ALL rules in list are enabled."""
        return all(self.is_rule_enabled(rid) for rid in rule_ids)

    def any_rule_enabled(self, rule_ids: List[str]) -> bool:
        """Check if ANY rule in list is enabled."""
        return any(self.is_rule_enabled(rid) for rid in rule_ids)

    @property
    def severity_scores(self) -> Dict[str, float]:
        """Get base severity scores."""
        return self.severity.scores

    @property
    def data_sensitivity_multipliers(self) -> Dict[str, float]:
        """Get sensitivity multiplier table."""
        return self.severity.data_sensitivity_multipliers

    @property
    def issue_type_multipliers(self) -> Dict[str, float]:
        """Get issue type multiplier table."""
        return self.severity.issue_type_multipliers

    @property
    def region_risk_factors(self) -> Dict[str, float]:
        """Get regional risk factor table."""
        return self.scoring.region_risk_factors

    @property
    def high_urgency_rules_set(self) -> set[str]:
        """Get set of high-urgency rule IDs."""
        return set(self.scoring.high_urgency_rules)

    def priority_band_for_rwc(self, rwc: float) -> str:
        """
        Get priority band (P1, P2, P3, P4) for a given RWC score.
        
        Args:
            rwc: Risk-Weighted Cost score
        
        Returns:
            Band name ('P1', 'P2', 'P3', 'P4')
        """
        bands_sorted = sorted(
            self.priority_bands.items(),
            key=lambda x: x[1].min_rwc,
            reverse=True
        )
        for band_name, band_config in bands_sorted:
            if rwc >= band_config.min_rwc:
                return band_name
        return 'P4'

    def get_rule_threshold(self, rule_id: str, threshold_key: str, default: Any = None) -> Any:
        """Get a tunable threshold for a specific rule."""
        return self.rule_thresholds.get(rule_id, threshold_key, default)

    def to_dict(self) -> dict:
        """Export current config as dictionary."""
        return self.raw.copy()


# ══════════════════════════════════════════════════════════════════════════════
# Convenience: Global config instance
# ══════════════════════════════════════════════════════════════════════════════

_global_config: Optional[Config] = None


def init_config(config_path: str | Path = 'config.yaml') -> Config:
    """Initialize global config instance."""
    global _global_config
    _global_config = Config.load_or_default(config_path)
    return _global_config


def get_config() -> Config:
    """Get global config instance (must call init_config first)."""
    global _global_config
    if _global_config is None:
        _global_config = Config.load_or_default()
    return _global_config
