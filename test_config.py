"""Quick test of config loader - verify it loads correctly."""

from pathlib import Path
from core.config import Config

# Test 1: Load from file
try:
    config = Config.load('config.yaml')
    print("✅ Config loaded successfully")
    print(f"   - Severity scores: {config.severity_scores}")
    print(f"   - S3_PUBLIC_BUCKET enabled: {config.is_rule_enabled('S3_PUBLIC_BUCKET')}")
    print(f"   - Priority band for RWC=30: {config.priority_band_for_rwc(30)}")
    print(f"   - Priority band for RWC=20: {config.priority_band_for_rwc(20)}")
    print(f"   - Priority band for RWC=8: {config.priority_band_for_rwc(8)}")
    print(f"   - Priority band for RWC=2: {config.priority_band_for_rwc(2)}")
except Exception as e:
    print(f"❌ Error loading config: {e}")

# Test 2: Default config
try:
    default_config = Config.default()
    print("\n✅ Default config created successfully")
    print(f"   - Severity scores: {default_config.severity_scores}")
except Exception as e:
    print(f"❌ Error creating default config: {e}")

print("\n✨ Config loader is working!")
