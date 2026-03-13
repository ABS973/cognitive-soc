"""
Test alert_ingestor offline — no AWS calls needed.
Tests source detection, normalisation, severity gating.
"""
import json, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lambda', 'alert_ingestor'))

# Mock boto3 before importing handler
import unittest.mock as mock
sys.modules['boto3'] = mock.MagicMock()

import handler

def load(path):
    with open(path) as f:
        return json.load(f)

GD  = load("tests/fixtures/guardduty_high_finding.json")
BEH = load("tests/fixtures/behavioral_anomaly_alert.json")

# ── Tests ──────────────────────────────────────────────────────────────────

def test_detect_source_guardduty():
    assert handler.detect_source(GD) == "guardduty"
    print("  ✓ GuardDuty source detected")

def test_detect_source_behavioral():
    assert handler.detect_source(BEH) == "behavioral"
    print("  ✓ Behavioral source detected")

def test_normalise_guardduty():
    f = handler.normalise_guardduty(GD)
    assert f["finding_id"]    == "test-finding-001"
    assert f["entity_id"]     == "ahmed-dev"
    assert f["entity_type"]   == "IAMUser"
    assert f["severity_label"] == "HIGH"
    assert f["severity_score"] == 8.0
    assert f["source"]        == "guardduty"
    print(f"  ✓ GuardDuty normalised: entity={f['entity_id']} severity={f['severity_label']}")

def test_normalise_behavioral():
    f = handler.normalise_behavioral(BEH)
    assert f["entity_id"]         == "ahmed-dev"
    assert f["severity_score"]    == 91.5
    assert f["severity_label"]    == "CRITICAL"
    assert f["source"]            == "behavioral_dna"
    assert f["behavioral_composite"] == 91.5
    print(f"  ✓ Behavioral normalised: score={f['severity_score']} severity={f['severity_label']}")

def test_severity_gate_passes():
    f = handler.normalise_guardduty(GD)
    assert handler.meets_threshold(f) == True
    print("  ✓ Severity gate PASS: HIGH GuardDuty finding crosses threshold")

def test_severity_gate_blocks_low():
    f = handler.normalise_guardduty(GD)
    f["severity_score"] = 3.0
    f["severity_label"] = "LOW"
    assert handler.meets_threshold(f) == False
    print("  ✓ Severity gate BLOCK: LOW finding blocked correctly")

def test_severity_gate_behavioral():
    f = handler.normalise_behavioral(BEH)
    assert handler.meets_threshold(f) == True
    print("  ✓ Severity gate PASS: CRITICAL behavioral alert crosses threshold")

def test_private_ip_filter():
    from handler import is_private_ip; assert is_private_ip("192.168.1.1") == True
    from handler import is_private_ip; assert is_private_ip("10.0.0.1")    == True
    from handler import is_private_ip; assert is_private_ip("185.220.101.45") == False
    print("  ✓ Private IP filter working correctly")

if __name__ == "__main__":
    print("\n🔵 Testing alert_ingestor...\n")
    tests = [
        test_detect_source_guardduty,
        test_detect_source_behavioral,
        test_normalise_guardduty,
        test_normalise_behavioral,
        test_severity_gate_passes,
        test_severity_gate_blocks_low,
        test_severity_gate_behavioral,
        test_private_ip_filter,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{'✅' if passed == len(tests) else '❌'} {passed}/{len(tests)} tests passed\n")
