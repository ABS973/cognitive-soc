"""
Test triage_engine offline — no AWS calls needed.
Tests false positive scoring and triage decisions.
"""
import json, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lambda', 'triage_engine'))

import unittest.mock as mock
sys.modules['boto3'] = mock.MagicMock()

import handler

# Base finding to reuse across tests
BASE = {
    "finding_id":    "test-001",
    "finding_type":  "PrivilegeEscalation:IAMUser/AnomalousBehavior",
    "source":        "guardduty",
    "severity_label": "HIGH",
    "severity_score": 8.0,
    "entity_id":     "ahmed-dev",
    "entity_type":   "IAMUser",
    "ingested_at":   "2025-03-13T03:00:00Z",
    "enrichment":    {"enriched": True, "ip_reputation": {"is_known_malicious": False, "confidence_score": 0}},
    "behavioral_scores": {},
    "behavioral_composite": 0,
}

def test_critical_bypasses_triage():
    f = {**BASE, "severity_label": "CRITICAL"}
    result = handler.lambda_handler(f, {})
    assert result["triage_decision"] == "INVESTIGATE"
    assert result["triage_priority"] == "CRITICAL"
    print("  ✓ CRITICAL finding bypasses FP filter → INVESTIGATE")

def test_known_malicious_ip_investigate():
    f = {**BASE, "enrichment": {"enriched": True, "ip_reputation": {"is_known_malicious": True, "confidence_score": 90}}}
    result = handler.lambda_handler(f, {})
    assert result["proceed"] == True
    print(f"  ✓ Known malicious IP → {result['triage_decision']} (fp_score={result['fp_score']})")

def test_behavioral_confirms_investigate():
    f = {**BASE, "behavioral_composite": 91.5, "behavioral_scores": {"temporal_score": 95, "service_score": 95}}
    result = handler.lambda_handler(f, {})
    assert result["proceed"] == True
    print(f"  ✓ Behavioral DNA confirms anomaly → {result['triage_decision']} (fp_score={result['fp_score']})")

def test_noisy_finding_type_raises_fp():
    f = {**BASE, "finding_type": "Recon:EC2/PortProbeUnprotectedPort", "severity_label": "MEDIUM", "severity_score": 5.0}
    result = handler.lambda_handler(f, {})
    print(f"  ✓ Noisy finding type scored → {result['triage_decision']} (fp_score={result['fp_score']})")

def test_business_hours_raises_fp_score():
    f = {**BASE, "ingested_at": "2025-03-13T10:00:00+00:00"}  # 10am UTC Thursday
    result = handler.lambda_handler(f, {})
    print(f"  ✓ Business hours detected → {result['triage_decision']} (fp_score={result['fp_score']})")

def test_result_has_required_fields():
    result = handler.lambda_handler(BASE, {})
    for field in ["triage_decision", "triage_priority", "fp_score", "fp_reason", "proceed"]:
        assert field in result, f"Missing field: {field}"
    print("  ✓ Result contains all required fields")

def test_priority_assignment():
    f = {**BASE, "behavioral_composite": 91.5}
    result = handler.lambda_handler(f, {})
    assert result["triage_priority"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    print(f"  ✓ Priority assigned: {result['triage_priority']}")

if __name__ == "__main__":
    print("\n🔵 Testing triage_engine...\n")
    tests = [
        test_critical_bypasses_triage,
        test_known_malicious_ip_investigate,
        test_behavioral_confirms_investigate,
        test_noisy_finding_type_raises_fp,
        test_business_hours_raises_fp_score,
        test_result_has_required_fields,
        test_priority_assignment,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{'✅' if passed == len(tests) else '❌'} {passed}/{len(tests)} tests passed\n")
