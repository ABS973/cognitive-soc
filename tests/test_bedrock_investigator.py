"""
Test bedrock_investigator — tests JSON parsing and safety rules offline.
The actual Bedrock call is mocked so this runs without AWS credentials.
"""
import json, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lambda', 'bedrock_investigator'))

import unittest.mock as mock
sys.modules['boto3'] = mock.MagicMock()

import handler

VALID_REPORT = {
    "triage_decision":       "CONFIRMED_THREAT",
    "confidence_score":      92,
    "severity":              "HIGH",
    "executive_summary":     "IAM user ahmed-dev performed privilege escalation at 3am from a known malicious IP.",
    "what_happened":         "The user attached an admin policy to their own account at 03:15 UTC.",
    "attack_timeline":       [{"time": "03:15 UTC", "action": "AttachUserPolicy", "significance": "Self-escalation to admin"}],
    "affected_resources":    [{"resource": "arn:aws:iam::123:user/ahmed-dev", "risk": "Full admin access", "action_taken": "none"}],
    "mitre_chain":           [{"tactic": "Privilege Escalation", "technique": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts", "evidence": "AttachUserPolicy API call"}],
    "behavioral_evidence":   [{"dimension": "temporal", "anomaly": "Activity at 03:00 UTC — never seen before", "score": 95}],
    "ioc_findings":          [{"ioc": "185.220.101.45", "reputation": "malicious", "confidence": 87, "detail": "Tor exit node"}],
    "recommended_actions":   [{"priority": "IMMEDIATE", "action": "Revoke IAM credentials", "rationale": "Confirmed compromise", "soar_playbook": "iam_revoker"}],
    "false_positive_indicators": [],
    "investigation_notes":   "High confidence — multiple corroborating indicators.",
    "requires_human_review": False,
    "auto_response_safe":    True,
}

def test_parse_valid_report():
    result = handler.parse_and_validate(json.dumps(VALID_REPORT), 1)
    assert result is not None
    assert result["triage_decision"] == "CONFIRMED_THREAT"
    print("  ✓ Valid JSON report parsed successfully")

def test_parse_with_markdown_fences():
    raw = f"```json\n{json.dumps(VALID_REPORT)}\n```"
    result = handler.parse_and_validate(raw, 1)
    assert result is not None
    print("  ✓ Markdown code fences stripped correctly")

def test_reject_invalid_json():
    result = handler.parse_and_validate("this is not json at all", 1)
    assert result is None
    print("  ✓ Invalid JSON rejected correctly")

def test_reject_missing_fields():
    incomplete = {"triage_decision": "CONFIRMED_THREAT"}
    result = handler.parse_and_validate(json.dumps(incomplete), 1)
    assert result is None
    print("  ✓ Incomplete report (missing required fields) rejected")

def test_auto_response_safety_override_low_confidence():
    report = {**VALID_REPORT, "confidence_score": 70, "auto_response_safe": True}
    result = handler.enforce_auto_response_rules(report)
    assert result["auto_response_safe"] == False
    print("  ✓ auto_response_safe overridden to False when confidence < 85")

def test_auto_response_safety_override_not_confirmed():
    report = {**VALID_REPORT, "triage_decision": "PROBABLE_THREAT", "auto_response_safe": True}
    result = handler.enforce_auto_response_rules(report)
    assert result["auto_response_safe"] == False
    print("  ✓ auto_response_safe overridden to False when not CONFIRMED_THREAT")

def test_auto_response_safe_when_conditions_met():
    report = {**VALID_REPORT, "triage_decision": "CONFIRMED_THREAT", "confidence_score": 92, "auto_response_safe": True}
    result = handler.enforce_auto_response_rules(report)
    assert result["auto_response_safe"] == True
    print("  ✓ auto_response_safe remains True when all conditions met")

def test_fallback_report_structure():
    event = {"finding_id": "test-001", "entity_id": "ahmed-dev", "severity_label": "HIGH", "finding_type": "test"}
    report = handler.build_fallback_report(event, "Bedrock timeout")
    assert report["requires_human_review"] == True
    assert report["auto_response_safe"]    == False
    assert report["triage_decision"]       == "PROBABLE_THREAT"
    print("  ✓ Fallback report is safe: requires_human_review=True, auto_response_safe=False")

def test_request_builder():
    event = {
        "finding_id": "test-001", "finding_type": "PrivilegeEscalation:IAMUser/AnomalousBehavior",
        "severity_label": "HIGH", "entity_id": "ahmed-dev", "entity_type": "IAMUser",
        "title": "Test", "description": "Test", "account_id": "123", "region": "us-east-1",
        "created_at": "2025-03-13T09:00:00Z", "source": "guardduty",
        "behavioral_baseline": {}, "behavioral_scores": {}, "behavioral_composite": 0,
        "cloudtrail_events": [], "ioc_enrichment": {}, "enrichment": {}, "peer_comparison": {}, "entity_history": {}
    }
    req = handler.build_investigation_request(event)
    parsed = json.loads(req)
    assert "alert" in parsed
    assert "investigation_instructions" in parsed
    print("  ✓ Investigation request built and is valid JSON")

if __name__ == "__main__":
    print("\n🔵 Testing bedrock_investigator (offline — Bedrock mocked)...\n")
    tests = [
        test_parse_valid_report,
        test_parse_with_markdown_fences,
        test_reject_invalid_json,
        test_reject_missing_fields,
        test_auto_response_safety_override_low_confidence,
        test_auto_response_safety_override_not_confirmed,
        test_auto_response_safe_when_conditions_met,
        test_fallback_report_structure,
        test_request_builder,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{'✅' if passed == len(tests) else '❌'} {passed}/{len(tests)} tests passed\n")
