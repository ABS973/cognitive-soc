import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lambda', 'alert_ingestor'))
import unittest.mock as mock
sys.modules['boto3'] = mock.MagicMock()
import handler

def test_private_ip_filter():
    assert handler.is_private_ip("192.168.1.1") == True
    assert handler.is_private_ip("10.0.0.1")    == True
    assert handler.is_private_ip("172.16.0.1")  == True
    assert handler.is_private_ip("185.220.101.45") == False
    assert handler.is_private_ip("8.8.8.8")     == False
    print("  ✓ Private IP filter working correctly")

if __name__ == "__main__":
    print("\n🔵 Testing is_private_ip...\n")
    try:
        test_private_ip_filter()
        print("\n✅ 1/1 tests passed\n")
    except Exception as e:
        print(f"  ✗ {e}\n❌ 0/1 tests passed\n")
