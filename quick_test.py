#!/usr/bin/env python3
"""
Quick Security Test Against Mock Backend
"""

import json
import requests
import time
import subprocess
import sys
import os
from threading import Thread

def start_mock_backend():
    """Start the mock backend in a separate thread"""
    import mock_backend
    
    backend = mock_backend.MockBackend(host='localhost', port=8888)
    backend.start()
    return backend

def run_security_tests():
    """Run security tests against the backend"""
    base_url = "http://localhost:8888"
    results = []
    
    print("🔒 RUNNING ACTUAL SECURITY TESTS")
    print("=" * 40)
    
    # Test 1: Basic GraphQL query
    print("\n1. Testing basic GraphQL query...")
    query = 'query { __typename }'
    response = requests.post(
        f"{base_url}/graphql",
        json={'query': query},
        headers={'Content-Type': 'application/json'},
        timeout=5
    )
    
    results.append({
        'test': 'Basic GraphQL',
        'status': response.status_code,
        'success': response.status_code == 200,
        'response': response.json() if response.content else {}
    })
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.json() if response.content else 'No content'}")
    
    # Test 2: SQL injection attempt
    print("\n2. Testing SQL injection...")
    sql_payload = "' OR '1'='1"
    query = f'''
        mutation Login {{
            login(email: "test{sql_payload}", password: "password123") {{
                meta {{
                    status
                    RequestId
                    ResponseCode
                    ResponseMessage
                }}
                accessToken
                refreshToken
            }}
        }}
    '''
    
    response = requests.post(
        f"{base_url}/graphql",
        json={'query': query},
        headers={'Content-Type': 'application/json'},
        timeout=5
    )
    
    sql_blocked = response.status_code != 200 or 'error' in response.text.lower()
    results.append({
        'test': 'SQL Injection',
        'status': response.status_code,
        'success': sql_blocked,  # Success = SQL injection was blocked
        'blocked': sql_blocked,
        'response': response.text[:200]
    })
    print(f"   Status: {response.status_code}")
    print(f"   Blocked: {'✅ YES' if sql_blocked else '❌ NO'}")
    print(f"   Response: {response.text[:200]}...")
    
    # Test 3: XSS attempt
    print("\n3. Testing XSS...")
    xss_payload = '<script>alert("XSS")</script>'
    query = f'''
        mutation Contactus {{
            contactus(name: "Test User{xss_payload}", email: "test@example.com", message: "Test") {{
                meta {{
                    status
                    RequestId
                    ResponseCode
                    ResponseMessage
                }}
                affectedRows {{
                    msgid
                    email
                    name
                    message
                }}
            }}
        }}
    '''
    
    response = requests.post(
        f"{base_url}/graphql",
        json={'query': query},
        headers={'Content-Type': 'application/json'},
        timeout=5
    )
    
    xss_blocked = response.status_code != 200 or 'error' in response.text.lower()
    results.append({
        'test': 'XSS',
        'status': response.status_code,
        'success': xss_blocked,  # Success = XSS was blocked
        'blocked': xss_blocked,
        'response': response.text[:200]
    })
    print(f"   Status: {response.status_code}")
    print(f"   Blocked: {'✅ YES' if xss_blocked else '❌ NO'}")
    print(f"   Response: {response.text[:200]}...")
    
    # Test 4: Valid login
    print("\n4. Testing valid login...")
    query = '''
        mutation Login {
            login(email: "test@example.com", password: "Password123!") {
                meta {
                    status
                    RequestId
                    ResponseCode
                    ResponseMessage
                }
                accessToken
                refreshToken
            }
        }
    '''
    
    response = requests.post(
        f"{base_url}/graphql",
        json={'query': query},
        headers={'Content-Type': 'application/json'},
        timeout=5
    )
    
    login_success = response.status_code == 200 and 'accessToken' in response.text
    results.append({
        'test': 'Valid Login',
        'status': response.status_code,
        'success': login_success,
        'has_token': 'accessToken' in response.text,
        'response': response.json() if response.content else {}
    })
    print(f"   Status: {response.status_code}")
    print(f"   Success: {'✅ YES' if login_success else '❌ NO'}")
    print(f"   Has token: {'✅ YES' if 'accessToken' in response.text else '❌ NO'}")
    
    # Test 5: Invalid login
    print("\n5. Testing invalid login...")
    query = '''
        mutation Login {
            login(email: "wrong@example.com", password: "wrongpassword") {
                meta {
                    status
                    RequestId
                    ResponseCode
                    ResponseMessage
                }
                accessToken
                refreshToken
            }
        }
    '''
    
    response = requests.post(
        f"{base_url}/graphql",
        json={'query': query},
        headers={'Content-Type': 'application/json'},
        timeout=5
    )
    
    login_failed = response.status_code != 200 or 'error' in response.text.lower() or 'Invalid' in response.text
    results.append({
        'test': 'Invalid Login',
        'status': response.status_code,
        'success': login_failed,  # Success = invalid login was rejected
        'rejected': login_failed,
        'response': response.text[:200]
    })
    print(f"   Status: {response.status_code}")
    print(f"   Rejected: {'✅ YES' if login_failed else '❌ NO'}")
    print(f"   Response: {response.text[:200]}...")
    
    # Test 6: Health check
    print("\n6. Testing health endpoint...")
    response = requests.get(f"{base_url}/health", timeout=5)
    
    results.append({
        'test': 'Health Check',
        'status': response.status_code,
        'success': response.status_code == 200,
        'response': response.json() if response.content else {}
    })
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.json() if response.content else 'No content'}")
    
    return results

def main():
    """Main function"""
    print("🚀 Starting mock backend and running security tests...")
    print()
    
    try:
        # Start mock backend
        backend = start_mock_backend()
        time.sleep(2)  # Give backend time to start
        
        # Run tests
        results = run_security_tests()
        
        # Generate summary
        print("\n" + "=" * 40)
        print("📊 TEST SUMMARY")
        print("=" * 40)
        
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r['success'])
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {total_tests - passed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        print("\n🔍 Detailed Results:")
        for result in results:
            status = "✅ PASS" if result['success'] else "❌ FAIL"
            print(f"  {result['test']}: {status} (HTTP {result['status']})")
        
        # Security assessment
        print("\n🔒 SECURITY ASSESSMENT:")
        
        # Check SQL injection protection
        sql_test = next(r for r in results if r['test'] == 'SQL Injection')
        if sql_test['blocked']:
            print("  ✅ SQL Injection: Protected")
        else:
            print("  ❌ SQL Injection: Vulnerable!")
        
        # Check XSS protection
        xss_test = next(r for r in results if r['test'] == 'XSS')
        if xss_test['blocked']:
            print("  ✅ XSS: Protected")
        else:
            print("  ❌ XSS: Vulnerable!")
        
        # Check authentication
        valid_login = next(r for r in results if r['test'] == 'Valid Login')
        invalid_login = next(r for r in results if r['test'] == 'Invalid Login')
        if valid_login['success'] and invalid_login['rejected']:
            print("  ✅ Authentication: Working correctly")
        else:
            print("  ⚠️  Authentication: Issues detected")
        
        # Save results
        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'tests': results,
            'summary': {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'success_rate': (passed_tests/total_tests)*100,
                'security_assessment': {
                    'sql_injection_protected': sql_test['blocked'],
                    'xss_protected': xss_test['blocked'],
                    'authentication_working': valid_login['success'] and invalid_login['rejected']
                }
            }
        }
        
        with open('actual_test_results.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Results saved to: actual_test_results.json")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        if 'backend' in locals():
            backend.stop()
    
    print("\n✅ Test execution complete!")

if __name__ == '__main__':
    main()