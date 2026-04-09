#!/bin/bash

# CI/CD Security Test Runner for PeerNetwork
# This script is designed to run in CI/CD pipelines

set -e  # Exit on error

echo "🔒 Starting CI/CD Security Tests"
echo "================================="
echo "Timestamp: $(date)"
echo "Branch: ${GIT_BRANCH:-$(git branch --show-current)}"
echo "Commit: $(git rev-parse --short HEAD)"
echo ""

# Configuration
SECURITY_THRESHOLD=80
REQUIRED_TESTS=("sql_injection" "xss" "authentication")
FAIL_ON_CRITICAL=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    if [ "$1" = "success" ]; then
        echo -e "${GREEN}✅ $2${NC}"
    elif [ "$1" = "warning" ]; then
        echo -e "${YELLOW}⚠️  $2${NC}"
    elif [ "$1" = "error" ]; then
        echo -e "${RED}❌ $2${NC}"
    else
        echo "📝 $2"
    fi
}

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    print_status "error" "Python 3 is required but not installed"
    exit 1
fi

# Check if we're in the backend directory
if [ ! -f "tests/security_test_suite.py" ]; then
    if [ -f "../tests/security_test_suite.py" ]; then
        cd ..
    else
        print_status "error" "Please run from backend directory"
        exit 1
    fi
fi

# Run security tests
print_status "info" "Running security test suite..."
python3 tests/security_test_suite.py

# Check if report was generated
if [ ! -f "security-test-report.json" ]; then
    print_status "error" "Security test report not generated"
    exit 1
fi

# Parse results
print_status "info" "Analyzing test results..."

SECURITY_SCORE=$(python3 -c "
import json
with open('security-test-report.json') as f:
    data = json.load(f)
    print(data['summary']['security_score'])
")

TOTAL_VULNS=$(python3 -c "
import json
with open('security-test-report.json') as f:
    data = json.load(f)
    print(data['summary']['total_vulnerabilities'])
")

CRITICAL_VULNS=$(python3 -c "
import json
with open('security-test-report.json') as f:
    data = json.load(f)
    print(data['summary']['critical_vulnerabilities'])
")

HIGH_VULNS=$(python3 -c "
import json
with open('security-test-report.json') as f:
    data = json.load(f)
    print(data['summary']['high_vulnerabilities'])
")

# Display summary
echo ""
echo "📊 SECURITY TEST SUMMARY"
echo "========================"
echo "Security Score: $SECURITY_SCORE/100"
echo "Total Vulnerabilities: $TOTAL_VULNS"
echo "Critical: $CRITICAL_VULNS"
echo "High: $HIGH_VULNS"
echo ""

# Check thresholds
PASS=true

if [ "$SECURITY_SCORE" -lt "$SECURITY_THRESHOLD" ]; then
    print_status "error" "Security score $SECURITY_SCORE is below threshold of $SECURITY_THRESHOLD"
    PASS=false
else
    print_status "success" "Security score meets threshold ($SECURITY_SCORE >= $SECURITY_THRESHOLD)"
fi

if [ "$CRITICAL_VULNS" -gt 0 ] && [ "$FAIL_ON_CRITICAL" = "true" ]; then
    print_status "error" "Critical vulnerabilities found: $CRITICAL_VULNS"
    PASS=false
elif [ "$CRITICAL_VULNS" -gt 0 ]; then
    print_status "warning" "Critical vulnerabilities found: $CRITICAL_VULNS (not failing pipeline)"
else
    print_status "success" "No critical vulnerabilities found"
fi

# Generate JUnit XML for CI/CD integration
print_status "info" "Generating JUnit XML report..."
python3 -c "
import json
import xml.etree.ElementTree as ET
from datetime import datetime

with open('security-test-report.json') as f:
    data = json.load(f)

# Create testsuite element
testsuite = ET.Element('testsuite')
testsuite.set('name', 'Security Tests')
testsuite.set('tests', str(data['summary']['total_tests']))
testsuite.set('failures', str(data['summary']['total_vulnerabilities']))
testsuite.set('timestamp', datetime.now().isoformat())

# Add test cases
for test in data['test_results']:
    testcase = ET.SubElement(testsuite, 'testcase')
    testcase.set('name', test['test'])
    testcase.set('classname', 'SecurityTestSuite')
    
    if test.get('findings', 0) > 0:
        failure = ET.SubElement(testcase, 'failure')
        failure.set('message', f\"Found {test['findings']} vulnerabilities\")
        failure.text = str(test.get('details', []))

# Write XML file
tree = ET.ElementTree(testsuite)
tree.write('security-test-results.xml', encoding='utf-8', xml_declaration=True)
"

print_status "success" "JUnit report generated: security-test-results.xml"

# Generate markdown summary
cat > SECURITY_SUMMARY.md << EOF
# Security Test Results

**Date:** $(date)
**Branch:** ${GIT_BRANCH:-$(git branch --show-current)}
**Commit:** $(git rev-parse --short HEAD)

## Summary
- **Security Score:** $SECURITY_SCORE/100
- **Total Vulnerabilities:** $TOTAL_VULNS
- **Critical Vulnerabilities:** $CRITICAL_VULNS
- **High Vulnerabilities:** $HIGH_VULNS

## Status: $(if $PASS; then echo "✅ PASS"; else echo "❌ FAIL"; fi)

## Next Steps
$(if [ "$CRITICAL_VULNS" -gt 0 ]; then
  echo "1. Address critical vulnerabilities immediately"
  echo "2. Review security-test-report.json for details"
elif [ "$HIGH_VULNS" -gt 0 ]; then
  echo "1. Address high-severity vulnerabilities"
  echo "2. Schedule security improvements"
else
  echo "1. Continue regular security testing"
  echo "2. Consider expanding test coverage"
fi)

## Reports Generated
- security-test-report.json (detailed)
- executive-security-summary.json (high-level)
- security-test-results.xml (JUnit format)
- SECURITY_SUMMARY.md (this file)
EOF

print_status "success" "Markdown summary generated: SECURITY_SUMMARY.md"

# Final decision
echo ""
if [ "$PASS" = true ]; then
    print_status "success" "✅ SECURITY TESTS PASSED"
    echo "All security checks passed. Pipeline can continue."
    exit 0
else
    print_status "error" "❌ SECURITY TESTS FAILED"
    echo "Security checks failed. Pipeline should be blocked."
    echo ""
    echo "Review the following files for details:"
    echo "  - security-test-report.json"
    echo "  - SECURITY_SUMMARY.md"
    exit 1
fi