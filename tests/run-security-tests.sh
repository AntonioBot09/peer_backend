#!/bin/bash

# Security Test Runner for PeerNetwork Backend
# Run this script to execute all security tests

set -e

echo "🔒 Starting PeerNetwork Backend Security Tests"
echo "=============================================="

# Check if vendor directory exists
if [ ! -d "vendor" ]; then
    echo "❌ Vendor directory not found. Running composer install..."
    composer install --no-dev --optimize-autoloader
fi

# Run PHPUnit security tests
echo ""
echo "🚀 Running Security Test Suite..."
echo ""

../vendor/bin/phpunit --testsuite "Security Tests" --colors=always

echo ""
echo "✅ Security tests completed!"
echo ""
echo "📊 Test Summary:"
echo "   - SQL Injection Tests: Login, Register mutations"
echo "   - XSS Tests: Contactus mutation"
echo "   - Authentication Bypass Tests: JWT, IDOR, missing auth"
echo "   - Error Handling Tests: Malformed requests, special chars"
echo ""
echo "🔍 Next steps:"
echo "   1. Review any failing tests"
echo "   2. Fix vulnerabilities identified"
echo "   3. Run tests again to verify fixes"
echo "   4. Consider adding more test cases for other endpoints"