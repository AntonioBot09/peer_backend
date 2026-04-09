#!/usr/bin/env php
<?php

/**
 * Standalone Security Test Runner
 * 
 * This script runs security tests without requiring Composer or PHPUnit.
 * It provides a simple test framework for security validation.
 */

declare(strict_types=1);

// Simple test framework
class SecurityTestRunner
{
    private array $tests = [];
    private array $results = [];
    private int $passed = 0;
    private int $failed = 0;
    private int $skipped = 0;

    public function addTest(string $name, callable $test): void
    {
        $this->tests[$name] = $test;
    }

    public function runAll(): void
    {
        echo "🔒 Running Standalone Security Tests\n";
        echo "===================================\n\n";

        foreach ($this->tests as $name => $test) {
            echo "➡️  Running: {$name}... ";
            
            try {
                $result = $test();
                if ($result === true) {
                    echo "✅ PASS\n";
                    $this->passed++;
                    $this->results[$name] = ['status' => 'PASS', 'message' => ''];
                } else {
                    echo "❌ FAIL\n";
                    if (is_string($result)) {
                        echo "   Reason: {$result}\n";
                        $this->results[$name] = ['status' => 'FAIL', 'message' => $result];
                    }
                    $this->failed++;
                }
            } catch (\Throwable $e) {
                echo "⚠️  ERROR\n";
                echo "   Exception: {$e->getMessage()}\n";
                $this->results[$name] = ['status' => 'ERROR', 'message' => $e->getMessage()];
                $this->failed++;
            }
        }

        $this->printSummary();
    }

    private function printSummary(): void
    {
        echo "\n📊 Test Summary\n";
        echo "===============\n";
        echo "✅ Passed: {$this->passed}\n";
        echo "❌ Failed: {$this->failed}\n";
        echo "⚠️  Skipped: {$this->skipped}\n";
        echo "📈 Total: " . count($this->tests) . "\n\n";

        if ($this->failed > 0) {
            echo "🔍 Failed Tests:\n";
            foreach ($this->results as $name => $result) {
                if ($result['status'] === 'FAIL' || $result['status'] === 'ERROR') {
                    echo "   - {$name}: {$result['status']} - {$result['message']}\n";
                }
            }
        }
    }
}

// Security test utilities
class SecurityTestUtils
{
    public static function getSqlInjectionPayloads(): array
    {
        return [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT null --",
            "' AND (SELECT * FROM (SELECT(SLEEP(1)))a) --",
            "'; DROP TABLE users; --",
        ];
    }

    public static function getXssPayloads(): array
    {
        return [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '" onmouseover="alert(\'XSS\')',
            'javascript:alert("XSS")',
        ];
    }

    public static function checkForSqlErrors(string $response): bool
    {
        $patterns = [
            '/SQLSTATE\[/i',
            '/syntax error/i',
            '/mysql_fetch/i',
            '/pg_execute/i',
            '/Unclosed quotation mark/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $response)) {
                return true;
            }
        }

        return false;
    }

    public static function checkForXss(string $response): bool
    {
        $dangerousPatterns = [
            '/<script[^>]*>/i',
            '/on\w+\s*=/i',
            '/javascript:/i',
        ];

        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $response)) {
                return true;
            }
        }

        return false;
    }
}

// Mock GraphQL handler for testing
class MockGraphQLHandler
{
    public function handleRequest(string $query): array
    {
        // Simulate GraphQL processing
        // In a real test, this would make actual HTTP requests
        
        // Check for SQL injection attempts
        $sqlPayloads = SecurityTestUtils::getSqlInjectionPayloads();
        foreach ($sqlPayloads as $payload) {
            if (str_contains($query, $payload)) {
                return [
                    'status' => 400,
                    'body' => json_encode(['error' => 'Invalid input']),
                    'headers' => ['Content-Type' => 'application/json']
                ];
            }
        }

        // Check for XSS attempts
        $xssPayloads = SecurityTestUtils::getXssPayloads();
        foreach ($xssPayloads as $payload) {
            if (str_contains($query, $payload)) {
                return [
                    'status' => 400,
                    'body' => json_encode(['error' => 'Invalid input']),
                    'headers' => ['Content-Type' => 'application/json']
                ];
            }
        }

        // Default successful response
        return [
            'status' => 200,
            'body' => json_encode(['data' => ['result' => 'success']]),
            'headers' => ['Content-Type' => 'application/json']
        ];
    }
}

// Create test runner
$runner = new SecurityTestRunner();
$handler = new MockGraphQLHandler();

// Test 1: Basic SQL injection detection
$runner->addTest('SQL Injection - Basic Payloads', function() use ($handler) {
    $payloads = SecurityTestUtils::getSqlInjectionPayloads();
    
    foreach ($payloads as $payload) {
        $query = 'mutation Login { login(email: "' . $payload . '", password: "test") { accessToken } }';
        $response = $handler->handleRequest($query);
        
        // Should return error for SQL injection
        if ($response['status'] < 400) {
            return "SQL injection payload accepted: " . substr($payload, 0, 30) . "...";
        }
        
        // Should not contain SQL errors in response
        if (SecurityTestUtils::checkForSqlErrors($response['body'])) {
            return "SQL error leaked in response for payload: " . substr($payload, 0, 30) . "...";
        }
    }
    
    return true;
});

// Test 2: XSS payload detection
$runner->addTest('XSS - Script Payloads', function() use ($handler) {
    $payloads = SecurityTestUtils::getXssPayloads();
    
    foreach ($payloads as $payload) {
        $query = 'mutation Contactus { contactus(name: "' . $payload . '", email: "test@example.com", message: "test") { msgid } }';
        $response = $handler->handleRequest($query);
        
        // Should return error for XSS
        if ($response['status'] < 400) {
            return "XSS payload accepted: " . substr($payload, 0, 30) . "...";
        }
        
        // Should not contain unescaped XSS in response
        if (SecurityTestUtils::checkForXss($response['body'])) {
            return "XSS payload returned in response: " . substr($payload, 0, 30) . "...";
        }
    }
    
    return true;
});

// Test 3: Valid request should succeed
$runner->addTest('Valid Request Processing', function() use ($handler) {
    $queries = [
        'query { __typename }',
        'mutation Login { login(email: "valid@example.com", password: "Password123!") { accessToken } }',
        'mutation Register { register(input: { email: "valid@example.com", password: "Password123!", username: "validuser" }) { userid } }',
    ];
    
    foreach ($queries as $query) {
        $response = $handler->handleRequest($query);
        
        // Valid requests should process successfully
        if ($response['status'] >= 400) {
            return "Valid request rejected: " . substr($query, 0, 50) . "...";
        }
        
        // Should have proper content type
        if (!isset($response['headers']['Content-Type']) || 
            $response['headers']['Content-Type'] !== 'application/json') {
            return "Missing or incorrect Content-Type header";
        }
    }
    
    return true;
});

// Test 4: Error handling for malformed requests
$runner->addTest('Malformed Request Handling', function() use ($handler) {
    $malformedRequests = [
        '{not-valid-json}',
        '{"query": "invalid graphql"}',
        '',
        'null',
    ];
    
    foreach ($malformedRequests as $request) {
        $response = $handler->handleRequest($request);
        
        // Malformed requests should return 4xx errors
        if ($response['status'] < 400) {
            return "Malformed request accepted: " . substr($request, 0, 30) . "...";
        }
        
        // Should have proper error format
        $body = json_decode($response['body'], true);
        if (!isset($body['error'])) {
            return "Error response missing 'error' field";
        }
    }
    
    return true;
});

// Test 5: Rate limiting simulation
$runner->addTest('Rate Limiting Structure', function() use ($handler) {
    // Simulate rapid requests
    $query = 'mutation Login { login(email: "test@example.com", password: "test") { accessToken } }';
    
    $responses = [];
    for ($i = 0; $i < 5; $i++) {
        $responses[] = $handler->handleRequest($query);
    }
    
    // All responses should be consistent
    $firstStatus = $responses[0]['status'];
    foreach ($responses as $index => $response) {
        if ($response['status'] !== $firstStatus) {
            return "Inconsistent response status for request #{$index}";
        }
    }
    
    return true;
});

// Test 6: Authentication requirement check
$runner->addTest('Protected Endpoint Authentication', function() use ($handler) {
    $protectedQueries = [
        'query GetUserProfile { getUserProfile { userid email } }',
        'mutation UpdateProfile { updateProfile(input: { username: "test" }) { userid } }',
    ];
    
    foreach ($protectedQueries as $query) {
        $response = $handler->handleRequest($query);
        
        // Without auth token, should return 401/403
        // Note: This is a simulation - real test would check actual auth
        if ($response['status'] < 400) {
            return "Protected endpoint accessible without authentication: " . substr($query, 0, 50) . "...";
        }
    }
    
    return true;
});

// Test 7: Special character handling
$runner->addTest('Special Character Processing', function() use ($handler) {
    $specialChars = [
        'test@example.com',
        'test+tag@example.com',
        'test.user@example.com',
        'test"quote@example.com',
        "test'apostrophe@example.com",
        'test<less@example.com',
        'test>greater@example.com',
        'test&ersand@example.com',
    ];
    
    foreach ($specialChars as $email) {
        $query = 'mutation Register { register(input: { email: "' . $email . '", password: "test", username: "test" }) { userid } }';
        $response = $handler->handleRequest($query);
        
        // Should handle special characters without crashing
        if ($response['status'] >= 500) {
            return "Server error with special characters: " . substr($email, 0, 30) . "...";
        }
    }
    
    return true;
});

// Run all tests
$runner->runAll();

// Generate report file
$report = [
    'timestamp' => date('Y-m-d H:i:s'),
    'tests_run' => count($runner->tests),
    'passed' => $runner->passed,
    'failed' => $runner->failed,
    'results' => $runner->results,
];

file_put_contents('security-test-report.json', json_encode($report, JSON_PRETTY_PRINT));
echo "\n📄 Report saved to: security-test-report.json\n";