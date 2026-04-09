#!/usr/bin/env php
<?php

/**
 * Concurrency and Rate Limiting Simulation Tests
 * 
 * Simulates concurrent requests and rate limiting scenarios
 * without requiring actual parallel request execution.
 */

declare(strict_types=1);

class ConcurrencySimulator
{
    private array $results = [];
    
    public function simulateConcurrentRequests(string $endpoint, int $concurrentRequests = 10): array
    {
        echo "🔄 Simulating {$concurrentRequests} concurrent requests to: {$endpoint}\n";
        
        $results = [];
        $startTime = microtime(true);
        
        // Simulate concurrent requests
        for ($i = 0; $i < $concurrentRequests; $i++) {
            $requestId = "req_" . ($i + 1);
            
            // Simulate request processing
            $result = $this->simulateSingleRequest($endpoint, $requestId);
            
            $results[$requestId] = [
                'success' => $result['success'],
                'response_time' => $result['response_time'],
                'status_code' => $result['status_code'],
                'rate_limited' => $result['rate_limited'],
                'timestamp' => microtime(true),
            ];
            
            // Small delay to simulate network latency variation
            usleep(rand(1000, 5000)); // 1-5ms
        }
        
        $totalTime = microtime(true) - $startTime;
        
        return [
            'endpoint' => $endpoint,
            'concurrent_requests' => $concurrentRequests,
            'total_time_seconds' => round($totalTime, 3),
            'requests_per_second' => round($concurrentRequests / $totalTime, 2),
            'successful_requests' => count(array_filter($results, fn($r) => $r['success'])),
            'rate_limited_requests' => count(array_filter($results, fn($r) => $r['rate_limited'])),
            'average_response_time' => round(array_sum(array_column($results, 'response_time')) / count($results), 3),
            'detailed_results' => $results,
        ];
    }
    
    private function simulateSingleRequest(string $endpoint, string $requestId): array
    {
        // Simulate different scenarios based on endpoint and request ID
        
        // Rate limiting simulation: reject some requests if too many
        static $requestCounts = [];
        if (!isset($requestCounts[$endpoint])) {
            $requestCounts[$endpoint] = 0;
        }
        $requestCounts[$endpoint]++;
        
        $rateLimited = false;
        $statusCode = 200;
        
        // Simulate rate limiting for certain endpoints
        if (str_contains($endpoint, 'login') || str_contains($endpoint, 'register')) {
            // Simulate rate limiting after 5 requests per minute
            if ($requestCounts[$endpoint] > 5) {
                $rateLimited = true;
                $statusCode = 429; // Too Many Requests
            }
        }
        
        // Simulate response time (50-200ms for normal, longer if rate limited)
        $responseTime = $rateLimited ? 
            rand(100, 300) / 1000 : // 100-300ms for rate limited
            rand(50, 200) / 1000;   // 50-200ms for normal
        
        usleep((int)($responseTime * 1000000)); // Simulate processing time
        
        return [
            'success' => !$rateLimited,
            'response_time' => $responseTime,
            'status_code' => $statusCode,
            'rate_limited' => $rateLimited,
        ];
    }
    
    public function simulateRateLimitWindow(string $endpoint, int $windowSeconds = 60, int $requestsPerWindow = 10): array
    {
        echo "⏱️  Simulating rate limit window: {$requestsPerWindow} requests per {$windowSeconds} seconds for: {$endpoint}\n";
        
        $results = [];
        $requestTimestamps = [];
        
        // Simulate requests over time
        for ($i = 0; $i < $requestsPerWindow * 2; $i++) { // Try to exceed limit
            $requestTime = $i * ($windowSeconds / $requestsPerWindow / 2); // Spread requests
            
            // Simulate request at this time
            usleep((int)($requestTime * 1000000));
            
            $currentTime = microtime(true);
            
            // Remove timestamps outside window
            $requestTimestamps = array_filter(
                $requestTimestamps,
                fn($ts) => ($currentTime - $ts) <= $windowSeconds
            );
            
            // Check if rate limited
            $rateLimited = count($requestTimestamps) >= $requestsPerWindow;
            
            if (!$rateLimited) {
                $requestTimestamps[] = $currentTime;
            }
            
            $results[] = [
                'request_number' => $i + 1,
                'timestamp' => $currentTime,
                'rate_limited' => $rateLimited,
                'requests_in_window' => count($requestTimestamps),
            ];
        }
        
        return [
            'endpoint' => $endpoint,
            'window_seconds' => $windowSeconds,
            'limit_per_window' => $requestsPerWindow,
            'total_requests_sent' => count($results),
            'rate_limited_requests' => count(array_filter($results, fn($r) => $r['rate_limited'])),
            'successful_requests' => count(array_filter($results, fn($r) => !$r['rate_limited'])),
            'window_analysis' => $results,
        ];
    }
    
    public function simulateDistributedAttack(string $endpoint, int $attackers = 5, int $requestsPerAttacker = 20): array
    {
        echo "👥 Simulating distributed attack: {$attackers} attackers, {$requestsPerAttacker} requests each to: {$endpoint}\n";
        
        $results = [];
        $attackerResults = [];
        
        for ($attacker = 0; $attacker < $attackers; $attacker++) {
            $attackerId = "attacker_" . ($attacker + 1);
            $attackerIp = "192.168.1." . (100 + $attacker);
            
            echo "   Attacker {$attackerId} ({$attackerIp}) sending requests...\n";
            
            $attackerRequests = [];
            for ($i = 0; $i < $requestsPerAttacker; $i++) {
                // Simulate request with different IP
                $result = $this->simulateSingleRequest($endpoint, "{$attackerId}_req_{$i}");
                
                // Add attacker-specific info
                $result['attacker_id'] = $attackerId;
                $result['attacker_ip'] = $attackerIp;
                $result['request_number'] = $i + 1;
                
                $attackerRequests[] = $result;
                
                // Random delay between requests
                usleep(rand(10000, 50000)); // 10-50ms
            }
            
            $attackerResults[$attackerId] = [
                'ip_address' => $attackerIp,
                'total_requests' => $requestsPerAttacker,
                'successful_requests' => count(array_filter($attackerRequests, fn($r) => $r['success'])),
                'rate_limited_requests' => count(array_filter($attackerRequests, fn($r) => $r['rate_limited'])),
                'average_response_time' => round(array_sum(array_column($attackerRequests, 'response_time')) / count($attackerRequests), 3),
            ];
            
            $results = array_merge($results, $attackerRequests);
        }
        
        return [
            'endpoint' => $endpoint,
            'attackers' => $attackers,
            'requests_per_attacker' => $requestsPerAttacker,
            'total_requests' => count($results),
            'successful_requests' => count(array_filter($results, fn($r) => $r['success'])),
            'rate_limited_requests' => count(array_filter($results, fn($r) => $r['rate_limited'])),
            'attackers_summary' => $attackerResults,
            'overall_success_rate' => round(count(array_filter($results, fn($r) => $r['success'])) / count($results) * 100, 1) . '%',
        ];
    }
    
    public function generateReport(array $simulations): void
    {
        echo "\n📊 CONCURRENCY TEST REPORT\n";
        echo "=========================\n\n";
        
        foreach ($simulations as $name => $simulation) {
            echo "🔹 {$name}:\n";
            
            if (isset($simulation['concurrent_requests'])) {
                // Concurrent requests simulation
                echo "   Concurrent Requests: {$simulation['concurrent_requests']}\n";
                echo "   Successful: {$simulation['successful_requests']}\n";
                echo "   Rate Limited: {$simulation['rate_limited_requests']}\n";
                echo "   Avg Response Time: {$simulation['average_response_time']}s\n";
                echo "   Requests/sec: {$simulation['requests_per_second']}\n";
            } elseif (isset($simulation['attackers'])) {
                // Distributed attack simulation
                echo "   Attackers: {$simulation['attackers']}\n";
                echo "   Total Requests: {$simulation['total_requests']}\n";
                echo "   Success Rate: {$simulation['overall_success_rate']}\n";
                echo "   Rate Limited: {$simulation['rate_limited_requests']}\n";
                
                echo "   Per Attacker:\n";
                foreach ($simulation['attackers_summary'] as $attackerId => $stats) {
                    echo "     - {$attackerId} ({$stats['ip_address']}): ";
                    echo "{$stats['successful_requests']}/{$stats['total_requests']} successful, ";
                    echo "avg {$stats['average_response_time']}s\n";
                }
            } elseif (isset($simulation['window_seconds'])) {
                // Rate limit window simulation
                echo "   Window: {$simulation['window_seconds']}s\n";
                echo "   Limit: {$simulation['limit_per_window']} requests\n";
                echo "   Sent: {$simulation['total_requests_sent']}\n";
                echo "   Successful: {$simulation['successful_requests']}\n";
                echo "   Rate Limited: {$simulation['rate_limited_requests']}\n";
            }
            
            echo "\n";
        }
        
        // Save detailed report
        $report = [
            'timestamp' => date('Y-m-d H:i:s'),
            'simulations' => $simulations,
            'summary' => [
                'total_simulations' => count($simulations),
                'endpoints_tested' => array_unique(array_column($simulations, 'endpoint')),
            ],
        ];
        
        file_put_contents('concurrency-test-report.json', json_encode($report, JSON_PRETTY_PRINT));
        echo "📄 Detailed report saved to: concurrency-test-report.json\n";
    }
}

// Run simulations
$simulator = new ConcurrencySimulator();

echo "🚀 Starting Concurrency and Rate Limiting Simulations\n";
echo "===================================================\n\n";

$simulations = [];

// 1. Concurrent login attempts
$simulations['Concurrent Login Attempts'] = $simulator->simulateConcurrentRequests(
    '/graphql (login)',
    15
);

// 2. Rate limit window for registration
$simulations['Registration Rate Limit Window'] = $simulator->simulateRateLimitWindow(
    '/graphql (register)',
    60, // 60-second window
    5   // 5 requests per window
);

// 3. Distributed attack on login
$simulations['Distributed Login Attack'] = $simulator->simulateDistributedAttack(
    '/graphql (login)',
    3,  // 3 attackers
    10  // 10 requests each
);

// 4. Concurrent public API requests (should have higher limits)
$simulations['Concurrent Public Requests'] = $simulator->simulateConcurrentRequests(
    '/graphql (public)',
    30
);

// Generate report
$simulator->generateReport($simulations);

// Recommendations
echo "\n💡 RECOMMENDATIONS\n";
echo "================\n";
echo "1. Implement IP-based rate limiting for authentication endpoints\n";
echo "2. Use token bucket algorithm for precise rate limiting\n";
echo "3. Consider user-based rate limiting in addition to IP-based\n";
echo "4. Implement exponential backoff for clients\n";
echo "5. Add rate limit headers to responses (X-RateLimit-*)\n";
echo "6. Monitor for distributed attacks across multiple IPs\n";
echo "7. Consider CAPTCHA for suspicious traffic patterns\n";
echo "8. Implement request queuing for high-load scenarios\n";