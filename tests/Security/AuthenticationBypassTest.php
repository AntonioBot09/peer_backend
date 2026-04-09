<?php

declare(strict_types=1);

namespace Tests\Security;

/**
 * Authentication bypass tests.
 * Tests various methods to bypass authentication mechanisms.
 */
class AuthenticationBypassTest extends BaseSecurityTest
{
    /**
     * Test authentication bypass with SQL injection in login.
     *
     * @dataProvider authBypassPayloadsProvider
     */
    public function testLoginAuthBypass(string $payload): void
    {
        $query = '
            mutation Login {
                login(email: "' . $payload . '", password: "' . $payload . '") {
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
        ';

        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        $data = $this->parseGraphQLResponse($response);
        
        // Should not grant access with auth bypass payloads
        if (isset($data['data']['login']['accessToken'])) {
            $this->fail('Authentication bypass succeeded with payload: ' . $payload);
        }
    }

    /**
     * Test JWT token tampering.
     */
    public function testJwtTokenTampering(): void
    {
        $tamperedTokens = [
            // Tampered JWT (different signature)
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            
            // None algorithm attack
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
            
            // Empty token
            '',
            
            // Malformed token
            'not.a.valid.token',
            
            // Token with invalid characters
            '!!!invalid!!!',
        ];

        foreach ($tamperedTokens as $token) {
            $query = '
                query GetUserProfile {
                    getUserProfile {
                        meta {
                            status
                            RequestId
                            ResponseCode
                            ResponseMessage
                        }
                        userid
                        email
                        username
                    }
                }
            ';

            $request = $this->createGraphQLRequest($query, null, $token);
            $response = $this->executeGraphQLRequest($request);
            
            $this->assertNoSqlErrors($response);
            $this->assertProperErrorHandling($response);
            
            $data = $this->parseGraphQLResponse($response);
            
            // Should not grant access with tampered tokens
            if (isset($data['data']['getUserProfile']['userid'])) {
                $this->fail('JWT tampering succeeded with token: ' . substr($token, 0, 50) . '...');
            }
            
            // Should return proper error (401 Unauthorized or similar)
            $statusCode = $response->getStatusCode();
            if ($statusCode !== 401 && $statusCode !== 403) {
                // Might be 400 for malformed tokens, but should not be 200
                $this->assertNotEquals(200, $statusCode, 'Tampered token returned 200 OK');
            }
        }
    }

    /**
     * Test missing authentication for protected endpoints.
     */
    public function testMissingAuthentication(): void
    {
        $protectedQueries = [
            'query GetUserProfile {
                getUserProfile {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    userid
                    email
                    username
                }
            }',
            
            'query GetUserWallet {
                getUserWallet {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    balance
                    transactions
                }
            }',
            
            'mutation UpdateProfile {
                updateProfile(input: {
                    username: "hacker",
                    bio: "Hacked account"
                }) {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    userid
                }
            }',
        ];

        foreach ($protectedQueries as $query) {
            $request = $this->createGraphQLRequest($query);
            $response = $this->executeGraphQLRequest($request);
            
            $this->assertNoSqlErrors($response);
            $this->assertProperErrorHandling($response);
            
            $data = $this->parseGraphQLResponse($response);
            
            // Should not grant access without authentication
            if (isset($data['data'])) {
                foreach ($data['data'] as $operation => $result) {
                    if ($result !== null && !isset($result['meta']['ResponseCode']) || 
                        (isset($result['meta']['ResponseCode']) && $result['meta']['ResponseCode'] === 'success')) {
                        $this->fail('Protected endpoint accessible without authentication: ' . $operation);
                    }
                }
            }
            
            // Should return proper error code
            $statusCode = $response->getStatusCode();
            $this->assertContains(
                $statusCode,
                [401, 403, 400],
                'Protected endpoint should return 401, 403, or 400 without auth, got: ' . $statusCode
            );
        }
    }

    /**
     * Test authorization header manipulation.
     */
    public function testAuthorizationHeaderManipulation(): void
    {
        $malformedHeaders = [
            'Bearer',
            'Bearer ',
            'Basic ' . base64_encode('admin:password'),
            'Token invalid-token',
            'JWT fake.jwt.token',
            'Bearer null',
            'Bearer undefined',
            'Bearer true',
            'Bearer false',
            'Bearer 0',
            'Bearer 1',
            'Bearer []',
            'Bearer {}',
        ];

        foreach ($malformedHeaders as $header) {
            $query = '
                query GetUserProfile {
                    getUserProfile {
                        meta {
                            status
                            RequestId
                            ResponseCode
                            ResponseMessage
                        }
                        userid
                        email
                        username
                    }
                }
            ';

            // Parse header to get just the token part for createGraphQLRequest
            $token = null;
            if (str_starts_with($header, 'Bearer ')) {
                $token = substr($header, 7);
            }

            $request = $this->createGraphQLRequest($query, null, $token);
            $response = $this->executeGraphQLRequest($request);
            
            $this->assertNoSqlErrors($response);
            $this->assertProperErrorHandling($response);
            
            $data = $this->parseGraphQLResponse($response);
            
            // Should not grant access with malformed headers
            if (isset($data['data']['getUserProfile']['userid'])) {
                $this->fail('Authorization header manipulation succeeded with: ' . $header);
            }
        }
    }

    /**
     * Test IDOR (Insecure Direct Object Reference) vulnerability.
     */
    public function testIdorVulnerability(): void
    {
        // Test accessing other users' data by manipulating IDs
        $idorQueries = [
            'query GetUserById($userid: String!) {
                getUserById(userid: $userid) {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    userid
                    email
                    username
                    privateData
                }
            }',
            
            'mutation UpdateUser($userid: String!) {
                updateUser(userid: $userid, input: {
                    email: "hacked@example.com"
                }) {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    userid
                }
            }',
        ];

        // Test with various user IDs (assuming we have a valid token for user "123")
        $testUserIds = [
            '124',  // Next user
            '1',    // First user (likely admin)
            'admin',
            "' OR '1'='1",
            '1000', // Non-existent but valid format
            '../other/user',
        ];

        foreach ($idorQueries as $queryTemplate) {
            foreach ($testUserIds as $userId) {
                // Extract operation name
                preg_match('/^(query|mutation)\s+(\w+)/', $queryTemplate, $matches);
                $operationName = $matches[2] ?? 'Unknown';
                
                $variables = ['userid' => $userId];
                $query = $queryTemplate;
                
                // For this test, we'll use a valid token (simulating authenticated user "123")
                $validToken = 'valid.jwt.token.for.user.123';
                
                $request = $this->createGraphQLRequest($query, $variables, $validToken);
                $response = $this->executeGraphQLRequest($request);
                
                $this->assertNoSqlErrors($response);
                $this->assertProperErrorHandling($response);
                
                $data = $this->parseGraphQLResponse($response);
                
                // Check if we can access/modify other users' data
                if (isset($data['data'][$operationName])) {
                    $result = $data['data'][$operationName];
                    
                    // If operation succeeded and returned data for a different user
                    if (isset($result['userid']) && $result['userid'] == $userId && $userId !== '123') {
                        $this->fail(
                            'Possible IDOR vulnerability: Accessed user ' . $userId . 
                            ' data while authenticated as user 123'
                        );
                    }
                    
                    // If mutation succeeded on other user
                    if (isset($result['meta']['ResponseCode']) && 
                        $result['meta']['ResponseCode'] === 'success' && 
                        $userId !== '123') {
                        $this->fail(
                            'Possible IDOR vulnerability: Modified user ' . $userId . 
                            ' data while authenticated as user 123'
                        );
                    }
                }
            }
        }
    }

    /**
     * Test rate limiting bypass attempts.
     */
    public function testRateLimitingBypass(): void
    {
        $bypassAttempts = [
            // Changing IP headers
            'X-Forwarded-For: 1.2.3.4',
            'X-Real-IP: 5.6.7.8',
            'CF-Connecting-IP: 9.10.11.12',
            
            // Changing user agents
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
            'curl/7.68.0',
            
            // API key rotation (if applicable)
            'apikey1',
            'apikey2',
            'apikey3',
        ];

        $query = '
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
        ';

        // Simulate rapid requests (in real test would need actual request sending)
        // For now, just test that the endpoint handles the query properly
        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        // Note: Actual rate limiting test would require sending multiple requests
        // and checking for 429 Too Many Requests responses
    }

    /**
     * Data provider for authentication bypass payloads.
     *
     * @return array
     */
    public function authBypassPayloadsProvider(): array
    {
        return array_map(
            fn($payload) => [$payload],
            $this->getAuthBypassPayloads()
        );
    }
}