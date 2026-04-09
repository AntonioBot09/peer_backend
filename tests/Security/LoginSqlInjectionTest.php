<?php

declare(strict_types=1);

namespace Tests\Security;

/**
 * SQL injection tests for login mutation.
 * Tests email and password fields for SQL injection vulnerabilities.
 */
class LoginSqlInjectionTest extends BaseSecurityTest
{
    /**
     * Test SQL injection in email field of login mutation.
     *
     * @dataProvider sqlInjectionPayloadsProvider
     */
    public function testLoginEmailSqlInjection(string $payload): void
    {
        $query = '
            mutation Login {
                login(email: "' . $payload . '", password: "test123") {
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
        
        // Should not expose SQL errors
        $this->assertNoSqlErrors($response);
        
        // Should have proper error handling
        $this->assertProperErrorHandling($response);
        
        $data = $this->parseGraphQLResponse($response);
        
        // Should not return successful login with SQL injection
        if (isset($data['data']['login']['accessToken'])) {
            $this->fail('Login succeeded with SQL injection payload: ' . $payload);
        }
    }

    /**
     * Test SQL injection in password field of login mutation.
     *
     * @dataProvider sqlInjectionPayloadsProvider
     */
    public function testLoginPasswordSqlInjection(string $payload): void
    {
        $query = '
            mutation Login {
                login(email: "test@example.com", password: "' . $payload . '") {
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
        
        // Should not expose SQL errors
        $this->assertNoSqlErrors($response);
        
        // Should have proper error handling
        $this->assertProperErrorHandling($response);
        
        $data = $this->parseGraphQLResponse($response);
        
        // Should not return successful login with SQL injection
        if (isset($data['data']['login']['accessToken'])) {
            $this->fail('Login succeeded with SQL injection payload: ' . $payload);
        }
    }

    /**
     * Test SQL injection in both email and password fields.
     *
     * @dataProvider sqlInjectionPayloadsProvider
     */
    public function testLoginBothFieldsSqlInjection(string $payload): void
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
        
        // Should not expose SQL errors
        $this->assertNoSqlErrors($response);
        
        // Should have proper error handling
        $this->assertProperErrorHandling($response);
    }

    /**
     * Test blind SQL injection with time-based payloads.
     */
    public function testLoginBlindSqlInjection(): void
    {
        $timeBasedPayloads = [
            "' AND IF(1=1, SLEEP(5), 0) --",
            "' AND IF(SUBSTRING(@@version,1,1)='5', SLEEP(5), 0) --",
            "'; SELECT pg_sleep(5) --",
        ];

        foreach ($timeBasedPayloads as $payload) {
            $startTime = microtime(true);
            
            $query = '
                mutation Login {
                    login(email: "test@example.com' . $payload . '", password: "test123") {
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
            
            $endTime = microtime(true);
            $executionTime = $endTime - $startTime;
            
            // Response should not take significantly longer than normal
            // (allowing some buffer for normal processing)
            $this->assertLessThan(
                3.0,
                $executionTime,
                'Possible time-based SQL injection detected with payload: ' . $payload . 
                ' (execution time: ' . $executionTime . 's)'
            );
            
            $this->assertNoSqlErrors($response);
            $this->assertProperErrorHandling($response);
        }
    }

    /**
     * Data provider for SQL injection payloads.
     *
     * @return array
     */
    public function sqlInjectionPayloadsProvider(): array
    {
        return array_map(
            fn($payload) => [$payload],
            $this->getSqlInjectionPayloads()
        );
    }

    /**
     * Test that valid login works (sanity check).
     */
    public function testValidLoginWorks(): void
    {
        // Note: This test requires actual database with test user
        // For now, we'll just test that the query structure is valid
        $query = '
            mutation Login {
                login(email: "valid@example.com", password: "validpassword") {
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
        
        // Should not have SQL errors
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
    }
}