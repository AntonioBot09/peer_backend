<?php

declare(strict_types=1);

namespace Tests\Security;

/**
 * SQL injection tests for register mutation.
 * Tests email, password, username, and referralUuid fields for SQL injection vulnerabilities.
 */
class RegisterSqlInjectionTest extends BaseSecurityTest
{
    /**
     * Test SQL injection in email field of register mutation.
     *
     * @dataProvider sqlInjectionPayloadsProvider
     */
    public function testRegisterEmailSqlInjection(string $payload): void
    {
        $query = '
            mutation Register {
                register(input: {
                    email: "' . $payload . '",
                    password: "Password123!",
                    username: "testuser",
                    referralUuid: "ref123"
                }) {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    userid
                }
            }
        ';

        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        $data = $this->parseGraphQLResponse($response);
        
        // Should not successfully register with SQL injection
        if (isset($data['data']['register']['userid'])) {
            $this->fail('Registration succeeded with SQL injection payload in email: ' . $payload);
        }
    }

    /**
     * Test SQL injection in username field of register mutation.
     *
     * @dataProvider sqlInjectionPayloadsProvider
     */
    public function testRegisterUsernameSqlInjection(string $payload): void
    {
        $query = '
            mutation Register {
                register(input: {
                    email: "test@example.com",
                    password: "Password123!",
                    username: "' . $payload . '",
                    referralUuid: "ref123"
                }) {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    userid
                }
            }
        ';

        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        $data = $this->parseGraphQLResponse($response);
        
        // Should not successfully register with SQL injection
        if (isset($data['data']['register']['userid'])) {
            $this->fail('Registration succeeded with SQL injection payload in username: ' . $payload);
        }
    }

    /**
     * Test SQL injection in password field of register mutation.
     *
     * @dataProvider sqlInjectionPayloadsProvider
     */
    public function testRegisterPasswordSqlInjection(string $payload): void
    {
        $query = '
            mutation Register {
                register(input: {
                    email: "test@example.com",
                    password: "' . $payload . '",
                    username: "testuser",
                    referralUuid: "ref123"
                }) {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    userid
                }
            }
        ';

        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        $data = $this->parseGraphQLResponse($response);
        
        // Should not successfully register with SQL injection
        if (isset($data['data']['register']['userid'])) {
            $this->fail('Registration succeeded with SQL injection payload in password: ' . $payload);
        }
    }

    /**
     * Test SQL injection in referralUuid field of register mutation.
     *
     * @dataProvider sqlInjectionPayloadsProvider
     */
    public function testRegisterReferralUuidSqlInjection(string $payload): void
    {
        $query = '
            mutation Register {
                register(input: {
                    email: "test@example.com",
                    password: "Password123!",
                    username: "testuser",
                    referralUuid: "' . $payload . '"
                }) {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    userid
                }
            }
        ';

        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        $data = $this->parseGraphQLResponse($response);
        
        // Should not successfully register with SQL injection
        if (isset($data['data']['register']['userid'])) {
            $this->fail('Registration succeeded with SQL injection payload in referralUuid: ' . $payload);
        }
    }

    /**
     * Test SQL injection in all fields simultaneously.
     *
     * @dataProvider sqlInjectionPayloadsProvider
     */
    public function testRegisterAllFieldsSqlInjection(string $payload): void
    {
        $query = '
            mutation Register {
                register(input: {
                    email: "' . $payload . '",
                    password: "' . $payload . '",
                    username: "' . $payload . '",
                    referralUuid: "' . $payload . '"
                }) {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    userid
                }
            }
        ';

        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
    }

    /**
     * Test stacked query SQL injection.
     */
    public function testRegisterStackedQueryInjection(): void
    {
        $stackedQueries = [
            "test@example.com'; DROP TABLE users; --",
            "test@example.com'; UPDATE users SET password='hacked' WHERE username='admin'; --",
            "test@example.com'; INSERT INTO users (email, password) VALUES ('hacker@example.com', 'hacked'); --",
        ];

        foreach ($stackedQueries as $payload) {
            $query = '
                mutation Register {
                    register(input: {
                        email: "' . $payload . '",
                        password: "Password123!",
                        username: "testuser",
                        referralUuid: "ref123"
                    }) {
                        meta {
                            status
                            RequestId
                            ResponseCode
                            ResponseMessage
                        }
                        userid
                    }
                }
            ';

            $request = $this->createGraphQLRequest($query);
            $response = $this->executeGraphQLRequest($request);
            
            $this->assertNoSqlErrors($response);
            $this->assertProperErrorHandling($response);
            
            // Check response doesn't indicate successful stacked query execution
            $data = $this->parseGraphQLResponse($response);
            $this->assertNotEquals(
                'success',
                $data['data']['register']['meta']['status'] ?? null,
                'Possible stacked query execution with payload: ' . $payload
            );
        }
    }

    /**
     * Test that valid registration structure is accepted (sanity check).
     */
    public function testValidRegistrationStructure(): void
    {
        $query = '
            mutation Register {
                register(input: {
                    email: "valid@example.com",
                    password: "ValidPassword123!",
                    username: "validuser",
                    referralUuid: "valid-ref-123"
                }) {
                    meta {
                        status
                        RequestId
                        ResponseCode
                        ResponseMessage
                    }
                    userid
                }
            }
        ';

        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
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
}