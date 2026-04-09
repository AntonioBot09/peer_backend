<?php

declare(strict_types=1);

namespace Tests\Security;

/**
 * Error handling and resilience tests.
 * Tests how the backend handles errors, timeouts, and edge cases.
 */
class ErrorHandlingTest extends BaseSecurityTest
{
    /**
     * Test malformed JSON requests.
     */
    public function testMalformedJsonRequests(): void
    {
        $malformedPayloads = [
            '{not-valid-json}',
            '{"query": "mutation Login { login(email: "test", password: "test") { accessToken } }"}', // Unescaped quotes
            '[invalid]',
            'null',
            '',
            '    ',
            '{"query": "query { __typename }", "variables": "not-an-object"}',
            '{"query": 123}',
            '{"query": null}',
            '{"query": true}',
            '{"query": []}',
        ];

        foreach ($malformedPayloads as $payload) {
            // Create request with malformed JSON
            $request = new \Slim\Psr7\Request('POST', '/graphql');
            $request = $request->withHeader('Content-Type', 'application/json');
            $request->getBody()->write($payload);
            $request->getBody()->rewind();

            $response = $this->executeGraphQLRequest($request);
            
            // Should handle malformed JSON gracefully
            $this->assertNoSqlErrors($response);
            
            // Should return 400 Bad Request for malformed JSON
            $statusCode = $response->getStatusCode();
            $this->assertGreaterThanOrEqual(
                400,
                $statusCode,
                'Malformed JSON should return 4xx error, got: ' . $statusCode . ' for payload: ' . $payload
            );
            
            // Should have proper error message
            $body = (string) $response->getBody();
            $data = json_decode($body, true);
            $this->assertIsArray($data, 'Response should be JSON');
            $this->assertArrayHasKey('error', $data, 'Error response should contain error field');
        }
    }

    /**
     * Test extremely large requests.
     */
    public function testLargeRequestHandling(): void
    {
        // Create very large query
        $largeQuery = 'query { __typename ' . str_repeat(' __typename', 10000) . ' }';
        
        $request = $this->createGraphQLRequest($largeQuery);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        // Should handle large requests without crashing
        $statusCode = $response->getStatusCode();
        $this->assertNotEquals(500, $statusCode, 'Large request caused 500 Internal Server Error');
    }

    /**
     * Test deeply nested GraphQL queries.
     */
    public function testDeeplyNestedQueries(): void
    {
        // Create deeply nested query (GraphQL depth attack)
        $depth = 20;
        $query = 'query { ' . $this->generateNestedQuery($depth) . ' }';
        
        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        // Should handle depth limits properly
        $data = $this->parseGraphQLResponse($response);
        
        // Should not return 500 for depth limit exceeded
        $statusCode = $response->getStatusCode();
        $this->assertNotEquals(500, $statusCode, 'Deeply nested query caused 500 Internal Server Error');
    }

    /**
     * Test circular fragment references.
     */
    public function testCircularFragmentReferences(): void
    {
        $query = '
            query {
                ...FragmentA
            }
            
            fragment FragmentA on Query {
                __typename
                ...FragmentB
            }
            
            fragment FragmentB on Query {
                __typename
                ...FragmentA
            }
        ';
        
        $request = $this->createGraphQLRequest($query);
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        // Should handle circular references gracefully
        $statusCode = $response->getStatusCode();
        $this->assertNotEquals(500, $statusCode, 'Circular fragment caused 500 Internal Server Error');
    }

    /**
     * Test invalid GraphQL syntax.
     */
    public function testInvalidGraphQLSyntax(): void
    {
        $invalidQueries = [
            'query { invalidField }',
            'mutation { invalidMutation }',
            '{ __typename ',
            'query { __typename } mutation { __typename }',
            'query ($var: InvalidType) { __typename }',
            'query { ... on InvalidType { __typename } }',
            'query { __typename @invalidDirective }',
        ];
        
        foreach ($invalidQueries as $query) {
            $request = $this->createGraphQLRequest($query);
            $response = $this->executeGraphQLRequest($request);
            
            $this->assertNoSqlErrors($response);
            
            // Should return 400 for invalid GraphQL
            $statusCode = $response->getStatusCode();
            $this->assertGreaterThanOrEqual(
                400,
                $statusCode,
                'Invalid GraphQL should return 4xx error, got: ' . $statusCode . ' for query: ' . $query
            );
            
            $this->assertProperErrorHandling($response);
        }
    }

    /**
     * Test missing required fields in mutations.
     */
    public function testMissingRequiredFields(): void
    {
        $incompleteMutations = [
            // Missing email
            'mutation Register {
                register(input: {
                    password: "test",
                    username: "test"
                }) {
                    userid
                }
            }',
            
            // Missing password
            'mutation Register {
                register(input: {
                    email: "test@example.com",
                    username: "test"
                }) {
                    userid
                }
            }',
            
            // Empty input object
            'mutation Register {
                register(input: {}) {
                    userid
                }
            }',
            
            // Null input
            'mutation Register {
                register(input: null) {
                    userid
                }
            }',
        ];
        
        foreach ($incompleteMutations as $query) {
            $request = $this->createGraphQLRequest($query);
            $response = $this->executeGraphQLRequest($request);
            
            $this->assertNoSqlErrors($response);
            $this->assertProperErrorHandling($response);
            
            // Should return validation error, not 500
            $statusCode = $response->getStatusCode();
            $this->assertNotEquals(
                500,
                $statusCode,
                'Missing required fields caused 500 Internal Server Error for query: ' . $query
            );
        }
    }

    /**
     * Test type mismatch in variables.
     */
    public function testTypeMismatch(): void
    {
        $typeMismatchQueries = [
            [
                'query' => 'query GetUser($userid: Int!) { getUserById(userid: $userid) { userid } }',
                'variables' => ['userid' => 'not-a-number'],
            ],
            [
                'query' => 'query GetUser($userid: String!) { getUserById(userid: $userid) { userid } }',
                'variables' => ['userid' => 123], // Int instead of String
            ],
            [
                'query' => 'query GetUser($email: String!) { getUserByEmail(email: $email) { userid } }',
                'variables' => ['email' => ['array', 'not', 'string']],
            ],
            [
                'query' => 'mutation Login($input: LoginInput!) { login(input: $input) { accessToken } }',
                'variables' => ['input' => 'not-an-object'],
            ],
        ];
        
        foreach ($typeMismatchQueries as $testCase) {
            $request = $this->createGraphQLRequest($testCase['query'], $testCase['variables']);
            $response = $this->executeGraphQLRequest($request);
            
            $this->assertNoSqlErrors($response);
            $this->assertProperErrorHandling($response);
            
            // Should handle type mismatches gracefully
            $statusCode = $response->getStatusCode();
            $this->assertNotEquals(
                500,
                $statusCode,
                'Type mismatch caused 500 Internal Server Error'
            );
        }
    }

    /**
     * Test special characters and Unicode in input.
     */
    public function testSpecialCharacterHandling(): void
    {
        $specialStrings = [
            'test@example.com',
            'test+tag@example.com',
            'test.user@example.com',
            'test"quote@example.com',
            "test'apostrophe@example.com",
            'test<less@example.com',
            'test>greater@example.com',
            'test&ersand@example.com',
            'test=equals@example.com',
            'test?question@example.com',
            'test#hash@example.com',
            'test%percent@example.com',
            'test{brace@example.com',
            'test}bracket@example.com',
            'test[array@example.com',
            'test]close@example.com',
            'test|pipe@example.com',
            'test\\backslash@example.com',
            'test/forward@example.com',
            'test:colon@example.com',
            'test;semicolon@example.com',
            'test`backtick@example.com',
            'test~tilde@example.com',
            'test^caret@example.com',
            'test*asterisk@example.com',
            'test(open@example.com',
            'test)close@example.com',
            'test_underscore@example.com',
            'test-dash@example.com',
            'test space@example.com',
            'test	tab@example.com',
            'test' . "\n" . 'newline@example.com',
            'test' . "\r" . 'return@example.com',
            'test' . "\0" . 'null@example.com',
            '🎉emoji@example.com',
            '🚀rocket@example.com',
            'test' . html_entity_decode('&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;', ENT_QUOTES, 'UTF-8') . '@example.com',
            'test' . urlencode('<script>') . '@example.com',
            'test' . base64_encode('<script>') . '@example.com',
            'test' . sprintf('%c', 0) . 'nullbyte@example.com',
        ];
        
        foreach ($specialStrings as $email) {
            $query = '
                mutation Register {
                    register(input: {
                        email: "' . addslashes($email) . '",
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
            
            // Should handle special characters without crashing
            $statusCode = $response->getStatusCode();
            $this->assertNotEquals(
                500,
                $statusCode,
                'Special characters caused 500 Internal Server Error: ' . substr($email, 0, 50)
            );
        }
    }

    /**
     * Test concurrent request handling (simulated).
     * Note: Actual concurrency testing would require multiple simultaneous requests.
     */
    public function testConcurrentRequestStructure(): void
    {
        // Test batch queries (multiple operations in one request)
        $batchQuery = [
            ['query' => 'query { __typename }'],
            ['query' => 'query { __schema { types { name } } }'],
            ['query' => 'mutation Login { login(email: "test@example.com", password: "test") { accessToken } }'],
        ];
        
        $request = $this->createGraphQLRequest(json_encode($batchQuery));
        $response = $this->executeGraphQLRequest($request);
        
        $this->assertNoSqlErrors($response);
        $this->assertProperErrorHandling($response);
        
        // Should handle batch requests
        $statusCode = $response->getStatusCode();
        $this->assertNotEquals(500, $statusCode, 'Batch request caused 500 Internal Server Error');
    }

    /**
     * Generate a nested GraphQL query for depth testing.
     *
     * @param int $depth Nesting depth
     * @return string
     */
    private function generateNestedQuery(int $depth): string
    {
        if ($depth <= 0) {
            return '__typename';
        }
        
        return '__typename { ' . $this->generateNestedQuery($depth - 1) . ' }';
    }
}