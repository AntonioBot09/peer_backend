<?php

declare(strict_types=1);

namespace Tests\Security;

use PHPUnit\Framework\TestCase;
use Fawaz\Handler\GraphQLHandler;
use Fawaz\GraphQLSchemaBuilder;
use Fawaz\Utils\PeerLoggerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Request;
use Slim\Psr7\Response;

/**
 * Base class for security tests.
 * Provides common methods for testing SQL injection, XSS, and authentication bypass.
 */
abstract class BaseSecurityTest extends TestCase
{
    protected GraphQLHandler $graphqlHandler;
    protected PeerLoggerInterface $logger;
    protected GraphQLSchemaBuilder $schemaBuilder;

    protected function setUp(): void
    {
        parent::setUp();
        
        // Mock dependencies
        $this->logger = $this->createMock(PeerLoggerInterface::class);
        $this->schemaBuilder = $this->createMock(GraphQLSchemaBuilder::class);
        
        // Create GraphQL handler instance
        $this->graphqlHandler = new GraphQLHandler($this->logger, $this->schemaBuilder);
    }

    /**
     * Create a mock GraphQL request with payload.
     *
     * @param string $query GraphQL query/mutation
     * @param array|null $variables GraphQL variables
     * @param string|null $authorization Bearer token
     * @return ServerRequestInterface
     */
    protected function createGraphQLRequest(
        string $query,
        ?array $variables = null,
        ?string $authorization = null
    ): ServerRequestInterface {
        $payload = ['query' => $query];
        if ($variables !== null) {
            $payload['variables'] = $variables;
        }

        $request = new Request('POST', '/graphql');
        $request = $request->withHeader('Content-Type', 'application/json');
        
        if ($authorization !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $authorization);
        }

        $body = json_encode($payload);
        $request->getBody()->write($body);
        $request->getBody()->rewind();

        return $request;
    }

    /**
     * Execute a GraphQL request and return response.
     *
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     */
    protected function executeGraphQLRequest(ServerRequestInterface $request): ResponseInterface
    {
        return $this->graphqlHandler->handle($request);
    }

    /**
     * Parse GraphQL response body.
     *
     * @param ResponseInterface $response
     * @return array
     */
    protected function parseGraphQLResponse(ResponseInterface $response): array
    {
        $body = (string) $response->getBody();
        return json_decode($body, true) ?? [];
    }

    /**
     * Common SQL injection payloads for testing.
     *
     * @return array
     */
    protected function getSqlInjectionPayloads(): array
    {
        return [
            // Basic SQL injection
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1' /*",
            
            // Union-based SQL injection
            "' UNION SELECT null, null, null --",
            "' UNION SELECT username, password FROM users --",
            
            // Error-based SQL injection
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            "' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT @@version))) --",
            
            // Blind SQL injection
            "' AND IF(1=1, SLEEP(5), 0) --",
            "' AND IF(SUBSTRING(@@version,1,1)='5', SLEEP(5), 0) --",
            
            // Time-based SQL injection
            "'; WAITFOR DELAY '00:00:05' --",
            "'; SELECT pg_sleep(5) --",
            
            // Stacked queries
            "'; DROP TABLE users; --",
            "'; UPDATE users SET password='hacked' WHERE username='admin'; --",
        ];
    }

    /**
     * Common XSS payloads for testing.
     *
     * @return array
     */
    protected function getXssPayloads(): array
    {
        return [
            // Basic XSS
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            
            // Event handlers
            '" onmouseover="alert(\'XSS\')',
            "' onfocus='alert(\"XSS\")' autofocus ",
            
            // JavaScript URIs
            'javascript:alert("XSS")',
            'JaVaScRiPt:alert("XSS")',
            
            // Data URIs
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
            
            // SVG payloads
            '<svg><script>alert("XSS")</script></svg>',
            
            // Bypass attempts
            '<scr<script>ipt>alert("XSS")</scr</script>ipt>',
            '<<script>script>alert("XSS")</script>',
        ];
    }

    /**
     * Common authentication bypass payloads.
     *
     * @return array
     */
    protected function getAuthBypassPayloads(): array
    {
        return [
            // JWT tampering
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
            
            // SQL injection in auth
            "admin' --",
            "admin' #",
            "' OR '1'='1",
            
            // NoSQL injection
            '{"$ne": null}',
            '{"$gt": ""}',
            
            // Header manipulation
            'Bearer null',
            'Bearer undefined',
            'Bearer true',
        ];
    }

    /**
     * Assert that response does not contain SQL error messages.
     *
     * @param ResponseInterface $response
     */
    protected function assertNoSqlErrors(ResponseInterface $response): void
    {
        $body = (string) $response->getBody();
        
        $sqlErrorPatterns = [
            '/SQLSTATE\[/i',
            '/syntax error/i',
            '/mysql_fetch/i',
            '/pg_execute/i',
            '/sqlite3_exec/i',
            '/ORA-[0-9]{5}/i',
            '/Microsoft.*ODBC/i',
            '/Driver.*SQL/i',
            '/Unclosed quotation mark/i',
            '/Incorrect syntax/i',
        ];

        foreach ($sqlErrorPatterns as $pattern) {
            $this->assertDoesNotMatchRegularExpression(
                $pattern,
                $body,
                'Response contains SQL error: ' . $pattern
            );
        }
    }

    /**
     * Assert that response has proper error handling (not raw errors).
     *
     * @param ResponseInterface $response
     */
    protected function assertProperErrorHandling(ResponseInterface $response): void
    {
        $statusCode = $response->getStatusCode();
        
        // Should return proper HTTP status codes
        $this->assertContains(
            $statusCode,
            [200, 400, 401, 403, 404, 422, 500],
            'Unexpected HTTP status code: ' . $statusCode
        );

        $body = (string) $response->getBody();
        $data = json_decode($body, true);

        if ($statusCode >= 400) {
            // Error responses should have structured format
            $this->assertIsArray($data, 'Error response should be JSON object');
            $this->assertArrayHasKey('error', $data, 'Error response should contain error field');
        }
    }
}