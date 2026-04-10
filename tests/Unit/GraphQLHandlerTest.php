<?php

declare(strict_types=1);

namespace Tests\Unit;

use Fawaz\GraphQLSchemaBuilder;
use Fawaz\Handler\GraphQLHandler;
use Fawaz\Utils\PeerLoggerInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Slim\Psr7\Response;

/**
 * Unit tests for GraphQLHandler.
 *
 * Covers request body validation (empty, null, invalid JSON, missing query),
 * bearer token extraction, and invalid-token rejection.
 */
final class GraphQLHandlerTest extends TestCase
{
    private PeerLoggerInterface $logger;
    private GraphQLSchemaBuilder $schemaBuilder;
    private GraphQLHandler $handler;

    protected function setUp(): void
    {
        parent::setUp();
        $this->logger = $this->createMock(PeerLoggerInterface::class);
        $this->schemaBuilder = $this->createMock(GraphQLSchemaBuilder::class);
        $this->handler = new GraphQLHandler($this->logger, $this->schemaBuilder);
    }

    private function createRequest(string $body, array $headers = []): ServerRequestInterface
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn($body);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getBody')->willReturn($stream);
        $request->method('getHeader')->willReturnCallback(function (string $name) use ($headers) {
            return $headers[$name] ?? [];
        });

        return $request;
    }

    // ─── Empty / Null body → 400 ─────────────────────────────────────

    public function testEmptyBodyReturns400(): void
    {
        $response = $this->handler->handle($this->createRequest(''));

        $this->assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        $this->assertStringContainsString('Empty or invalid request body', $body['error']);
    }

    public function testNullStringBodyReturns400(): void
    {
        $response = $this->handler->handle($this->createRequest('null'));

        $this->assertSame(400, $response->getStatusCode());
    }

    public function testWhitespaceOnlyBodyReturns400(): void
    {
        $response = $this->handler->handle($this->createRequest('   '));

        $this->assertSame(400, $response->getStatusCode());
    }

    // ─── Invalid JSON → 400 ──────────────────────────────────────────

    public function testInvalidJsonReturns400(): void
    {
        $response = $this->handler->handle($this->createRequest('{broken json'));

        $this->assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        $this->assertStringContainsString('Invalid JSON format', $body['error']);
    }

    public function testJsonArrayReturns400(): void
    {
        // Non-object JSON arrays: json_decode produces array but missing 'query'
        $response = $this->handler->handle($this->createRequest('["not","an","object"]'));

        // This is valid JSON and an array, but missing 'query' key
        $this->assertSame(400, $response->getStatusCode());
    }

    // ─── Missing query field → 400 ───────────────────────────────────

    public function testMissingQueryFieldReturns400(): void
    {
        $response = $this->handler->handle($this->createRequest('{"variables":{}}'));

        $this->assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        $this->assertStringContainsString('Invalid GraphQL query', $body['error']);
    }

    public function testEmptyQueryStringReturns400(): void
    {
        $response = $this->handler->handle($this->createRequest('{"query":"   "}'));

        $this->assertSame(400, $response->getStatusCode());
    }

    // ─── Invalid bearer token → 401 ─────────────────────────────────

    public function testInvalidBearerTokenReturns401(): void
    {
        $this->schemaBuilder
            ->method('setCurrentUserId')
            ->willReturn(false);

        $response = $this->handler->handle(
            $this->createRequest(
                '{"query":"{ hello }"}',
                ['Authorization' => ['Bearer invalid.token.here']]
            )
        );

        $this->assertSame(401, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        $this->assertStringContainsString('Invalid Access Token', $body['error']);
    }

    // ─── Content-Type header ─────────────────────────────────────────

    public function testErrorResponsesHaveJsonContentType(): void
    {
        $response = $this->handler->handle($this->createRequest(''));

        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
    }

    public function testValidBodyWithInvalidTokenHasJsonContentType(): void
    {
        $this->schemaBuilder
            ->method('setCurrentUserId')
            ->willReturn(false);

        $response = $this->handler->handle(
            $this->createRequest('{"query":"{ test }"}')
        );

        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
    }

    // ─── Bearer token extraction ─────────────────────────────────────

    public function testNoBearerTokenPassesNullToSchemaBuilder(): void
    {
        $this->schemaBuilder
            ->expects($this->once())
            ->method('setCurrentUserId')
            ->with(null)
            ->willReturn(false);

        $this->handler->handle($this->createRequest('{"query":"{ hello }"}'));
    }

    public function testBearerTokenExtractedFromAuthorizationHeader(): void
    {
        $this->schemaBuilder
            ->expects($this->once())
            ->method('setCurrentUserId')
            ->with('my-token-value')
            ->willReturn(false);

        $this->handler->handle(
            $this->createRequest(
                '{"query":"{ hello }"}',
                ['Authorization' => ['Bearer my-token-value']]
            )
        );
    }

    public function testMalformedAuthorizationHeaderIgnored(): void
    {
        $this->schemaBuilder
            ->expects($this->once())
            ->method('setCurrentUserId')
            ->with(null)
            ->willReturn(false);

        // Not a Bearer token
        $this->handler->handle(
            $this->createRequest(
                '{"query":"{ hello }"}',
                ['Authorization' => ['Basic dXNlcjpwYXNz']]
            )
        );
    }
}
