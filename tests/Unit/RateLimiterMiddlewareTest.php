<?php

declare(strict_types=1);

namespace Tests\Unit;

use Fawaz\Middleware\RateLimiterMiddleware;
use Fawaz\RateLimiter\RateLimiter;
use Fawaz\Utils\PeerLoggerInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;

/**
 * Unit tests for RateLimiterMiddleware.
 *
 * Covers pass-through on allowed requests, 429 response on rate limit,
 * correct header values, and handling of invalid/missing REMOTE_ADDR.
 */
final class RateLimiterMiddlewareTest extends TestCase
{
    private PeerLoggerInterface $logger;

    protected function setUp(): void
    {
        parent::setUp();
        $this->logger = $this->createMock(PeerLoggerInterface::class);
    }

    private function createRequest(string $ip = '192.168.1.1'): ServerRequestInterface
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => $ip]);
        return $request;
    }

    private function createHandler(?ResponseInterface $response = null): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response ?? new Response());
        return $handler;
    }

    // ─── Pass-through when allowed ───────────────────────────────────

    public function testPassesThroughWhenRateLimitNotExceeded(): void
    {
        $rateLimiter = $this->createMock(RateLimiter::class);
        $rateLimiter->method('isAllowed')->willReturn(true);

        $middleware = new RateLimiterMiddleware($rateLimiter, $this->logger);

        $innerResponse = new Response(200);
        $innerResponse->getBody()->write('OK');
        $handler = $this->createHandler($innerResponse);

        $response = $middleware->process($this->createRequest(), $handler);

        $this->assertSame(200, $response->getStatusCode());
    }

    // ─── 429 when rate limited ───────────────────────────────────────

    public function testReturns429WhenRateLimitExceeded(): void
    {
        $rateLimiter = $this->createMock(RateLimiter::class);
        $rateLimiter->method('isAllowed')->willReturn(false);
        $rateLimiter->method('getLimit')->willReturn(100);

        $middleware = new RateLimiterMiddleware($rateLimiter, $this->logger);

        $response = $middleware->process($this->createRequest(), $this->createHandler());

        $this->assertSame(429, $response->getStatusCode());
    }

    public function testRateLimitResponseContainsCorrectHeaders(): void
    {
        $rateLimiter = $this->createMock(RateLimiter::class);
        $rateLimiter->method('isAllowed')->willReturn(false);
        $rateLimiter->method('getLimit')->willReturn(50);

        $middleware = new RateLimiterMiddleware($rateLimiter, $this->logger);

        $response = $middleware->process($this->createRequest(), $this->createHandler());

        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
        $this->assertSame('50', $response->getHeaderLine('X-RateLimit-Limit'));
        $this->assertSame('0', $response->getHeaderLine('X-RateLimit-Remaining'));

        $reset = (int) $response->getHeaderLine('X-RateLimit-Reset');
        $this->assertGreaterThan(time(), $reset);
    }

    public function testRateLimitResponseContainsJsonBody(): void
    {
        $rateLimiter = $this->createMock(RateLimiter::class);
        $rateLimiter->method('isAllowed')->willReturn(false);
        $rateLimiter->method('getLimit')->willReturn(10);

        $middleware = new RateLimiterMiddleware($rateLimiter, $this->logger);

        $response = $middleware->process($this->createRequest(), $this->createHandler());

        $body = json_decode((string) $response->getBody(), true);
        $this->assertSame('Rate limit exceeded', $body['errors']);
        $this->assertSame(60, $body['retry_after']);
    }

    // ─── Invalid / Missing IP ────────────────────────────────────────

    public function testHandlesMissingRemoteAddr(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn([]);

        $rateLimiter = $this->createMock(RateLimiter::class);
        $rateLimiter->method('isAllowed')->with('unknown')->willReturn(true);

        $middleware = new RateLimiterMiddleware($rateLimiter, $this->logger);
        $response = $middleware->process($request, $this->createHandler(new Response(200)));

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testHandlesInvalidIpAddress(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => 'not-an-ip']);

        $rateLimiter = $this->createMock(RateLimiter::class);
        $rateLimiter->method('isAllowed')->with('unknown')->willReturn(true);

        $middleware = new RateLimiterMiddleware($rateLimiter, $this->logger);
        $response = $middleware->process($request, $this->createHandler(new Response(200)));

        $this->assertSame(200, $response->getStatusCode());
    }
}
