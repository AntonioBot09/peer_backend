<?php

declare(strict_types=1);

namespace Tests\Unit;

use Fawaz\Middleware\SecurityHeadersMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;

/**
 * Unit tests for SecurityHeadersMiddleware.
 *
 * Verifies that all security headers are set with the correct values.
 */
final class SecurityHeadersMiddlewareTest extends TestCase
{
    private SecurityHeadersMiddleware $middleware;
    private ResponseInterface $response;

    protected function setUp(): void
    {
        parent::setUp();
        $this->middleware = new SecurityHeadersMiddleware();

        $request = $this->createMock(ServerRequestInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn(new Response(200));

        $this->response = $this->middleware->process($request, $handler);
    }

    public function testSetsContentSecurityPolicy(): void
    {
        $this->assertSame(
            "default-src 'self'; script-src 'self'; object-src 'none';",
            $this->response->getHeaderLine('Content-Security-Policy')
        );
    }

    public function testSetsXContentTypeOptions(): void
    {
        $this->assertSame('nosniff', $this->response->getHeaderLine('X-Content-Type-Options'));
    }

    public function testSetsXFrameOptions(): void
    {
        $this->assertSame('DENY', $this->response->getHeaderLine('X-Frame-Options'));
    }

    public function testSetsXXSSProtection(): void
    {
        $this->assertSame('1; mode=block', $this->response->getHeaderLine('X-XSS-Protection'));
    }

    public function testSetsStrictTransportSecurity(): void
    {
        $this->assertSame(
            'max-age=31536000; includeSubDomains; preload',
            $this->response->getHeaderLine('Strict-Transport-Security')
        );
    }

    public function testSetsReferrerPolicy(): void
    {
        $this->assertSame('no-referrer', $this->response->getHeaderLine('Referrer-Policy'));
    }

    public function testSetsPermissionsPolicy(): void
    {
        $this->assertSame(
            'geolocation=(), microphone=(), camera=()',
            $this->response->getHeaderLine('Permissions-Policy')
        );
    }

    public function testPreservesOriginalStatusCode(): void
    {
        $this->assertSame(200, $this->response->getStatusCode());
    }
}
