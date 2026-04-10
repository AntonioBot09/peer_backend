<?php

declare(strict_types=1);

namespace Tests\Unit;

use Fawaz\App\ValidationException;
use Fawaz\Services\JWTService;
use Fawaz\Utils\PeerLoggerInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for JWTService.
 *
 * Covers token creation, validation, expiry, wrong-key rejection,
 * issuer/audience claim checks, and custom-expiry tokens.
 */
final class JWTServiceTest extends TestCase
{
    private string $privateKey = '';
    private string $publicKey = '';
    private string $refreshPrivateKey = '';
    private string $refreshPublicKey = '';
    private PeerLoggerInterface $logger;
    private JWTService $jwtService;

    protected function setUp(): void
    {
        parent::setUp();

        // Generate ephemeral RSA key pairs for testing
        $accessKeyResource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($accessKeyResource, $privKey);
        $this->privateKey = $privKey;
        $this->publicKey = openssl_pkey_get_details($accessKeyResource)['key'];

        $refreshKeyResource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($refreshKeyResource, $refreshPrivKey);
        $this->refreshPrivateKey = $refreshPrivKey;
        $this->refreshPublicKey = openssl_pkey_get_details($refreshKeyResource)['key'];

        $this->logger = $this->createMock(PeerLoggerInterface::class);

        $this->jwtService = new JWTService(
            $this->privateKey,
            $this->publicKey,
            $this->refreshPrivateKey,
            $this->refreshPublicKey,
            3600,  // 1 hour access token
            86400, // 24 hours refresh token
            $this->logger
        );
    }

    // ─── Token Creation ──────────────────────────────────────────────

    public function testCreateAccessTokenProducesValidRS256JWT(): void
    {
        $token = $this->jwtService->createAccessToken(['uid' => 'user-1']);

        $decoded = JWT::decode($token, new Key($this->publicKey, 'RS256'));

        $this->assertSame('user-1', $decoded->uid);
        $this->assertObjectHasProperty('iat', $decoded);
        $this->assertObjectHasProperty('exp', $decoded);
        $this->assertEqualsWithDelta(time(), $decoded->iat, 5);
        $this->assertEqualsWithDelta(time() + 3600, $decoded->exp, 5);
    }

    public function testCreateRefreshTokenProducesValidRS256JWT(): void
    {
        $token = $this->jwtService->createRefreshToken(['uid' => 'user-2']);

        $decoded = JWT::decode($token, new Key($this->refreshPublicKey, 'RS256'));

        $this->assertSame('user-2', $decoded->uid);
        $this->assertEqualsWithDelta(time() + 86400, $decoded->exp, 5);
    }

    public function testAccessAndRefreshTokensUseDifferentKeys(): void
    {
        $accessToken = $this->jwtService->createAccessToken(['uid' => 'user-3']);
        $refreshToken = $this->jwtService->createRefreshToken(['uid' => 'user-3']);

        // Access token must not decode with refresh key
        $this->expectException(\Exception::class);
        JWT::decode($accessToken, new Key($this->refreshPublicKey, 'RS256'));
    }

    // ─── Token Validation ────────────────────────────────────────────

    public function testValidateTokenSucceedsWithCorrectKey(): void
    {
        $token = $this->jwtService->createAccessToken(['uid' => 'user-4']);

        $decoded = $this->jwtService->validateToken($token);

        $this->assertSame('user-4', $decoded->uid);
    }

    public function testValidateRefreshTokenSucceedsWithRefreshFlag(): void
    {
        $token = $this->jwtService->createRefreshToken(['uid' => 'user-5']);

        $decoded = $this->jwtService->validateToken($token, isRefreshToken: true);

        $this->assertSame('user-5', $decoded->uid);
    }

    public function testValidateTokenRejectsExpiredToken(): void
    {
        // Create a service with 0 second validity so token expires instantly
        $shortService = new JWTService(
            $this->privateKey,
            $this->publicKey,
            $this->refreshPrivateKey,
            $this->refreshPublicKey,
            -1,  // already expired
            86400,
            $this->logger
        );

        $token = $shortService->createAccessToken(['uid' => 'user-6']);

        $this->expectException(ValidationException::class);
        $this->jwtService->validateToken($token);
    }

    public function testValidateTokenRejectsTokenSignedWithWrongKey(): void
    {
        // Generate a separate key pair
        $otherKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($otherKey, $otherPrivate);

        $payload = ['uid' => 'user-7', 'iat' => time(), 'exp' => time() + 3600];
        $token = JWT::encode($payload, $otherPrivate, 'RS256');

        $this->expectException(ValidationException::class);
        $this->jwtService->validateToken($token);
    }

    public function testValidateTokenRejectsRefreshTokenWithAccessKey(): void
    {
        $token = $this->jwtService->createRefreshToken(['uid' => 'user-8']);

        // Validating a refresh token without the isRefreshToken flag should fail
        $this->expectException(ValidationException::class);
        $this->jwtService->validateToken($token, isRefreshToken: false);
    }

    // ─── Issuer / Audience claim checks ──────────────────────────────

    public function testValidateTokenRejectsInvalidIssuer(): void
    {
        $payload = [
            'uid' => 'user-9',
            'iss' => 'evil-issuer.com',
            'iat' => time(),
            'exp' => time() + 3600,
        ];
        $token = JWT::encode($payload, $this->privateKey, 'RS256');

        $this->expectException(ValidationException::class);
        $this->jwtService->validateToken($token);
    }

    public function testValidateTokenRejectsInvalidAudience(): void
    {
        $payload = [
            'uid' => 'user-10',
            'aud' => 'evil-audience.com',
            'iat' => time(),
            'exp' => time() + 3600,
        ];
        $token = JWT::encode($payload, $this->privateKey, 'RS256');

        $this->expectException(ValidationException::class);
        $this->jwtService->validateToken($token);
    }

    public function testValidateTokenAcceptsCorrectIssuerAndAudience(): void
    {
        $payload = [
            'uid' => 'user-11',
            'iss' => 'peerapp.de',
            'aud' => 'peerapp.de',
            'iat' => time(),
            'exp' => time() + 3600,
        ];
        $token = JWT::encode($payload, $this->privateKey, 'RS256');

        $decoded = $this->jwtService->validateToken($token);
        $this->assertSame('user-11', $decoded->uid);
        $this->assertSame('peerapp.de', $decoded->iss);
        $this->assertSame('peerapp.de', $decoded->aud);
    }

    // ─── Custom Expiry ───────────────────────────────────────────────

    public function testCreateAccessTokenWithCustomExpiryRespectsExpiry(): void
    {
        $customExpiry = 120; // 2 minutes
        $token = $this->jwtService->createAccessTokenWithCustomExpriy('user-12', $customExpiry);

        $decoded = JWT::decode($token, new Key($this->publicKey, 'RS256'));

        $this->assertSame('user-12', $decoded->uid);
        $this->assertEqualsWithDelta(time() + 120, $decoded->exp, 5);
        $this->assertSame('peerapp.de', $decoded->iss);
        $this->assertSame('peerapp.de', $decoded->aud);
        $this->assertObjectHasProperty('jti', $decoded);
        $this->assertObjectHasProperty('date', $decoded);
    }

    public function testCreateAccessTokenWithCustomExpiryProducesUniqueJTI(): void
    {
        $token1 = $this->jwtService->createAccessTokenWithCustomExpriy('user-13', 300);
        $token2 = $this->jwtService->createAccessTokenWithCustomExpriy('user-13', 300);

        $decoded1 = JWT::decode($token1, new Key($this->publicKey, 'RS256'));
        $decoded2 = JWT::decode($token2, new Key($this->publicKey, 'RS256'));

        $this->assertNotSame($decoded1->jti, $decoded2->jti);
    }

    // ─── Malformed token ─────────────────────────────────────────────

    public function testValidateTokenRejectsGarbageString(): void
    {
        $this->expectException(ValidationException::class);
        $this->jwtService->validateToken('not.a.jwt');
    }

    public function testValidateTokenRejectsEmptyString(): void
    {
        $this->expectException(ValidationException::class);
        $this->jwtService->validateToken('');
    }
}
