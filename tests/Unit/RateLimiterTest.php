<?php

declare(strict_types=1);

namespace Tests\Unit;

use Fawaz\RateLimiter\RateLimiter;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the RateLimiter class.
 *
 * Uses a temporary directory for storage so tests are isolated
 * and do not pollute the filesystem.
 */
final class RateLimiterTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tempDir = sys_get_temp_dir() . '/rate_limiter_test_' . uniqid();
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        // Clean up temp files
        $files = glob($this->tempDir . '/*');
        if ($files) {
            foreach ($files as $file) {
                if (is_file($file)) {
                    unlink($file);
                }
            }
        }
        if (is_dir($this->tempDir)) {
            rmdir($this->tempDir);
        }
        parent::tearDown();
    }

    // ─── isAllowed ───────────────────────────────────────────────────

    public function testIsAllowedReturnsTrueWhenUnderLimit(): void
    {
        $limiter = new RateLimiter(5, 60, $this->tempDir);

        $this->assertTrue($limiter->isAllowed('client-1'));
        $this->assertTrue($limiter->isAllowed('client-1'));
        $this->assertTrue($limiter->isAllowed('client-1'));
    }

    public function testIsAllowedReturnsFalseAfterExceedingLimit(): void
    {
        $limiter = new RateLimiter(3, 60, $this->tempDir);

        $this->assertTrue($limiter->isAllowed('client-2'));
        $this->assertTrue($limiter->isAllowed('client-2'));
        $this->assertTrue($limiter->isAllowed('client-2'));
        // 4th call exceeds limit of 3
        $this->assertFalse($limiter->isAllowed('client-2'));
    }

    public function testIsAllowedTracksIdentifiersIndependently(): void
    {
        $limiter = new RateLimiter(2, 60, $this->tempDir);

        $this->assertTrue($limiter->isAllowed('a'));
        $this->assertTrue($limiter->isAllowed('a'));
        $this->assertFalse($limiter->isAllowed('a'));

        // Different identifier still has quota
        $this->assertTrue($limiter->isAllowed('b'));
        $this->assertTrue($limiter->isAllowed('b'));
        $this->assertFalse($limiter->isAllowed('b'));
    }

    public function testIsAllowedPermitsRequestsAfterTimeWindowExpires(): void
    {
        // Use a very short window (1 second) to test expiry
        $limiter = new RateLimiter(1, 1, $this->tempDir);

        $this->assertTrue($limiter->isAllowed('client-3'));
        $this->assertFalse($limiter->isAllowed('client-3'));

        // Wait for window to expire
        sleep(2);

        $this->assertTrue($limiter->isAllowed('client-3'));
    }

    // ─── getLimit ────────────────────────────────────────────────────

    public function testGetLimitReturnsConfiguredValue(): void
    {
        $limiter = new RateLimiter(42, 60, $this->tempDir);
        $this->assertSame(42, $limiter->getLimit());
    }

    // ─── Storage file creation ───────────────────────────────────────

    public function testConstructorCreatesStorageFile(): void
    {
        new RateLimiter(5, 60, $this->tempDir);

        $expectedFile = $this->tempDir . DIRECTORY_SEPARATOR . date('Y-m-d') . '_rate_limiter_storage.json';
        $this->assertFileExists($expectedFile);

        $content = json_decode(file_get_contents($expectedFile), true);
        $this->assertSame([], $content);
    }

    public function testIsAllowedPersistsRequestsToFile(): void
    {
        $limiter = new RateLimiter(10, 60, $this->tempDir);

        $limiter->isAllowed('persist-test');

        $file = $this->tempDir . DIRECTORY_SEPARATOR . date('Y-m-d') . '_rate_limiter_storage.json';
        $data = json_decode(file_get_contents($file), true);

        $this->assertArrayHasKey('persist-test', $data);
        $this->assertCount(1, $data['persist-test']);
    }
}
