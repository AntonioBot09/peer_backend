<?php

declare(strict_types=1);

namespace Tests\Unit;

use Fawaz\App\CommentService;
use Fawaz\Database\CommentMapper;
use Fawaz\Database\CommentInfoMapper;
use Fawaz\Database\PostInfoMapper;
use Fawaz\Database\UserMapper;
use Fawaz\Database\Interfaces\TransactionManager;
use Fawaz\Utils\PeerLoggerInterface;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for CommentService.
 *
 * Covers UUID generation format, authentication gating,
 * createComment validation, and fetch methods.
 */
final class CommentServiceTest extends TestCase
{
    private const VALID_UUID = '550e8400-e29b-41d4-a716-446655440000';
    private const INVALID_UUID = 'not-a-uuid';

    private PeerLoggerInterface $logger;
    private CommentMapper $commentMapper;
    private CommentInfoMapper $commentInfoMapper;
    private PostInfoMapper $postInfoMapper;
    private UserMapper $userMapper;
    private TransactionManager $transactionManager;
    private CommentService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->logger = $this->createMock(PeerLoggerInterface::class);
        $this->commentMapper = $this->createMock(CommentMapper::class);
        $this->commentInfoMapper = $this->createMock(CommentInfoMapper::class);
        $this->postInfoMapper = $this->createMock(PostInfoMapper::class);
        $this->userMapper = $this->createMock(UserMapper::class);
        $this->transactionManager = $this->createMock(TransactionManager::class);

        $this->service = new CommentService(
            $this->logger,
            $this->commentMapper,
            $this->commentInfoMapper,
            $this->postInfoMapper,
            $this->userMapper,
            $this->transactionManager
        );
    }

    // ─── UUID Generation ─────────────────────────────────────────────

    public function testGenerateUUIDProducesValidV4Format(): void
    {
        $ref = new \ReflectionMethod(CommentService::class, 'generateUUID');
        $ref->setAccessible(true);

        $uuid = $ref->invoke($this->service);

        // UUID v4 pattern: 8-4-4-4-12 hex with version nibble 4 and variant 8/9/a/b
        $pattern = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/';
        $this->assertMatchesRegularExpression($pattern, $uuid);
    }

    public function testGenerateUUIDProducesUniqueValues(): void
    {
        $ref = new \ReflectionMethod(CommentService::class, 'generateUUID');
        $ref->setAccessible(true);

        $uuids = [];
        for ($i = 0; $i < 50; $i++) {
            $uuids[] = $ref->invoke($this->service);
        }

        $this->assertCount(50, array_unique($uuids), 'UUIDs should be unique');
    }

    // ─── Authentication Gating ───────────────────────────────────────

    public function testCreateCommentRejectsUnauthenticatedUser(): void
    {
        $result = $this->service->createComment(['content' => 'test', 'postid' => self::VALID_UUID]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('60501', $result['ResponseCode']);
    }

    public function testFetchAllByPostIdRejectsUnauthenticatedUser(): void
    {
        $result = $this->service->fetchAllByPostId(['postid' => self::VALID_UUID]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('60501', $result['ResponseCode']);
    }

    public function testFetchByParentIdRejectsUnauthenticatedUser(): void
    {
        $result = $this->service->fetchByParentId(['parent' => self::VALID_UUID]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('60501', $result['ResponseCode']);
    }

    // ─── createComment: Input validation ─────────────────────────────

    public function testCreateCommentRejectsEmptyArgs(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $result = $this->service->createComment([]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30101', $result['ResponseCode']);
    }

    public function testCreateCommentRejectsMissingContent(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $result = $this->service->createComment(['postid' => self::VALID_UUID]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30265', $result['ResponseCode']);
    }

    public function testCreateCommentRejectsMissingPostId(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $result = $this->service->createComment(['content' => 'Hello']);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30265', $result['ResponseCode']);
    }

    public function testCreateCommentRejectsInvalidPostId(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $result = $this->service->createComment([
            'content' => 'Valid content',
            'postid' => self::INVALID_UUID,
        ]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30209', $result['ResponseCode']);
    }

    public function testCreateCommentRejectsInvalidParentId(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $result = $this->service->createComment([
            'content' => 'Valid content',
            'postid' => self::VALID_UUID,
            'parentid' => self::INVALID_UUID,
        ]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('31603', $result['ResponseCode']);
    }

    public function testCreateCommentRejectsEmptyContent(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $result = $this->service->createComment([
            'content' => '   ',
            'postid' => self::VALID_UUID,
        ]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30101', $result['ResponseCode']);
    }

    // ─── fetchAllByPostId / fetchByParentId: UUID validation ─────────

    public function testFetchAllByPostIdRejectsInvalidUUID(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $result = $this->service->fetchAllByPostId(['postid' => self::INVALID_UUID]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30209', $result['ResponseCode']);
    }

    public function testFetchByParentIdRejectsInvalidUUID(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $result = $this->service->fetchByParentId(['parent' => self::INVALID_UUID]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30209', $result['ResponseCode']);
    }
}
