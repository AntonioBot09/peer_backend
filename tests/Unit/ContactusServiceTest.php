<?php

declare(strict_types=1);

namespace Tests\Unit;

use Fawaz\App\Contactus;
use Fawaz\App\ContactusService;
use Fawaz\Database\ContactusMapper;
use Fawaz\Database\Interfaces\TransactionManager;
use Fawaz\Utils\PeerLoggerInterface;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for ContactusService.
 *
 * Covers insert (transaction wrapping, rollback on failure),
 * checkRateLimit, loadById validation, and fetchAll checks.
 */
final class ContactusServiceTest extends TestCase
{
    private PeerLoggerInterface $logger;
    private ContactusMapper $contactUsMapper;
    private TransactionManager $transactionManager;
    private ContactusService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->logger = $this->createMock(PeerLoggerInterface::class);
        $this->contactUsMapper = $this->createMock(ContactusMapper::class);
        $this->transactionManager = $this->createMock(TransactionManager::class);

        $this->service = new ContactusService(
            $this->logger,
            $this->contactUsMapper,
            $this->transactionManager
        );
    }

    // ─── insert ──────────────────────────────────────────────────────

    public function testInsertCommitsTransactionOnSuccess(): void
    {
        $contact = new Contactus([
            'msgid' => 1,
            'email' => 'test@example.com',
            'name' => 'Test User',
            'message' => 'Hello',
            'ip' => '127.0.0.1',
            'createdat' => '2025-01-01 00:00:00.000000',
        ], [], false);

        $this->transactionManager->expects($this->once())->method('beginTransaction');
        $this->transactionManager->expects($this->once())->method('commit');
        $this->transactionManager->expects($this->never())->method('rollback');

        $this->contactUsMapper
            ->method('insert')
            ->willReturn($contact);

        $result = $this->service->insert($contact);

        $this->assertInstanceOf(Contactus::class, $result);
        $this->assertSame(1, $result->getMsgId());
    }

    public function testInsertRollsBackAndReturnsNullOnFailure(): void
    {
        $contact = new Contactus([
            'msgid' => 2,
            'email' => 'fail@example.com',
            'name' => 'Fail User',
            'message' => 'Bye',
            'ip' => '127.0.0.1',
            'createdat' => '2025-01-01 00:00:00.000000',
        ], [], false);

        $this->transactionManager->expects($this->once())->method('beginTransaction');
        $this->transactionManager->expects($this->never())->method('commit');
        $this->transactionManager->expects($this->once())->method('rollback');

        $this->contactUsMapper
            ->method('insert')
            ->willThrowException(new \RuntimeException('DB error'));

        $result = $this->service->insert($contact);

        $this->assertNull($result);
    }

    // ─── checkRateLimit ──────────────────────────────────────────────

    public function testCheckRateLimitReturnsTrueWhenAllowed(): void
    {
        $this->transactionManager->expects($this->once())->method('beginTransaction');
        $this->transactionManager->expects($this->once())->method('commit');

        $this->contactUsMapper
            ->method('checkRateLimit')
            ->willReturn(true);

        $this->assertTrue($this->service->checkRateLimit('192.168.1.1'));
    }

    public function testCheckRateLimitReturnsFalseWhenLimited(): void
    {
        $this->transactionManager->expects($this->once())->method('beginTransaction');
        $this->transactionManager->expects($this->once())->method('rollback');
        $this->transactionManager->expects($this->never())->method('commit');

        $this->contactUsMapper
            ->method('checkRateLimit')
            ->willReturn(false);

        $this->assertFalse($this->service->checkRateLimit('192.168.1.1'));
    }

    public function testCheckRateLimitReturnsFalseOnException(): void
    {
        $this->transactionManager->expects($this->once())->method('beginTransaction');
        $this->transactionManager->expects($this->once())->method('rollback');

        $this->contactUsMapper
            ->method('checkRateLimit')
            ->willThrowException(new \RuntimeException('DB error'));

        $this->assertFalse($this->service->checkRateLimit('10.0.0.1'));
    }

    // ─── loadById ────────────────────────────────────────────────────

    public function testLoadByIdRejectsUnauthenticatedUser(): void
    {
        $result = $this->service->loadById('id', '1');

        $this->assertSame('error', $result['status']);
        $this->assertSame('60501', $result['ResponseCode']);
    }

    public function testLoadByIdRejectsInvalidType(): void
    {
        $this->service->setCurrentUserId('some-user');

        $result = $this->service->loadById('invalid', '1');

        $this->assertSame('error', $result['status']);
        $this->assertSame('30105', $result['ResponseCode']);
    }

    public function testLoadByIdRejectsEmptyValue(): void
    {
        $this->service->setCurrentUserId('some-user');

        $result = $this->service->loadById('id', '');

        $this->assertSame('error', $result['status']);
        $this->assertSame('30102', $result['ResponseCode']);
    }

    public function testLoadByIdRejectsNonDigitValueForIdType(): void
    {
        $this->service->setCurrentUserId('some-user');

        $result = $this->service->loadById('id', 'abc');

        $this->assertSame('error', $result['status']);
        $this->assertSame('30105', $result['ResponseCode']);
    }

    public function testLoadByIdReturnsNotFoundWhenMapperReturnsNull(): void
    {
        $this->service->setCurrentUserId('some-user');

        $this->contactUsMapper
            ->method('loadById')
            ->willReturn(null);

        $result = $this->service->loadById('id', '999');

        $this->assertSame('error', $result['status']);
        $this->assertSame('40401', $result['ResponseCode']);
    }

    public function testLoadByIdSucceedsWithValidIdType(): void
    {
        $this->service->setCurrentUserId('some-user');

        $contact = new Contactus([
            'msgid' => 1,
            'email' => 'test@example.com',
            'name' => 'Found User',
            'message' => 'Hello',
            'ip' => '127.0.0.1',
            'createdat' => '2025-01-01 00:00:00.000000',
        ], [], false);

        $this->contactUsMapper
            ->method('loadById')
            ->willReturn($contact);

        $result = $this->service->loadById('id', '1');

        $this->assertArrayHasKey('msgid', $result);
        $this->assertSame(1, $result['msgid']);
    }

    public function testLoadByIdSucceedsWithNameType(): void
    {
        $this->service->setCurrentUserId('some-user');

        $contact = new Contactus([
            'msgid' => 2,
            'email' => 'name@example.com',
            'name' => 'Named User',
            'message' => 'Hi',
            'ip' => '127.0.0.1',
            'createdat' => '2025-01-01 00:00:00.000000',
        ], [], false);

        $this->contactUsMapper
            ->method('loadByName')
            ->willReturn($contact);

        $result = $this->service->loadById('name', 'Named User');

        $this->assertArrayHasKey('name', $result);
        $this->assertSame('Named User', $result['name']);
    }

    // ─── fetchAll ────────────────────────────────────────────────────

    public function testFetchAllRejectsUnauthenticatedUser(): void
    {
        $result = $this->service->fetchAll(['limit' => 10]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('60501', $result['ResponseCode']);
    }

    public function testFetchAllRejectsEmptyArgs(): void
    {
        $this->service->setCurrentUserId('some-user');

        $result = $this->service->fetchAll([]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30101', $result['ResponseCode']);
    }

    public function testFetchAllReturnsNotFoundWhenEmpty(): void
    {
        $this->service->setCurrentUserId('some-user');

        $this->contactUsMapper
            ->method('fetchAll')
            ->willReturn([]);

        $result = $this->service->fetchAll(['limit' => 10]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('40401', $result['ResponseCode']);
    }

    public function testFetchAllReturnsResultsOnSuccess(): void
    {
        $this->service->setCurrentUserId('some-user');

        $contact = new Contactus([
            'msgid' => 3,
            'email' => 'all@example.com',
            'name' => 'All User',
            'message' => 'Msg',
            'ip' => '127.0.0.1',
            'createdat' => '2025-01-01 00:00:00.000000',
        ], [], false);

        $this->contactUsMapper
            ->method('fetchAll')
            ->willReturn([$contact]);

        $result = $this->service->fetchAll(['limit' => 10]);

        $this->assertIsArray($result);
        $this->assertCount(1, $result);
        $this->assertSame('All User', $result[0]['name']);
    }
}
