<?php

declare(strict_types=1);

namespace Tests\Unit;

use Fawaz\App\WalletService;
use Fawaz\App\UserService;
use Fawaz\App\Wallet;
use Fawaz\Database\PeerTokenMapper;
use Fawaz\Database\UserMapper;
use Fawaz\Database\WalletMapper;
use Fawaz\Database\Interfaces\TransactionManager;
use Fawaz\Services\TokenTransfer\Fees\FeePolicyMode;
use Fawaz\Services\TokenTransfer\Strategies\TransferStrategy;
use Fawaz\Utils\PeerLoggerInterface;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for WalletService.
 *
 * Covers authentication gating, UUID validation, payment flow,
 * and day-value validation for wins/pays logs.
 */
final class WalletServiceTest extends TestCase
{
    private const VALID_UUID = '550e8400-e29b-41d4-a716-446655440000';
    private const INVALID_UUID = 'not-a-uuid';

    private PeerLoggerInterface $logger;
    private WalletMapper $walletMapper;
    private UserMapper $userMapper;
    private UserService $userService;
    private PeerTokenMapper $peerTokenMapper;
    private TransactionManager $transactionManager;
    private WalletService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->logger = $this->createMock(PeerLoggerInterface::class);
        $this->walletMapper = $this->createMock(WalletMapper::class);
        $this->userMapper = $this->createMock(UserMapper::class);
        $this->userService = $this->createMock(UserService::class);
        $this->peerTokenMapper = $this->createMock(PeerTokenMapper::class);
        $this->transactionManager = $this->createMock(TransactionManager::class);

        $this->service = new WalletService(
            $this->logger,
            $this->walletMapper,
            $this->userMapper,
            $this->userService,
            $this->peerTokenMapper,
            $this->transactionManager
        );
    }

    // ─── fetchWalletById: Authentication ─────────────────────────────

    public function testFetchWalletByIdRejectsUnauthenticatedUser(): void
    {
        // currentUserId is null by default
        $result = $this->service->fetchWalletById([]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('60501', $result['ResponseCode']);
    }

    public function testFetchWalletByIdRejectsInvalidUserUUID(): void
    {
        $this->service->setCurrentUserId(self::INVALID_UUID);

        $result = $this->service->fetchWalletById([]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30102', $result['ResponseCode']);
    }

    public function testFetchWalletByIdRejectsInvalidPostId(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $result = $this->service->fetchWalletById(['postid' => self::INVALID_UUID]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30209', $result['ResponseCode']);
    }

    public function testFetchWalletByIdRejectsInvalidFromId(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $result = $this->service->fetchWalletById(['fromid' => self::INVALID_UUID]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30105', $result['ResponseCode']);
    }

    public function testFetchWalletByIdSucceedsWithValidUUID(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $wallet = new Wallet([
            'token' => 'test-token-1',
            'userid' => self::VALID_UUID,
            'postid' => self::VALID_UUID,
            'fromid' => self::VALID_UUID,
            'numbers' => 100.0,
            'numbersq' => 1,
            'whereby' => 2,
            'createdat' => '2025-01-01 00:00:00.000000',
        ], [], false);

        $this->walletMapper
            ->method('loadWalletById')
            ->willReturn([$wallet]);

        $result = $this->service->fetchWalletById([]);

        $this->assertSame('success', $result['status']);
        $this->assertSame('11209', $result['ResponseCode']);
        $this->assertSame(1, $result['counter']);
        $this->assertCount(1, $result['affectedRows']);
    }

    public function testFetchWalletByIdReturnsErrorWhenMapperReturnsFalse(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $this->walletMapper
            ->method('loadWalletById')
            ->willReturn(false);

        $result = $this->service->fetchWalletById([]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('41216', $result['ResponseCode']);
    }

    // ─── callFetchWinsLog / callFetchPaysLog: Day validation ─────────

    public function testCallFetchWinsLogRejectsUnauthenticatedUser(): void
    {
        $result = $this->service->callFetchWinsLog(['day' => 'D0']);

        $this->assertSame('error', $result['status']);
        $this->assertSame('60501', $result['ResponseCode']);
    }

    public function testCallFetchWinsLogRejectsInvalidDay(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $result = $this->service->callFetchWinsLog(['day' => 'INVALID']);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30105', $result['ResponseCode']);
    }

    /** @dataProvider validDaysProvider */
    public function testCallFetchWinsLogAcceptsValidDay(string $day): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $expected = ['status' => 'success', 'ResponseCode' => '11209', 'affectedRows' => []];
        $this->walletMapper
            ->method('fetchWinsLog')
            ->willReturn($expected);

        $result = $this->service->callFetchWinsLog(['day' => $day]);

        $this->assertSame('success', $result['status']);
    }

    public function testCallFetchPaysLogRejectsInvalidDay(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $result = $this->service->callFetchPaysLog(['day' => 'X9']);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30105', $result['ResponseCode']);
    }

    public function testCallFetchPaysLogRejectsUnauthenticatedUser(): void
    {
        $result = $this->service->callFetchPaysLog(['day' => 'D0']);

        $this->assertSame('error', $result['status']);
        $this->assertSame('60501', $result['ResponseCode']);
    }

    // ─── performPayment ──────────────────────────────────────────────

    public function testPerformPaymentRejectsInvalidArtType(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        $strategy = $this->createMock(TransferStrategy::class);
        $result = $this->service->performPayment(self::VALID_UUID, $strategy, ['art' => 999]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('30105', $result['ResponseCode']);
    }

    public function testPerformPaymentRejectsInsufficientBalance(): void
    {
        $this->service->setCurrentUserId(self::VALID_UUID);

        // Wallet balance = 0, price for like (art=2) = 3.0
        $this->walletMapper
            ->method('getUserWalletBalance')
            ->willReturn(0.0);

        $strategy = $this->createMock(TransferStrategy::class);
        $strategy->method('getFeePolicyMode')->willReturn(FeePolicyMode::ADDED);

        $this->peerTokenMapper
            ->method('calculateRequiredAmountByMode')
            ->willReturn('5.0');

        $result = $this->service->performPayment(self::VALID_UUID, $strategy, ['art' => 2]);

        $this->assertSame('error', $result['status']);
        $this->assertSame('51301', $result['ResponseCode']);
    }

    // ─── loadLiquidityById ───────────────────────────────────────────

    public function testLoadLiquidityByIdReturnsSuccess(): void
    {
        $this->walletMapper
            ->method('loadLiquidityById')
            ->willReturn(1000.0);

        $result = $this->service->loadLiquidityById(self::VALID_UUID);

        $this->assertSame('success', $result['status']);
        $this->assertSame('11204', $result['ResponseCode']);
        $this->assertSame(1000.0, $result['currentliquidity']);
    }

    public function testLoadLiquidityByIdReturnsErrorOnException(): void
    {
        $this->walletMapper
            ->method('loadLiquidityById')
            ->willThrowException(new \Exception('DB error'));

        $result = $this->service->loadLiquidityById(self::VALID_UUID);

        $this->assertSame('error', $result['status']);
    }

    // ─── getUserWalletBalance ────────────────────────────────────────

    public function testGetUserWalletBalanceReturnsBalance(): void
    {
        $this->walletMapper
            ->method('getUserWalletBalance')
            ->willReturn(500.0);

        $this->assertSame(500.0, $this->service->getUserWalletBalance(self::VALID_UUID));
    }

    public function testGetUserWalletBalanceReturnsZeroOnException(): void
    {
        $this->walletMapper
            ->method('getUserWalletBalance')
            ->willThrowException(new \Exception('DB error'));

        $this->assertSame(0.0, $this->service->getUserWalletBalance(self::VALID_UUID));
    }

    // ─── Data Providers ──────────────────────────────────────────────

    public static function validDaysProvider(): array
    {
        return [
            ['D0'], ['D1'], ['D2'], ['D3'], ['D4'], ['D5'],
            ['W0'], ['M0'], ['Y0'],
        ];
    }
}
