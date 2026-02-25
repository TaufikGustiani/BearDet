// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BearDet
/// @notice Tracks drawdowns and bear-market indicators; emits exit advisories when thresholds are crossed. Helps dashboards and bots decide when to reduce exposure.
/// @dev Salt: 0xd4f6a8c0e2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0

import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/ReentrancyGuard.sol";
import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/access/Ownable.sol";

contract BearDet is ReentrancyGuard, Ownable {

    event ExitSignalRaised(
        uint256 indexed signalId,
        uint8 indicatorId,
        uint256 value,
        uint256 threshold,
        bytes32 labelHash,
        uint256 atBlock
    );
    event DrawdownRecorded(
        uint256 indexed snapshotId,
        address indexed reporter,
        uint256 drawdownBps,
        uint256 peakValue,
        uint256 currentValue,
        uint256 atBlock
    );
    event ExitAdvisoryPosted(
        uint256 indexed advisoryId,
        address indexed by,
        uint8 severity,
        uint256 atBlock
    );
    event BearIndicatorUpdated(
        uint8 indexed indicatorId,
        uint256 previousValue,
        uint256 newValue,
        uint256 atBlock
    );
    event GuardianSet(address indexed previous, address indexed current);
    event ReporterSet(address indexed previous, address indexed current);
    event TreasurySet(address indexed previous, address indexed current);
    event DrawdownThresholdSet(uint256 previousBps, uint256 newBps);
    event HaltToggled(bool halted);
    event FeeCollected(address indexed from, uint256 amountWei);
    event TreasuryWithdrawn(address indexed to, uint256 amountWei);
    event SnapshotBatchRecorded(uint256 count, address indexed reporter, uint256 atBlock);
    event IndicatorThresholdSet(uint8 indexed indicatorId, uint256 threshold);
    event ExitScoreComputed(uint256 snapshotId, uint256 scoreBps, uint256 atBlock);
    event ReporterFeeSet(uint256 previousWei, uint256 newWei);
    event AdvisoryAcknowledged(uint256 indexed advisoryId, address indexed by);

    error BRD_ZeroAddress();
    error BRD_ZeroAmount();
    error BRD_Halted();
    error BRD_NotGuardian();
    error BRD_NotReporter();
    error BRD_TransferFailed();
    error BRD_DrawdownOutOfRange();
    error BRD_IndicatorOutOfRange();
    error BRD_SeverityOutOfRange();
    error BRD_ThresholdInvalid();
    error BRD_SnapshotNotFound();
    error BRD_MaxSnapshotsReached();
    error BRD_ArrayLengthMismatch();
    error BRD_BatchTooLarge();
    error BRD_WithdrawZero();
    error BRD_MaxSignalsReached();
    error BRD_InvalidIndicatorId();
    error BRD_InvalidIndex();
    error BRD_AdvisoryNotFound();
    error BRD_SignalNotFound();

    uint256 public constant BRD_BPS_DENOM = 10000;
    uint256 public constant BRD_MAX_INDICATORS = 16;
    uint256 public constant BRD_MAX_SEVERITY = 5;
    uint256 public constant BRD_MAX_DRAWDOWN_BPS = 10000;
    uint256 public constant BRD_MAX_SNAPSHOTS = 50000;
    uint256 public constant BRD_MAX_SIGNALS = 2000;
    uint256 public constant BRD_BATCH_SIZE = 100;
    uint256 public constant BRD_DOMAIN_SALT = 0xd4f6a8c0e2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0;

    address public immutable brdTreasury;
    uint256 public immutable deployBlock;
    bytes32 public immutable chainDomain;

    address public brdGuardian;
    address public brdReporter;
    bool public brdHalted;
    uint256 public drawdownThresholdBps;
    uint256 public snapshotCounter;
    uint256 public signalCounter;
    uint256 public advisoryCounter;
    uint256 public treasuryBalance;
    uint256 public reporterFeeWei;
    mapping(uint8 => uint256) public indicatorThreshold;

    struct DrawdownSnapshot {
        address reporter;
        uint256 drawdownBps;
        uint256 peakValue;
        uint256 currentValue;
        uint256 atBlock;
    }

    struct ExitSignal {
        uint8 indicatorId;
        uint256 value;
        uint256 threshold;
        bytes32 labelHash;
        uint256 atBlock;
    }

    struct ExitAdvisory {
        address author;
        uint8 severity;
        uint256 atBlock;
    }

    mapping(uint256 => DrawdownSnapshot) public snapshots;
    mapping(uint256 => ExitSignal) public signals;
    mapping(uint256 => ExitAdvisory) public advisories;
    mapping(uint8 => uint256) public latestIndicatorValue;
    uint256[] private _snapshotIds;
    uint256[] private _signalIds;
    uint256[] private _advisoryIds;

    modifier whenNotHalted() {
        if (brdHalted) revert BRD_Halted();
        _;
    }

    modifier onlyGuardian() {
        if (msg.sender != brdGuardian && msg.sender != owner()) revert BRD_NotGuardian();
        _;
    }

    modifier onlyReporter() {
        if (msg.sender != brdReporter && msg.sender != owner()) revert BRD_NotReporter();
        _;
    }

    constructor() Ownable(msg.sender) {
        brdTreasury = address(0x3c5e7a9b1d4f6a8c0e2a4b6c8d0e2f4a6b8c0d2e);
        brdGuardian = address(0x6f2b4d8a0c2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a);
        brdReporter = address(0x9a1c3e5b7d9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b);
        deployBlock = block.number;
        chainDomain = keccak256(abi.encodePacked("BearDet.exit", block.chainid, deployBlock));
        drawdownThresholdBps = 1500;
    }

    function setHalted(bool halted) external onlyOwner {
        brdHalted = halted;
        emit HaltToggled(halted);
    }

    function setGuardian(address newGuardian) external onlyOwner {
        if (newGuardian == address(0)) revert BRD_ZeroAddress();
        address prev = brdGuardian;
        brdGuardian = newGuardian;
        emit GuardianSet(prev, newGuardian);
    }

    function setReporter(address newReporter) external onlyOwner {
        if (newReporter == address(0)) revert BRD_ZeroAddress();
        address prev = brdReporter;
        brdReporter = newReporter;
