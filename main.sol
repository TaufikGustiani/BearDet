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
        emit ReporterSet(prev, newReporter);
    }

    function setDrawdownThresholdBps(uint256 newBps) external onlyGuardian {
        if (newBps > BRD_MAX_DRAWDOWN_BPS) revert BRD_ThresholdInvalid();
        uint256 prev = drawdownThresholdBps;
        drawdownThresholdBps = newBps;
        emit DrawdownThresholdSet(prev, newBps);
    }

    function updateIndicator(uint8 indicatorId, uint256 value) external onlyReporter whenNotHalted {
        if (indicatorId >= BRD_MAX_INDICATORS) revert BRD_InvalidIndicatorId();
        uint256 prev = latestIndicatorValue[indicatorId];
        latestIndicatorValue[indicatorId] = value;
        emit BearIndicatorUpdated(indicatorId, prev, value, block.number);
    }

    function recordDrawdown(uint256 drawdownBps, uint256 peakValue, uint256 currentValue) external onlyReporter whenNotHalted returns (uint256 snapshotId) {
        if (drawdownBps > BRD_MAX_DRAWDOWN_BPS) revert BRD_DrawdownOutOfRange();
        if (_snapshotIds.length >= BRD_MAX_SNAPSHOTS) revert BRD_MaxSnapshotsReached();

        snapshotCounter++;
        snapshotId = snapshotCounter;
        snapshots[snapshotId] = DrawdownSnapshot({
            reporter: msg.sender,
            drawdownBps: drawdownBps,
            peakValue: peakValue,
            currentValue: currentValue,
            atBlock: block.number
        });
        _snapshotIds.push(snapshotId);
        emit DrawdownRecorded(snapshotId, msg.sender, drawdownBps, peakValue, currentValue, block.number);

        if (drawdownBps >= drawdownThresholdBps && _signalIds.length < BRD_MAX_SIGNALS) {
            signalCounter++;
            uint256 sigId = signalCounter;
            signals[sigId] = ExitSignal({
                indicatorId: 0,
                value: drawdownBps,
                threshold: drawdownThresholdBps,
                labelHash: keccak256("BearDet.drawdown"),
                atBlock: block.number
            });
            _signalIds.push(sigId);
            emit ExitSignalRaised(sigId, 0, drawdownBps, drawdownThresholdBps, keccak256("BearDet.drawdown"), block.number);
        }
        return snapshotId;
    }

    function raiseExitSignal(uint8 indicatorId, uint256 value, uint256 threshold, bytes32 labelHash) external onlyReporter whenNotHalted returns (uint256 signalId) {
        if (indicatorId >= BRD_MAX_INDICATORS) revert BRD_InvalidIndicatorId();
        if (value > BRD_BPS_DENOM * 100) revert BRD_IndicatorOutOfRange();
        if (_signalIds.length >= BRD_MAX_SIGNALS) revert BRD_MaxSignalsReached();

        signalCounter++;
        signalId = signalCounter;
        signals[signalId] = ExitSignal({ indicatorId: indicatorId, value: value, threshold: threshold, labelHash: labelHash, atBlock: block.number });
        _signalIds.push(signalId);
        emit ExitSignalRaised(signalId, indicatorId, value, threshold, labelHash, block.number);
        return signalId;
    }

    function postExitAdvisory(uint8 severity) external onlyReporter whenNotHalted returns (uint256 advisoryId) {
        if (severity > BRD_MAX_SEVERITY) revert BRD_SeverityOutOfRange();
        advisoryCounter++;
        advisoryId = advisoryCounter;
        advisories[advisoryId] = ExitAdvisory({ author: msg.sender, severity: severity, atBlock: block.number });
        _advisoryIds.push(advisoryId);
        emit ExitAdvisoryPosted(advisoryId, msg.sender, severity, block.number);
        return advisoryId;
    }

    function recordDrawdownBatch(
        uint256[] calldata drawdownBpsList,
        uint256[] calldata peakValues,
        uint256[] calldata currentValues
    ) external onlyReporter whenNotHalted returns (uint256[] memory snapshotIds) {
        uint256 n = drawdownBpsList.length;
        if (n == 0 || n > BRD_BATCH_SIZE || peakValues.length != n || currentValues.length != n) revert BRD_ArrayLengthMismatch();
        if (_snapshotIds.length + n > BRD_MAX_SNAPSHOTS) revert BRD_MaxSnapshotsReached();

        snapshotIds = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            if (drawdownBpsList[i] > BRD_MAX_DRAWDOWN_BPS) revert BRD_DrawdownOutOfRange();
            snapshotCounter++;
            uint256 sid = snapshotCounter;
            snapshots[sid] = DrawdownSnapshot({
                reporter: msg.sender,
                drawdownBps: drawdownBpsList[i],
                peakValue: peakValues[i],
                currentValue: currentValues[i],
                atBlock: block.number
            });
            _snapshotIds.push(sid);
            snapshotIds[i] = sid;
            emit DrawdownRecorded(sid, msg.sender, drawdownBpsList[i], peakValues[i], currentValues[i], block.number);
        }
        emit SnapshotBatchRecorded(n, msg.sender, block.number);
        return snapshotIds;
    }

    /// @notice Fetch a single drawdown snapshot by id.
    function getSnapshot(uint256 snapshotId) external view returns (address reporter, uint256 drawdownBps, uint256 peakValue, uint256 currentValue, uint256 atBlock) {
        DrawdownSnapshot storage s = snapshots[snapshotId];
        if (s.atBlock == 0) revert BRD_SnapshotNotFound();
        return (s.reporter, s.drawdownBps, s.peakValue, s.currentValue, s.atBlock);
    }

    function getSignal(uint256 signalId) external view returns (uint8 indicatorId, uint256 value, uint256 threshold, bytes32 labelHash, uint256 atBlock) {
        ExitSignal storage s = signals[signalId];
        if (s.atBlock == 0) revert BRD_SnapshotNotFound();
        return (s.indicatorId, s.value, s.threshold, s.labelHash, s.atBlock);
    }

    function getAdvisory(uint256 advisoryId) external view returns (address author, uint8 severity, uint256 atBlock) {
        ExitAdvisory storage a = advisories[advisoryId];
        if (a.atBlock == 0) revert BRD_SnapshotNotFound();
        return (a.author, a.severity, a.atBlock);
    }

    function snapshotCount() external view returns (uint256) {
        return _snapshotIds.length;
    }

    function signalCount() external view returns (uint256) {
        return _signalIds.length;
    }

    function advisoryCount() external view returns (uint256) {
        return _advisoryIds.length;
    }

    function getSnapshotIdAt(uint256 index) external view returns (uint256) {
        if (index >= _snapshotIds.length) revert BRD_ThresholdInvalid();
        return _snapshotIds[index];
    }

    function getSignalIdAt(uint256 index) external view returns (uint256) {
        if (index >= _signalIds.length) revert BRD_ThresholdInvalid();
        return _signalIds[index];
    }

    function getAdvisoryIdAt(uint256 index) external view returns (uint256) {
        if (index >= _advisoryIds.length) revert BRD_ThresholdInvalid();
        return _advisoryIds[index];
    }

    function isExitSignalActive() external view returns (bool) {
        if (_signalIds.length == 0) return false;
        uint256 lastId = _signalIds[_signalIds.length - 1];
        ExitSignal storage s = signals[lastId];
        return s.value >= drawdownThresholdBps;
    }

    function recentSignals(uint256 limit) external view returns (uint256[] memory ids, uint256[] memory values, uint256[] memory blocks) {
        uint256 n = _signalIds.length;
        if (limit > n) limit = n;
        if (limit == 0) return (new uint256[](0), new uint256[](0), new uint256[](0));
        ids = new uint256[](limit);
        values = new uint256[](limit);
        blocks = new uint256[](limit);
        for (uint256 i = 0; i < limit; i++) {
            uint256 idx = n - 1 - i;
            uint256 id = _signalIds[idx];
            ids[i] = id;
            values[i] = signals[id].value;
            blocks[i] = signals[id].atBlock;
        }
