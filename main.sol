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
