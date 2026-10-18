// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice Experimental audit commitment registry, not a vault or action authorizer.
/// @dev No upgrade, key rotation, external calls, transfers, or raw audit contents.
contract AuditCheckpoint {
    address public immutable publisher;
    bytes32 public immutable producer;
    bytes32 public immutable domain;
    uint64 public lastSequence;
    bytes32 public lastDigest;
    mapping(uint64 => bytes32) public digestAt;

    error InvalidSetup();
    error Unauthorized();
    error ScopeMismatch();
    error InvalidCheckpoint();
    event Checkpoint(uint64 indexed sequence, bytes32 digest, bytes32 previousDigest);

    constructor(address publisher_, bytes32 producer_, bytes32 scope_) {
        if (publisher_ == address(0) || producer_ == bytes32(0) || scope_ == bytes32(0)) revert InvalidSetup();
        publisher = publisher_;
        producer = producer_;
        domain = keccak256(abi.encode("agent-audit-checkpoint/v1", block.chainid, address(this), scope_));
    }

    /// @dev sequence is a batch's last observed event, not a claim that every event exists.
    function append(bytes32 expectedDomain, bytes32 expectedProducer, uint64 sequence,
                    bytes32 previousDigest, bytes32 digest) external {
        if (msg.sender != publisher) revert Unauthorized();
        if (expectedDomain != domain || expectedProducer != producer) revert ScopeMismatch();
        uint64 previousSequence = lastSequence;
        if (sequence <= previousSequence || previousDigest != lastDigest || digest == bytes32(0)) revert InvalidCheckpoint();
        digestAt[sequence] = digest;
        lastSequence = sequence;
        lastDigest = digest;
        emit Checkpoint(sequence, digest, previousDigest);
        assert(lastSequence > previousSequence);
        assert(digestAt[sequence] == digest);
        assert(lastDigest == digest);
    }
}
