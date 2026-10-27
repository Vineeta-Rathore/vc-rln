// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./IssuerRootRegistry.sol";

interface IPostVerifier {
    function verifyProof(uint256[2] calldata a, uint256[2][2] calldata b, uint256[2] calldata c, uint256[14] calldata pub)
        external view returns (bool);
}

/// Cost baseline only: one community whose posts are verified on-chain. The design verifies posts off-chain;
/// this contract measures what on-chain verification would cost per post. Public signals follow the circuit:
/// [y, nullifier, pseudonym, root, schema, epoch, community, x, ageCutoff, seniorityCutoff, baseLimit,
///  verifiedBonus, seniorityBonus, mode].
contract PostBoard {
    IssuerRootRegistry public immutable registry;
    IPostVerifier public immutable verifier;
    address public immutable issuer;
    uint256 public immutable window;
    uint256 public immutable epochLength;
    bytes32 public immutable policyHash;  // keccak of (schema, community, ageCutoff, seniorityCutoff, limits, mode)
    mapping(uint256 => uint256) public shareX;  // nullifier => x of the accepted post (0 = unused)

    event Posted(uint256 indexed nullifier, uint256 epoch, uint256 x, uint256 y, uint256 pseudonym);

    constructor(IssuerRootRegistry r, IPostVerifier v, address issuer_, uint256 window_, uint256 epochLength_, bytes32 policyHash_) {
        registry = r;
        verifier = v;
        issuer = issuer_;
        window = window_;
        epochLength = epochLength_;
        policyHash = policyHash_;
    }

    /// `slot` is the ring slot of the root the proof was made against (registry.currentSlot at proving time).
    function post(uint256[2] calldata a, uint256[2][2] calldata b, uint256[2] calldata c, uint256[14] calldata pub, uint256 slot) external {
        require(keccak256(abi.encode(pub[4], pub[6], pub[8], pub[9], pub[10], pub[11], pub[12], pub[13])) == policyHash, "policy");
        require(pub[5] == block.timestamp / epochLength, "epoch");
        require(registry.isAcceptableAt(issuer, pub[3], slot, window), "root");
        require(pub[7] != 0, "x");  // x = 0 would leave the nullifier marked unused (0 is the empty value below)
        require(shareX[pub[1]] == 0, "nullifier used");  // a second share would reveal the secret off-chain
        require(verifier.verifyProof(a, b, c, pub), "proof");
        shareX[pub[1]] = pub[7];
        emit Posted(pub[1], pub[5], pub[7], pub[0], pub[2]);
    }
}
