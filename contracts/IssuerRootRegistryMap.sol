// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC1056 {
    function identityOwner(address identity) external view returns (address);
}

/// Comparison design (one storage slot per published root). Roots of each issuer's credential tree. An issuer is a did:ethr identity, and only its current ERC-1056
/// owner can publish, so a DID key rotation moves the publishing right with it. Added leaves and revoked
/// indices are emitted as events: anyone can rebuild the tree from the log and check every root. Verifiers
/// read the publication times to accept a superseded root for a bounded window.
contract IssuerRootRegistryMap {
    struct RootInfo {
        uint64 publishedAt;
        uint64 supersededAt;
    }

    IERC1056 public immutable didRegistry;
    mapping(address => uint256) public currentRoot;
    mapping(address => uint256) public leafCount;
    mapping(address => mapping(uint256 => RootInfo)) public roots;

    event LeavesAdded(address indexed issuer, uint256 firstIndex, uint256[] leaves, uint256 root);
    event LeavesRevoked(address indexed issuer, uint256[] indices, uint256 root);

    constructor(address registry) {
        didRegistry = IERC1056(registry);
    }

    modifier onlyIssuer(address issuer) {
        require(msg.sender == didRegistry.identityOwner(issuer), "not the issuer's DID owner");
        _;
    }

    function addLeaves(address issuer, uint256[] calldata leaves, uint256 newRoot) external onlyIssuer(issuer) {
        uint256 first = leafCount[issuer];
        leafCount[issuer] = first + leaves.length;
        _setRoot(issuer, newRoot);
        emit LeavesAdded(issuer, first, leaves, newRoot);
    }

    function revokeLeaves(address issuer, uint256[] calldata indices, uint256 newRoot) external onlyIssuer(issuer) {
        uint256 n = leafCount[issuer];
        for (uint256 i = 0; i < indices.length; i++) require(indices[i] < n, "no such leaf");
        _setRoot(issuer, newRoot);
        emit LeavesRevoked(issuer, indices, newRoot);
    }

    /// True if `root` is the issuer's current root or was superseded less than `window` seconds ago.
    function isAcceptable(address issuer, uint256 root, uint256 window) public view returns (bool) {
        RootInfo memory r = roots[issuer][root];
        if (r.publishedAt == 0) return false;
        return r.supersededAt == 0 || block.timestamp < uint256(r.supersededAt) + window;
    }

    function _setRoot(address issuer, uint256 newRoot) internal {
        uint256 old = currentRoot[issuer];
        if (old != 0 && old != newRoot) roots[issuer][old].supersededAt = uint64(block.timestamp);
        roots[issuer][newRoot] = RootInfo(uint64(block.timestamp), 0);
        currentRoot[issuer] = newRoot;
    }
}
