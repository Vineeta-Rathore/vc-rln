// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC1056 {
    function identityOwner(address identity) external view returns (address);
}

/// Roots of each issuer's credential tree. An issuer is a did:ethr identity, and only its current ERC-1056
/// owner can publish, so a DID key rotation moves the publishing right with it. Added leaves and revoked
/// indices are emitted as events: anyone can rebuild the tree from the log and check every root.
/// The last HISTORY roots are kept in a fixed ring, so after the first HISTORY publications an update only
/// overwrites existing slots and adds no state (relevant under state-creation pricing, EIP-8037). A verifier
/// accepts a root while it is in the ring and was superseded less than its own window ago.
contract IssuerRootRegistry {
    uint256 public constant HISTORY = 16;

    struct Entry {
        uint256 root;
        uint64 publishedAt;
        uint64 supersededAt;
    }

    struct Issuer {
        uint64 leafCount;
        uint64 publications;
        Entry[16] ring;
    }

    IERC1056 public immutable didRegistry;
    mapping(address => Issuer) internal issuers;

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
        Issuer storage s = issuers[issuer];
        uint256 first = s.leafCount;
        s.leafCount = uint64(first + leaves.length);
        _publish(s, newRoot);
        emit LeavesAdded(issuer, first, leaves, newRoot);
    }

    function revokeLeaves(address issuer, uint256[] calldata indices, uint256 newRoot) external onlyIssuer(issuer) {
        Issuer storage s = issuers[issuer];
        uint256 n = s.leafCount;
        for (uint256 i = 0; i < indices.length; i++) require(indices[i] < n, "no such leaf");
        _publish(s, newRoot);
        emit LeavesRevoked(issuer, indices, newRoot);
    }

    function currentRoot(address issuer) external view returns (uint256) {
        Issuer storage s = issuers[issuer];
        return s.publications == 0 ? 0 : s.ring[(s.publications - 1) % HISTORY].root;
    }

    function leafCount(address issuer) external view returns (uint256) {
        return issuers[issuer].leafCount;
    }

    /// Ring slot holding the current root (a hint for contracts that check one slot).
    function currentSlot(address issuer) external view returns (uint256) {
        return (issuers[issuer].publications - 1) % HISTORY;
    }

    /// For off-chain verifiers: is `root` among the last HISTORY roots and superseded less than `window` s ago?
    function isAcceptable(address issuer, uint256 root, uint256 window) external view returns (bool) {
        Issuer storage s = issuers[issuer];
        uint256 p = s.publications;
        uint256 k = p < HISTORY ? p : HISTORY;
        for (uint256 i = 0; i < k; i++) {
            Entry storage e = s.ring[(p - 1 - i) % HISTORY];
            if (e.root == root) return _fresh(e, window);
        }
        return false;
    }

    /// For contracts: the same check against one ring slot.
    function isAcceptableAt(address issuer, uint256 root, uint256 slot, uint256 window) external view returns (bool) {
        Entry storage e = issuers[issuer].ring[slot % HISTORY];
        return e.publishedAt != 0 && e.root == root && _fresh(e, window);
    }

    function _fresh(Entry storage e, uint256 window) internal view returns (bool) {
        return e.supersededAt == 0 || block.timestamp < uint256(e.supersededAt) + window;
    }

    function _publish(Issuer storage s, uint256 newRoot) internal {
        uint256 p = s.publications;
        if (p > 0) s.ring[(p - 1) % HISTORY].supersededAt = uint64(block.timestamp);
        s.ring[p % HISTORY] = Entry(newRoot, uint64(block.timestamp), 0);
        s.publications = uint64(p + 1);
    }
}
