pragma circom 2.1.6;

// VC-gated, rate-limited posting (one proof per post).
// The leaf is a commitment to a holder-bound credential; the posting limit is computed here from the
// hidden attributes under the community's public policy; the share/nullifier relations follow RLN v2
// (a1 = H(s, E, j), y = s + a1*x, nullifier = H(a1), j < limit).

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

// Root of a binary Poseidon tree; pathIndex[i] = 1 when the running node is the right child at level i.
template MerkleRoot(DEPTH) {
    signal input leaf;
    signal input pathElements[DEPTH];
    signal input pathIndex[DEPTH];
    signal output root;

    signal node[DEPTH + 1];
    signal left[DEPTH];
    signal right[DEPTH];
    component h[DEPTH];
    node[0] <== leaf;
    for (var i = 0; i < DEPTH; i++) {
        pathIndex[i] * (pathIndex[i] - 1) === 0;
        left[i] <== node[i] + pathIndex[i] * (pathElements[i] - node[i]);
        right[i] <== node[i] + pathElements[i] - left[i];
        h[i] = Poseidon(2);
        h[i].inputs[0] <== left[i];
        h[i].inputs[1] <== right[i];
        node[i + 1] <== h[i].out;
    }
    root <== node[DEPTH];
}

template VCRLN(DEPTH) {
    // private: holder secret, credential attributes and salt, Merkle path, message index
    signal input secret;
    signal input birthDate;        // days since 1900-01-01
    signal input accountCreated;   // days since 1900-01-01
    signal input verifiedHuman;    // v: 0 or 1, the issuer's account check (e.g. a mobile number), not proof of a unique person
    signal input salt;
    signal input pathElements[DEPTH];
    signal input pathIndex[DEPTH];
    signal input messageId;

    // public: issuer root and schema, epoch and community, post hash, community policy
    signal input root;
    signal input schema;
    signal input epoch;
    signal input community;
    signal input x;
    signal input ageCutoff;        // latest admissible birth date (age gate)
    signal input seniorityCutoff;  // accounts created on or before this date count as senior
    signal input baseLimit;
    signal input verifiedBonus;
    signal input seniorityBonus;
    signal input mode;             // 0 anonymous, 1 pseudonymous

    signal output y;
    signal output nullifier;
    signal output pseudonym;

    // 1. holder-bound credential leaf and membership in the issuer's tree
    component idc = Poseidon(1);
    idc.inputs[0] <== secret;
    component leafH = Poseidon(6);
    leafH.inputs[0] <== schema;
    leafH.inputs[1] <== idc.out;
    leafH.inputs[2] <== birthDate;
    leafH.inputs[3] <== accountCreated;
    leafH.inputs[4] <== verifiedHuman;
    leafH.inputs[5] <== salt;
    component mr = MerkleRoot(DEPTH);
    mr.leaf <== leafH.out;
    for (var i = 0; i < DEPTH; i++) {
        mr.pathElements[i] <== pathElements[i];
        mr.pathIndex[i] <== pathIndex[i];
    }
    root === mr.root;

    // 2. ranges (comparators below are only sound for inputs inside these widths) and booleans
    component rb = Num2Bits(20);  rb.in <== birthDate;
    component rt = Num2Bits(20);  rt.in <== accountCreated;
    component ra = Num2Bits(20);  ra.in <== ageCutoff;
    component rs = Num2Bits(20);  rs.in <== seniorityCutoff;
    component rj = Num2Bits(16);  rj.in <== messageId;
    verifiedHuman * (verifiedHuman - 1) === 0;
    mode * (mode - 1) === 0;

    // 3. policy: age gate, seniority bit, limit from the hidden attributes, message index below the limit
    component ageOk = LessEqThan(20);
    ageOk.in[0] <== birthDate;
    ageOk.in[1] <== ageCutoff;
    ageOk.out === 1;
    component senior = LessEqThan(20);
    senior.in[0] <== accountCreated;
    senior.in[1] <== seniorityCutoff;
    signal vb <== verifiedBonus * verifiedHuman;
    signal sb <== seniorityBonus * senior.out;
    signal limit <== baseLimit + vb + sb;
    component rk = Num2Bits(16);  rk.in <== limit;
    component jOk = LessThan(16);
    jOk.in[0] <== messageId;
    jOk.in[1] <== limit;
    jOk.out === 1;

    // 4. RLN v2 share and nullifier; the external nullifier is bound to (epoch, community) here
    component ext = Poseidon(2);
    ext.inputs[0] <== epoch;
    ext.inputs[1] <== community;
    component a1H = Poseidon(3);
    a1H.inputs[0] <== secret;
    a1H.inputs[1] <== ext.out;
    a1H.inputs[2] <== messageId;
    y <== secret + a1H.out * x;
    component nH = Poseidon(1);
    nH.inputs[0] <== a1H.out;
    nullifier <== nH.out;

    // 5. optional per-community pseudonym (0 in anonymous mode)
    component pH = Poseidon(2);
    pH.inputs[0] <== secret;
    pH.inputs[1] <== community;
    pseudonym <== mode * pH.out;
}
