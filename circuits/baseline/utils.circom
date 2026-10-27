// Reference RLN v2 circuit from https://github.com/Rate-Limiting-Nullifier/circom-rln (commit 17f0fed7d8d19e8b127fd0b3e5295a4831193a0d),
// dual-licensed Apache-2.0 / MIT. Used unchanged as the baseline; only the circomlib include paths are rewritten.
pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

template MerkleTreeInclusionProof(DEPTH) {
    signal input leaf;
    signal input pathIndex[DEPTH];
    signal input pathElements[DEPTH];

    signal output root;

    signal mux[DEPTH][2];
    signal levelHashes[DEPTH + 1];
    
    levelHashes[0] <== leaf;
    for (var i = 0; i < DEPTH; i++) {
        pathIndex[i] * (pathIndex[i] - 1) === 0;

        mux[i] <== MultiMux1(2)(
            [
                [levelHashes[i], pathElements[i]], 
                [pathElements[i], levelHashes[i]]
            ], 
            pathIndex[i]
        );

        levelHashes[i + 1] <== Poseidon(2)([mux[i][0], mux[i][1]]);
    }

    root <== levelHashes[DEPTH];
}

template RangeCheck(LIMIT_BIT_SIZE) {
    assert(LIMIT_BIT_SIZE < 253);

    signal input messageId;
    signal input limit;

    signal bitCheck[LIMIT_BIT_SIZE] <== Num2Bits(LIMIT_BIT_SIZE)(messageId);
    signal rangeCheck <== LessThan(LIMIT_BIT_SIZE)([messageId, limit]);
    rangeCheck === 1;
}