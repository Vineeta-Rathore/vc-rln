#!/usr/bin/env bash
# Compile the post circuit at each tree depth and the reference RLN v2 circuit, then run the Groth16
# setup: phase 1 from the PSE perpetual powers of tau (contribution 0080, 2^15), phase 2 with one local
# contribution. Writes build/<name>/{c.r1cs, c_js/c.wasm, c.zkey, vkey.json, info.json}. A fresh run draws new
# phase-2 randomness, so its keys differ from the published ones; to check the published keys instead run
#   node node_modules/snarkjs/build/cli.cjs zkey verify build/vcrln_d20/c.r1cs ptau/ppot_0080_15.ptau build/vcrln_d20/c.zkey
#   DEPTHS="10 16 20 24 32" bash scripts/build.sh
set -euo pipefail
cd "$(dirname "$0")/.."
CIRCOM="${CIRCOM:-circom}"   # circom 2.2.3 (https://github.com/iden3/circom)
SNARKJS="node node_modules/snarkjs/build/cli.cjs"
PTAU=ptau/ppot_0080_15.ptau
PTAU_URL=https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_15.ptau
PTAU_SHA256=4a8eb5a754ed4710d6ad603c2e1a89c72325a448e4474f8694d2c71c7c272f3d
DEPTHS="${DEPTHS:-10 16 20 24 32}"

if [ ! -f "$PTAU" ]; then mkdir -p ptau; curl -fL -o "$PTAU" "$PTAU_URL"; fi
SHA="$(command -v sha256sum || echo "shasum -a 256")"
echo "$PTAU_SHA256  $PTAU" | $SHA -c -

build_one() {  # name main.circom
  local name=$1 main=$2 out=build/$1
  mkdir -p "$out"; rm -f "$out"/*.r1cs "$out/c.zkey" "$out/c_0.zkey"  # replaces the shipped depth-20 build
  "$CIRCOM" "$main" --r1cs --wasm --O2 -l node_modules -l circuits -l circuits/baseline -o "$out" > "$out/compile.log"
  mv "$out"/*.r1cs "$out/c.r1cs"; rm -rf "$out/c_js"; mv "$out"/*_js "$out/c_js"; mv "$out/c_js/"*.wasm "$out/c_js/c.wasm"
  $SNARKJS r1cs info "$out/c.r1cs" > "$out/r1cs_info.log"
  $SNARKJS groth16 setup "$out/c.r1cs" "$PTAU" "$out/c_0.zkey" > /dev/null
  $SNARKJS zkey contribute "$out/c_0.zkey" "$out/c.zkey" --name="IC4 phase 2" -e="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" > /dev/null
  rm "$out/c_0.zkey"
  $SNARKJS zkey export verificationkey "$out/c.zkey" "$out/vkey.json" > /dev/null
  node -e '
    const fs=require("fs"); const log=fs.readFileSync(process.argv[1]+"/r1cs_info.log","utf8");
    const g=k=>{const m=log.match(new RegExp("# of "+k+": (\\d+)")); return m?Number(m[1]):null};
    const zk=fs.statSync(process.argv[1]+"/c.zkey").size, wasm=fs.statSync(process.argv[1]+"/c_js/c.wasm").size;
    const info={name:process.argv[2], constraints:g("Constraints"), wires:g("Wires"), privateInputs:g("Private Inputs"),
      publicInputs:g("Public Inputs"), outputs:g("Outputs"), zkeyBytes:zk, wasmBytes:wasm};
    fs.writeFileSync(process.argv[1]+"/info.json", JSON.stringify(info,null,1)); console.log(JSON.stringify(info));
  ' "$out" "$name"
}

for d in $DEPTHS; do
  printf 'pragma circom 2.1.6;\ninclude "vcrln.circom";\ncomponent main {public [root, schema, epoch, community, x, ageCutoff, seniorityCutoff, baseLimit, verifiedBonus, seniorityBonus, mode]} = VCRLN(%s);\n' "$d" > "build/main_vcrln_d$d.circom"
  build_one "vcrln_d$d" "build/main_vcrln_d$d.circom"
done
build_one "rln2_d20" circuits/baseline/rln.circom
