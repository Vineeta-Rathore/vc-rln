// Offline CLI regressions: invalid inputs must stop before cryptographic or RPC initialization.
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const script = path.join(__dirname, "rebuild_tree.js");
const registries = require("../data/registries.json");

function run(args, extraEnv = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    encoding: "utf8", timeout: 10000, env: { ...process.env, LOG_STEP: "2000", ...extraEnv },
  });
}

test("an unknown network cannot produce a successful empty verification", () => {
  const result = run(["not-a-network"]);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /No registry selected/);
  for (const entry of registries) assert.ok(result.stderr.includes(entry.network));
});

test("invalid log steps fail before hasher or RPC work", () => {
  assert.ok(registries.length > 0);
  for (const value of ["0", "-1", "1.5", "NaN", "Infinity", "9007199254740992"]) {
    const result = run([registries[0].network], { LOG_STEP: value });
    assert.equal(result.error, undefined, value);
    assert.equal(result.status, 1, value);
    assert.match(result.stderr, /LOG_STEP must be a positive safe integer/);
  }
});
