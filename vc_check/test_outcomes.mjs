import assert from "node:assert/strict";
import test from "node:test";
import { failedChecks } from "./verification_outcomes.mjs";

const valid = {
  jsonldSafeMode: "expands",
  jsonldSafeModeWithoutUndefinedTerms: "fails: invalid property",
  keyInAssertionMethod: true,
  digitalBazaarVerified: true,
  tamperedRejected: true,
};

test("the expected signature, authorization and JSON-LD outcomes pass", () => {
  assert.deepEqual(failedChecks(valid), []);
});

test("a failed or missing required outcome is reported", () => {
  for (const field of Object.keys(valid)) {
    const changed = { ...valid, [field]: field.startsWith("jsonld") ? "unexpected" : false };
    assert.deepEqual(failedChecks(changed), [field]);
    const absent = { ...valid };
    delete absent[field];
    assert.deepEqual(failedChecks(absent), [field]);
  }
});

test("strings or numbers cannot stand in for successful verification booleans", () => {
  for (const value of ["true", "false", 1, null]) {
    assert.deepEqual(failedChecks({ ...valid, digitalBazaarVerified: value }), ["digitalBazaarVerified"]);
  }
});

test("rejection of both the original and altered credential still fails the original check", () => {
  assert.deepEqual(failedChecks({ ...valid, digitalBazaarVerified: false, tamperedRejected: true }), ["digitalBazaarVerified"]);
});
