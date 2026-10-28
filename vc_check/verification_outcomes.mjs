// Required outcomes of this signature/data-model check. Registry status is checked separately by the application.
export function failedChecks(result) {
  const expected = {
    jsonldSafeMode: result.jsonldSafeMode === "expands",
    jsonldSafeModeWithoutUndefinedTerms: typeof result.jsonldSafeModeWithoutUndefinedTerms === "string"
      && result.jsonldSafeModeWithoutUndefinedTerms.startsWith("fails: "),
    keyInAssertionMethod: result.keyInAssertionMethod === true,
    digitalBazaarVerified: result.digitalBazaarVerified === true,
    tamperedRejected: result.tamperedRejected === true,
  };
  return Object.entries(expected).filter(([, passed]) => !passed).map(([name]) => name);
}
