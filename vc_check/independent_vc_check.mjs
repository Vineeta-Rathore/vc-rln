// Independent check of the end-to-end credential with third-party libraries (not our code):
//  1. JSON-LD expansion in safe mode (jsonld), which fails if any term is undefined; the same credential without the
//     undefined-terms context is expanded too, to show that VC 2.0 needs that context here;
//  2. @digitalbazaar/vc verifyCredential with the eddsa-jcs-2022 cryptosuite, the issuer key taken from the issuer's
//     did:ethr document resolved on OP Sepolia. Registry status is checked by our client (scripts/vc_demo.js).
//   cd vc_check && npm install && npm run check        (versions pinned in vc_check/package.json; writes result.json)
//   OP_RPC overrides the OP Sepolia endpoint; ERC1056 overrides the registry read from ../data/registries.json.
import fs from "node:fs";
import { createRequire } from "node:module";
import jsonld from "jsonld";
import * as vc from "@digitalbazaar/vc";
import { DataIntegrityProof } from "@digitalbazaar/data-integrity";
import { createVerifyCryptosuite } from "@digitalbazaar/eddsa-jcs-2022-cryptosuite";

const req = createRequire(import.meta.url);
const { Resolver } = req("did-resolver");
const { getResolver } = req("ethr-did-resolver");

const CTX = {
  "https://www.w3.org/ns/credentials/v2": "cred-v2", "https://www.w3.org/ns/credentials/undefined-terms/v2": "undef-v2",
  "https://www.w3.org/ns/did/v1": "did-v1", "https://w3id.org/security/multikey/v1": "multikey-v1",
  "https://w3id.org/security/data-integrity/v2": "di-v2",
};
const docs = {};
const documentLoader = async (url) => {
  if (CTX[url]) return { contextUrl: null, documentUrl: url, document: JSON.parse(fs.readFileSync(new URL(`vc_contexts/${CTX[url]}.json`, import.meta.url))) };
  const base = url.split("#")[0];
  if (docs[url]) return { contextUrl: null, documentUrl: url, document: docs[url] };
  if (docs[base]) return { contextUrl: null, documentUrl: url, document: docs[base] };
  throw new Error("offline loader: " + url);
};

const out = {};
const cred = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const safe = async (doc) => { try { await jsonld.expand(doc, { documentLoader, safe: true }); return "expands"; } catch (e) { return "fails: " + (e.details?.event?.code || e.name || e.message); } };
const { proof, ...unsigned } = cred;
out.jsonldSafeMode = await safe(unsigned);
out.jsonldSafeModeWithoutUndefinedTerms = await safe({ ...unsigned,
  "@context": unsigned["@context"].filter((c) => c !== "https://www.w3.org/ns/credentials/undefined-terms/v2") });

// the issuer key from the issuer's DID document, as a Multikey document for the library
const RPC = process.env.OP_RPC || "https://sepolia.optimism.io";
const regFile = new URL("../data/registries.json", import.meta.url);
const reg = process.env.ERC1056 || JSON.parse(fs.readFileSync(regFile, "utf8")).find((r) => r.network === "opSepolia").erc1056;
const resolver = new Resolver(getResolver({ networks: [{ name: "opsepolia", chainId: 11155420, rpcUrl: RPC, registry: reg }] }));
const didDoc = (await resolver.resolve(cred.issuer)).didDocument;
const vm = didDoc.verificationMethod.find((m) => m.id === proof.verificationMethod);
if (!vm) throw new Error("verification method not in the issuer's DID document");
docs[vm.id] = { "@context": "https://w3id.org/security/multikey/v1", id: vm.id, type: "Multikey", controller: cred.issuer, publicKeyMultibase: vm.publicKeyMultibase };
docs[cred.issuer] = { "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], id: cred.issuer,
  verificationMethod: [docs[vm.id]], assertionMethod: (didDoc.assertionMethod || []).map((m) => (typeof m === "string" ? m : m.id)) };
out.keyInAssertionMethod = docs[cred.issuer].assertionMethod.includes(vm.id);

const suite = new DataIntegrityProof({ cryptosuite: createVerifyCryptosuite() });
// the status entry is our registry leaf, checked on-chain by the demo (current root, window); the library only needs
// a status function, which here reports that the check is external
const checkStatus = async () => ({ verified: true });
const r = await vc.verifyCredential({ credential: cred, suite, documentLoader, checkStatus });
out.digitalBazaarVerified = r.verified;
if (!r.verified) out.error = JSON.stringify(r.error || r.results, null, 1).slice(0, 1500);
const tampered = { ...cred, credentialSubject: { ...cred.credentialSubject, verifiedHuman: false } };
out.tamperedRejected = !(await vc.verifyCredential({ credential: tampered, suite, documentLoader, checkStatus })).verified;
out.versions = Object.fromEntries(["jsonld", "@digitalbazaar/vc", "@digitalbazaar/data-integrity", "@digitalbazaar/eddsa-jcs-2022-cryptosuite"]
  .map((m) => [m, JSON.parse(fs.readFileSync(new URL(`node_modules/${m}/package.json`, import.meta.url), "utf8")).version]));
out.credential = process.argv[2];
out.date = new Date().toISOString();
out.script = "vc_check/independent_vc_check.mjs";
fs.writeFileSync(new URL("result.json", import.meta.url), JSON.stringify(out, null, 1) + "\n");
console.log(JSON.stringify(out, null, 1));
