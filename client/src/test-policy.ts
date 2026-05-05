/**
 * Policy + RBAC unit test — no blockchain needed.
 * Tests that PolicyStore enforces mandatory-signer rules correctly.
 */

import { PolicyStore } from "./policy.js";

let pass = 0, fail = 0;

function check(label: string, actual: boolean, expected: boolean) {
  const ok = actual === expected;
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${label}`);
  if (ok) pass++; else fail++;
}

// ========== Setup ==========
const store = new PolicyStore();

// treasury: Party 2 (CFO) mandatory
store.add({ name: "treasury", txTag: "treasury", mandatoryParties: [2], minThreshold: 2 });
// admin: Party 3 (CEO) mandatory
store.add({ name: "admin", txTag: "admin", mandatoryParties: [3], minThreshold: 2 });
// upgrade: Both Party 2 AND Party 3 mandatory
store.add({ name: "upgrade", txTag: "upgrade", mandatoryParties: [2, 3], minThreshold: 3 });

console.log("=== Policy RBAC Test ===\n");
console.log("Policies registered:");
for (const p of store.list()) {
  console.log(`  [${p.id}] "${p.name}"  tag="${p.txTag}"  mandatory={${p.mandatoryParties.join(",")}}`);
}

// ========== Treasury tag ==========
console.log("\n--- tag=treasury (Party 2 mandatory) ---");
check("Parties {1,3} → VIOLATED (Party 2 missing)",  store.check("treasury", [1, 3]) !== null, true);
check("Parties {1,2} → OK",                           store.check("treasury", [1, 2]) === null, true);
check("Parties {2,3} → OK",                           store.check("treasury", [2, 3]) === null, true);
check("Parties {1,2,3} → OK",                         store.check("treasury", [1, 2, 3]) === null, true);

// ========== Admin tag ==========
console.log("\n--- tag=admin (Party 3 mandatory) ---");
check("Parties {1,2} → VIOLATED (Party 3 missing)",  store.check("admin", [1, 2]) !== null, true);
check("Parties {1,3} → OK",                           store.check("admin", [1, 3]) === null, true);
check("Parties {2,3} → OK",                           store.check("admin", [2, 3]) === null, true);

// ========== Upgrade tag ==========
console.log("\n--- tag=upgrade (Party 2 AND Party 3 both mandatory) ---");
check("Parties {1,2} → VIOLATED (Party 3 missing)",  store.check("upgrade", [1, 2]) !== null, true);
check("Parties {1,3} → VIOLATED (Party 2 missing)",  store.check("upgrade", [1, 3]) !== null, true);
check("Parties {1,2,3} → OK",                         store.check("upgrade", [1, 2, 3]) === null, true);

// ========== No tag (routine) ==========
console.log("\n--- no tag (any 2-of-3 allowed) ---");
check('Parties {1,2} with tag="" → OK',   store.check("", [1, 2]) === null, true);
check('Parties {1,3} with tag="" → OK',   store.check("", [1, 3]) === null, true);
check('Parties {2,3} with tag="" → OK',   store.check("", [2, 3]) === null, true);

// ========== Enforce throws ==========
console.log("\n--- enforce() throws on violation ---");
let threw = false;
try { store.enforce("treasury", [1, 3]); }
catch (e: any) { threw = e.message.includes("POLICY VIOLATION"); }
check("enforce(treasury, {1,3}) throws POLICY VIOLATION", threw, true);

let nothrew = true;
try { store.enforce("treasury", [1, 2]); }
catch { nothrew = false; }
check("enforce(treasury, {1,2}) does not throw", nothrew, true);

// ========== Remove policy ==========
console.log("\n--- remove policy ---");
const removed = store.remove(1); // remove treasury
check("remove policy id=1 returns true", removed, true);
check("After removal, tag=treasury has no policy", store.check("treasury", [1, 3]) === null, true);

// ========== Duplicate tag guard ==========
console.log("\n--- duplicate tag guard ---");
let dupThrew = false;
try { store.add({ name: "admin2", txTag: "admin", mandatoryParties: [3], minThreshold: 2 }); }
catch { dupThrew = true; }
check("Adding duplicate txTag throws", dupThrew, true);

// ========== minThreshold check ==========
console.log("\n--- minThreshold enforcement ---");
store.add({ name: "multisig5", txTag: "multisig5", mandatoryParties: [1], minThreshold: 3 });
check("Parties {1,2} with minThreshold=3 → VIOLATED", store.check("multisig5", [1, 2]) !== null, true);
check("Parties {1,2,3} with minThreshold=3 → OK",     store.check("multisig5", [1, 2, 3]) === null, true);

// ========== Summary ==========
console.log(`\n${"=".repeat(40)}`);
console.log(`  Results: ${pass} PASS, ${fail} FAIL`);
console.log(`${"=".repeat(40)}`);
if (fail > 0) process.exit(1);
