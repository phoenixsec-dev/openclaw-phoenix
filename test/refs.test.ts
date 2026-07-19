import test from "node:test";
import assert from "node:assert/strict";

import {
  extractPhoenixRefs,
  isPhoenixRef,
  normalizeListPrefix,
  normalizePhoenixRef,
  refToSecretPath,
} from "../src/refs.ts";

test("isPhoenixRef accepts valid refs and rejects malformed ones", () => {
  assert.equal(isPhoenixRef("phoenix://openclaw/api-key"), true);
  assert.equal(isPhoenixRef("phoenix://ns.prod/svc/api.key"), true);
  assert.equal(isPhoenixRef("  phoenix://openclaw/key  "), true);

  assert.equal(isPhoenixRef("phoenix://openclaw"), false);
  assert.equal(isPhoenixRef("phoenix://openclaw/"), false);
  assert.equal(isPhoenixRef("phoenix://open claw/key"), false);
  assert.equal(isPhoenixRef("vault://openclaw/key"), false);
  assert.equal(isPhoenixRef(""), false);
});

test("isPhoenixRef rejects dot and empty path segments", () => {
  assert.equal(isPhoenixRef("phoenix://openclaw/../../v1/status"), false);
  assert.equal(isPhoenixRef("phoenix://openclaw/./key"), false);
  assert.equal(isPhoenixRef("phoenix://openclaw/svc//key"), false);
  assert.equal(isPhoenixRef("phoenix://openclaw/key/.."), false);
  assert.equal(isPhoenixRef("phoenix://../key"), false);
});

test("normalizePhoenixRef passes through valid refs and applies defaultNamespace", () => {
  assert.equal(normalizePhoenixRef("phoenix://openclaw/key"), "phoenix://openclaw/key");
  assert.equal(normalizePhoenixRef("key", "openclaw"), "phoenix://openclaw/key");
  assert.equal(normalizePhoenixRef("svc/api.key", "openclaw"), "phoenix://openclaw/svc/api.key");
});

test("normalizePhoenixRef rejects invalid input", () => {
  assert.throws(() => normalizePhoenixRef(""), /ref required/);
  assert.throws(() => normalizePhoenixRef("   "), /ref required/);
  assert.throws(() => normalizePhoenixRef("key"), /defaultNamespace is not configured/);
  assert.throws(() => normalizePhoenixRef("/key", "openclaw"), /must not start with '\/'/);
  assert.throws(() => normalizePhoenixRef("phoenix://openclaw/../../v1/status"), /invalid phoenix ref/);
  assert.throws(() => normalizePhoenixRef("../../v1/status", "openclaw"), /invalid phoenix ref/);
  assert.throws(() => normalizePhoenixRef("a b", "openclaw"), /invalid phoenix ref/);
  assert.throws(() => normalizePhoenixRef("key?dry_run=true", "openclaw"), /invalid phoenix ref/);
});

test("refToSecretPath returns namespace/path", () => {
  assert.equal(refToSecretPath("phoenix://openclaw/svc/key"), "openclaw/svc/key");
  assert.equal(refToSecretPath("key", "openclaw"), "openclaw/key");
  assert.throws(() => refToSecretPath("phoenix://openclaw/../key"), /invalid phoenix ref/);
});

test("normalizeListPrefix handles empty, bare, and phoenix:// inputs", () => {
  assert.equal(normalizeListPrefix(undefined), "");
  assert.equal(normalizeListPrefix(undefined, "openclaw"), "openclaw/");
  assert.equal(normalizeListPrefix("   ", "openclaw"), "openclaw/");
  assert.equal(normalizeListPrefix("svc", "openclaw"), "openclaw/svc/");
  assert.equal(normalizeListPrefix("other-ns/svc", "openclaw"), "other-ns/svc/");
  assert.equal(normalizeListPrefix("other-ns/svc/"), "other-ns/svc/");
  assert.equal(normalizeListPrefix("phoenix://openclaw/svc"), "openclaw/svc/");
});

test("normalizeListPrefix rejects traversal-capable default namespaces", () => {
  assert.throws(() => normalizeListPrefix(undefined, "../status"), /single namespace segment/);
  assert.throws(() => normalizeListPrefix("key", "x/../status"), /single namespace segment/);
  assert.throws(() => normalizeListPrefix(undefined, ".."), /single namespace segment/);
});

test("normalizeListPrefix rejects traversal and URL metacharacters", () => {
  assert.throws(() => normalizeListPrefix("/svc"), /must not start with '\/'/);
  assert.throws(() => normalizeListPrefix("../../v1/status", "openclaw"), /invalid list prefix/);
  assert.throws(() => normalizeListPrefix("..", "openclaw"), /invalid list prefix/);
  assert.throws(() => normalizeListPrefix("svc/../other"), /invalid list prefix/);
  assert.throws(() => normalizeListPrefix("svc//key"), /invalid list prefix/);
  assert.throws(() => normalizeListPrefix("x?dry_run=true"), /invalid list prefix/);
  assert.throws(() => normalizeListPrefix("x#fragment"), /invalid list prefix/);
  assert.throws(() => normalizeListPrefix("a b"), /invalid list prefix/);
  assert.throws(() => normalizeListPrefix("a\\b"), /invalid list prefix/);
  assert.throws(() => normalizeListPrefix("phoenix://openclaw/../../v1/status"), /invalid phoenix ref/);
});

test("extractPhoenixRefs walks nested structures, dedupes, and survives cycles", () => {
  const cyclic: Record<string, unknown> = {
    env: { A: "phoenix://openclaw/key-a", B: "prefix phoenix://openclaw/key-b suffix" },
    list: ["phoenix://openclaw/key-a", { deep: "phoenix://ns2/key-c" }],
    number: 42,
    nothing: null,
  };
  cyclic.self = cyclic;

  const refs = [...extractPhoenixRefs(cyclic)].sort();
  assert.deepEqual(refs, [
    "phoenix://ns2/key-c",
    "phoenix://openclaw/key-a",
    "phoenix://openclaw/key-b",
  ]);
});
