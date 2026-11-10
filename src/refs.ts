const PHOENIX_REF_PREFIX = "phoenix://";
const PHOENIX_REF_RE = /^phoenix:\/\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._/-]+)$/;
const SECRET_PATH_CHARSET_RE = /^[A-Za-z0-9._/-]+$/;

function hasUnsafePathSegments(path: string): boolean {
  return path
    .split("/")
    .some((segment) => segment === "" || segment === "." || segment === "..");
}

// Single-source namespace constraint, shared by the runtime validation and the
// JSON schemas so OpenClaw's manifest validation rejects the same values the
// plugin rejects at registration. The lookahead excludes '.' and '..'.
export const PHOENIX_NAMESPACE_PATTERN = "^(?!\\.{1,2}$)[A-Za-z0-9._-]+$";
const PHOENIX_NAMESPACE_RE = new RegExp(PHOENIX_NAMESPACE_PATTERN);

export function isValidPhoenixNamespace(namespace: string): boolean {
  return PHOENIX_NAMESPACE_RE.test(namespace);
}

function assertSafeDefaultNamespace(defaultNamespace: string): void {
  if (!isValidPhoenixNamespace(defaultNamespace)) {
    throw new Error(
      `defaultNamespace must be a single namespace segment (letters, digits, '._-'): ${defaultNamespace}`,
    );
  }
}

export function isPhoenixRef(value: string): boolean {
  const trimmed = value.trim();
  if (!PHOENIX_REF_RE.test(trimmed)) {
    return false;
  }
  return !hasUnsafePathSegments(trimmed.slice(PHOENIX_REF_PREFIX.length));
}

export function normalizePhoenixRef(value: string, defaultNamespace?: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error("ref required");
  }
  if (trimmed.startsWith(PHOENIX_REF_PREFIX)) {
    if (!isPhoenixRef(trimmed)) {
      throw new Error(`invalid phoenix ref (allowed: letters, digits, '._-', no '.'/'..' segments): ${trimmed}`);
    }
    return trimmed;
  }
  if (!defaultNamespace) {
    throw new Error(`ref must be a phoenix:// URI when defaultNamespace is not configured: ${trimmed}`);
  }
  if (trimmed.startsWith("/")) {
    throw new Error(`ref must not start with '/': ${trimmed}`);
  }
  const ref = `${PHOENIX_REF_PREFIX}${defaultNamespace}/${trimmed}`;
  if (!isPhoenixRef(ref)) {
    throw new Error(`invalid phoenix ref: ${trimmed}`);
  }
  return ref;
}

export function refToSecretPath(refOrPath: string, defaultNamespace?: string): string {
  const normalized = normalizePhoenixRef(refOrPath, defaultNamespace);
  const match = PHOENIX_REF_RE.exec(normalized);
  if (!match) {
    throw new Error(`invalid phoenix ref: ${refOrPath}`);
  }
  return `${match[1]}/${match[2]}`;
}

// Message for a list prefix that uses a wildcard other than a trailing "*".
// Same wording as the Phoenix CLI and MCP phoenix_list.
function listWildcardError(value: string): Error {
  return new Error(
    `"${value}": list takes a folder (services/browser, services/browser/ or services/browser/*); other wildcards are not supported`,
  );
}

// Turns one of the three folder forms ("a/b", "a/b/", "a/b/*") into the bare
// folder "a/b" ("" for the root). Any other wildcard is an error. Mirrors
// listFolder in the Phoenix CLI.
function bareListFolder(value: string, original: string): string {
  const folder = value.endsWith("*") ? value.slice(0, -1) : value;
  if (/[*?[]/.test(folder) || (folder !== value && folder !== "" && !folder.endsWith("/"))) {
    throw listWildcardError(original);
  }
  return folder.endsWith("/") ? folder.slice(0, -1) : folder;
}

// Normalizes the phoenix_list prefix to the folder path the server expects
// (always ending in "/", or "" for everything). Accepts "a/b", "a/b/",
// "a/b/*" and the phoenix:// form of each, including a bare namespace
// ("phoenix://ns"). A single bare segment lives under defaultNamespace.
export function normalizeListPrefix(value: string | undefined, defaultNamespace?: string): string {
  const trimmed = value?.trim() ?? "";
  const isRef = trimmed.startsWith(PHOENIX_REF_PREFIX);
  const folder = bareListFolder(isRef ? trimmed.slice(PHOENIX_REF_PREFIX.length) : trimmed, trimmed);
  if (isRef) {
    if (!SECRET_PATH_CHARSET_RE.test(folder) || hasUnsafePathSegments(folder)) {
      throw new Error(`invalid phoenix ref (allowed: letters, digits, '._-', no '.'/'..' segments): ${trimmed}`);
    }
    return `${folder}/`;
  }
  if (!folder) {
    if (!defaultNamespace) {
      return "";
    }
    assertSafeDefaultNamespace(defaultNamespace);
    return `${defaultNamespace}/`;
  }
  if (folder.startsWith("/")) {
    throw new Error(`prefix must not start with '/': ${trimmed}`);
  }
  if (!SECRET_PATH_CHARSET_RE.test(folder) || hasUnsafePathSegments(folder)) {
    throw new Error(
      `invalid list prefix (allowed: letters, digits, '._-', no '.'/'..' segments): ${trimmed}`,
    );
  }
  if (defaultNamespace && !folder.includes("/")) {
    assertSafeDefaultNamespace(defaultNamespace);
    return `${defaultNamespace}/${folder}/`;
  }
  return `${folder}/`;
}

export function extractPhoenixRefs(value: unknown, results = new Set<string>()): Set<string> {
  const seen = new Set<unknown>();

  function visit(current: unknown) {
    if (current === null || current === undefined) {
      return;
    }
    if (typeof current === "string") {
      const matches = current.match(/phoenix:\/\/[A-Za-z0-9._-]+\/[A-Za-z0-9._/-]+/g) ?? [];
      for (const match of matches) {
        results.add(match);
      }
      return;
    }
    if (typeof current !== "object") {
      return;
    }
    if (seen.has(current)) {
      return;
    }
    seen.add(current);
    if (Array.isArray(current)) {
      for (const item of current) {
        visit(item);
      }
      return;
    }
    for (const entry of Object.values(current)) {
      visit(entry);
    }
  }

  visit(value);
  return results;
}
