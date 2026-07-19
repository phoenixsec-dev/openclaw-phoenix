const PHOENIX_REF_PREFIX = "phoenix://";
const PHOENIX_REF_RE = /^phoenix:\/\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._/-]+)$/;
const SECRET_PATH_CHARSET_RE = /^[A-Za-z0-9._/-]+$/;

function hasUnsafePathSegments(path: string): boolean {
  return path
    .split("/")
    .some((segment) => segment === "" || segment === "." || segment === "..");
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

export function normalizeListPrefix(value: string | undefined, defaultNamespace?: string): string {
  const trimmed = value?.trim();
  if (!trimmed) {
    return defaultNamespace ? `${defaultNamespace}/` : "";
  }
  if (trimmed.startsWith(PHOENIX_REF_PREFIX)) {
    return `${refToSecretPath(trimmed)}/`.replace(/\/+/g, "/");
  }
  if (trimmed.startsWith("/")) {
    throw new Error(`prefix must not start with '/': ${trimmed}`);
  }
  const withoutTrailingSlash = trimmed.replace(/\/$/, "");
  if (!SECRET_PATH_CHARSET_RE.test(withoutTrailingSlash) || hasUnsafePathSegments(withoutTrailingSlash)) {
    throw new Error(
      `invalid list prefix (allowed: letters, digits, '._-', no '.'/'..' segments): ${trimmed}`,
    );
  }
  if (defaultNamespace && !trimmed.includes("/")) {
    return `${defaultNamespace}/${trimmed}`.replace(/\/?$/, "/");
  }
  return trimmed.replace(/\/?$/, "/");
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
