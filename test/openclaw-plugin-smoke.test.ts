import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { registerHooks } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPO_ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
// Sibling-checkout convention: ../openclaw next to this repo unless overridden.
const OPENCLAW_REPO = path.resolve(process.env.OPENCLAW_REPO ?? path.resolve(REPO_ROOT, "../openclaw"));
const SDK_SPECIFIER = "openclaw/plugin-sdk/plugin-entry";
const LEGACY_CORE_SPECIFIER = "openclaw/plugin-sdk/core";
const EXPECTED_PLUGIN_ID = "phoenix-secrets";
const EXPECTED_TOOL_NAMES = ["phoenix_resolve", "phoenix_list", "phoenix_status"] as const;

function readJsonFile(filePath: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as Record<string, unknown>;
}

function moduleDataUrl(source: string): string {
  return `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
}

const pluginEntrySdkStubUrl = moduleDataUrl(`
const emptySchema = {
  jsonSchema: { type: "object", additionalProperties: false, properties: {} },
  safeParse(value) {
    if (value === undefined || (value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0)) {
      return { success: true, data: value };
    }
    return { success: false, error: { issues: [{ path: [], message: "config must be empty" }] } };
  }
};
export function emptyPluginConfigSchema() {
  return emptySchema;
}
export function definePluginEntry(entry) {
  if (!entry || typeof entry !== "object") {
    throw new TypeError("definePluginEntry expected an entry object");
  }
  if (typeof entry.id !== "string" || entry.id.length === 0) {
    throw new TypeError("definePluginEntry expected a non-empty id");
  }
  if (typeof entry.register !== "function") {
    throw new TypeError("definePluginEntry expected register(api)");
  }
  const configSchema = entry.configSchema ?? emptySchema;
  return {
    ...entry,
    get configSchema() {
      return typeof configSchema === "function" ? configSchema() : configSchema;
    },
  };
}
`);

const legacyCoreImportErrorUrl = moduleDataUrl(`
throw new Error(${JSON.stringify(
  `openclaw-phoenix must import definePluginEntry from ${SDK_SPECIFIER}; ${LEGACY_CORE_SPECIFIER} is the broader legacy/core surface.`,
)});
`);

// The loader shim prefers the REAL definePluginEntry from the local OpenClaw
// checkout (src/plugin-sdk/plugin-entry.ts, with the checkout's .js -> .ts
// source import specifiers remapped). That only works when the checkout can
// actually be loaded standalone: as of 2026-07 it cannot (no dist/ build, no
// node_modules, and plugin-entry.ts transitively imports the external "zod"
// dependency), so loadPluginEntry falls back to the hand-written stub and
// reports which mode ran via t.diagnostic.
const REAL_SDK_ENTRY_URL = pathToFileURL(
  path.join(OPENCLAW_REPO, "src", "plugin-sdk", "plugin-entry.ts"),
).href;
const OPENCLAW_SRC_URL_PREFIX = pathToFileURL(path.join(OPENCLAW_REPO, "src")).href + "/";

let sdkMode: "real" | "stub" = "stub";
let sdkHookRegistered = false;
function registerOpenClawPluginSdkSmokeShim(): void {
  if (sdkHookRegistered) {
    return;
  }

  registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier === SDK_SPECIFIER) {
        return {
          url: sdkMode === "real" ? REAL_SDK_ENTRY_URL : pluginEntrySdkStubUrl,
          shortCircuit: true,
        };
      }
      if (specifier === LEGACY_CORE_SPECIFIER) {
        return { url: legacyCoreImportErrorUrl, shortCircuit: true };
      }
      // The OpenClaw checkout's TypeScript sources import siblings via ".js"
      // specifiers; remap them to the ".ts" sources when loading the real SDK.
      const parentURL = (context as { parentURL?: string }).parentURL;
      if (
        sdkMode === "real" &&
        parentURL?.startsWith(OPENCLAW_SRC_URL_PREFIX) &&
        (specifier.startsWith("./") || specifier.startsWith("../")) &&
        specifier.endsWith(".js")
      ) {
        const candidate = new URL(specifier.replace(/\.js$/, ".ts"), parentURL);
        if (fs.existsSync(fileURLToPath(candidate))) {
          return { url: candidate.href, shortCircuit: true };
        }
      }
      return nextResolve(specifier, context);
    },
  });
  sdkHookRegistered = true;
}

function assertLocalOpenClawSdkEntrypoint(): void {
  const openClawPackageJsonPath = path.join(OPENCLAW_REPO, "package.json");
  const openClawPackageJson = readJsonFile(openClawPackageJsonPath);
  const exportsMap = openClawPackageJson.exports as Record<string, unknown> | undefined;
  const pluginEntryExport = exportsMap?.["./plugin-sdk/plugin-entry"];
  assert.ok(pluginEntryExport, "local OpenClaw package.json exports ./plugin-sdk/plugin-entry");

  const pluginEntrySourcePath = path.join(OPENCLAW_REPO, "src", "plugin-sdk", "plugin-entry.ts");
  assert.ok(fs.existsSync(pluginEntrySourcePath), "local OpenClaw source contains src/plugin-sdk/plugin-entry.ts");
  const pluginEntrySource = fs.readFileSync(pluginEntrySourcePath, "utf8");
  assert.match(pluginEntrySource, /export function definePluginEntry\s*\(/);
}

function expandLocalJsonSchemaRefs(value: unknown, root: Record<string, unknown>): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => expandLocalJsonSchemaRefs(item, root));
  }
  if (!value || typeof value !== "object") {
    return value;
  }

  const record = value as Record<string, unknown>;
  const ref = record.$ref;
  if (typeof ref === "string") {
    const match = /^#\/\$defs\/([^/]+)$/u.exec(ref);
    assert.ok(match, `unsupported smoke-test JSON Schema ref: ${ref}`);
    const defs = root.$defs as Record<string, unknown> | undefined;
    const target = defs?.[match[1]];
    assert.ok(target, `missing smoke-test JSON Schema $defs target: ${match[1]}`);
    return expandLocalJsonSchemaRefs(target, root);
  }

  const expanded: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(record)) {
    if (key === "$defs") {
      continue;
    }
    expanded[key] = expandLocalJsonSchemaRefs(item, root);
  }
  return expanded;
}

function sortStrings(values: readonly string[]): string[] {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function createCapturingPluginApi(pluginConfig: Record<string, unknown>) {
  const captured = {
    tools: [] as Array<{ tool: unknown; opts?: Record<string, unknown> }>,
    services: [] as Array<Record<string, unknown>>,
    clis: [] as Array<{ registrar: unknown; opts?: Record<string, unknown> }>,
  };
  const unexpectedRegistration = (name: string) => () => {
    throw new Error(`unexpected OpenClaw API registration during smoke: ${name}`);
  };

  const api = {
    id: EXPECTED_PLUGIN_ID,
    name: "Phoenix Secrets Manager",
    description: "Phoenix smoke-test host API",
    source: path.join(REPO_ROOT, "index.ts"),
    rootDir: REPO_ROOT,
    registrationMode: "full",
    config: {},
    pluginConfig,
    runtime: {},
    logger: {
      debug() {},
      info() {},
      warn() {},
      error() {},
    },
    resolvePath(input: string) {
      return path.resolve(REPO_ROOT, input);
    },
    registerTool(tool: unknown, opts?: Record<string, unknown>) {
      captured.tools.push({ tool, opts });
    },
    registerService(service: Record<string, unknown>) {
      captured.services.push(service);
    },
    registerCli(registrar: unknown, opts?: Record<string, unknown>) {
      captured.clis.push({ registrar, opts });
    },
    registerHook: unexpectedRegistration("registerHook"),
    registerProvider: unexpectedRegistration("registerProvider"),
    registerChannel: unexpectedRegistration("registerChannel"),
    registerGatewayMethod: unexpectedRegistration("registerGatewayMethod"),
    registerHttpRoute: unexpectedRegistration("registerHttpRoute"),
  };

  return { api, captured };
}

type FakeCommand = {
  name: string;
  descriptionText?: string;
  children: FakeCommand[];
  actions: unknown[];
  command: (name: string) => FakeCommand;
  description: (text: string) => FakeCommand;
  action: (handler: unknown) => FakeCommand;
};

function createFakeCommand(name: string): FakeCommand {
  const command: FakeCommand = {
    name,
    children: [],
    actions: [],
    command(childName: string) {
      const child = createFakeCommand(childName);
      command.children.push(child);
      return child;
    },
    description(text: string) {
      command.descriptionText = text;
      return command;
    },
    action(handler: unknown) {
      command.actions.push(handler);
      return command;
    },
  };
  return command;
}

function createFakeProgram() {
  const commands: FakeCommand[] = [];
  return {
    commands,
    command(name: string) {
      const command = createFakeCommand(name);
      commands.push(command);
      return command;
    },
  };
}

type LoadedPluginEntry = {
  id: string;
  name: string;
  description: string;
  configSchema?: Record<string, unknown>;
  register: (api: Record<string, unknown>) => void;
};

async function loadPluginEntry(t: { diagnostic: (message: string) => void }): Promise<LoadedPluginEntry> {
  registerOpenClawPluginSdkSmokeShim();
  const modes: Array<"real" | "stub"> = ["real", "stub"];
  let lastRealError: unknown;
  for (const mode of modes) {
    sdkMode = mode;
    const indexUrl = pathToFileURL(path.join(REPO_ROOT, "index.ts"));
    indexUrl.searchParams.set("openclaw-smoke", `${mode}-${Date.now()}`);
    try {
      const imported = await import(indexUrl.href);
      t.diagnostic(`plugin-sdk definePluginEntry mode: ${mode}`);
      return imported.default as LoadedPluginEntry;
    } catch (error) {
      if (mode === "real") {
        lastRealError = error;
        // Guard against false confidence from the stub: strict mode for CI or
        // environments where the real SDK is expected to load.
        if (process.env.OPENCLAW_SMOKE_REQUIRE_REAL_SDK) {
          throw new Error(
            `OPENCLAW_SMOKE_REQUIRE_REAL_SDK is set but the real plugin-sdk import failed: ${
              error instanceof Error ? error.message : String(error)
            }`,
          );
        }
        t.diagnostic(
          `real plugin-sdk import failed, falling back to stub: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        continue;
      }
      throw error;
    } finally {
      sdkMode = "stub";
    }
  }
  throw lastRealError;
}

if (!fs.existsSync(path.join(OPENCLAW_REPO, "package.json"))) {
  test("OpenClaw plugin load/registration smoke", {
    skip: `local OpenClaw repo not found at ${OPENCLAW_REPO}; set OPENCLAW_REPO=/path/to/openclaw to run this smoke validation`,
  }, () => {});
} else {
  test("OpenClaw plugin load/registration smoke", async (t) => {
    t.diagnostic(`Using local OpenClaw repo: ${OPENCLAW_REPO}`);
    assertLocalOpenClawSdkEntrypoint();

    const packageJson = readJsonFile(path.join(REPO_ROOT, "package.json"));
    const manifest = readJsonFile(path.join(REPO_ROOT, "openclaw.plugin.json"));

    assert.equal(manifest.id, EXPECTED_PLUGIN_ID);
    assert.deepEqual((packageJson.openclaw as { extensions?: unknown })?.extensions, ["./index.ts"]);

    const entry = await loadPluginEntry(t);
    assert.equal(entry.id, manifest.id);
    assert.equal(typeof entry.register, "function");

    const manifestSchema = manifest.configSchema as Record<string, unknown>;
    const runtimeSchema = entry.configSchema?.jsonSchema;
    assert.deepEqual(expandLocalJsonSchemaRefs(manifestSchema, manifestSchema), runtimeSchema);
    assert.deepEqual(manifest.uiHints, entry.configSchema?.uiHints);

    const manifestTools = ((manifest.contracts as { tools?: string[] } | undefined)?.tools ?? []);
    assert.deepEqual(sortStrings(manifestTools), sortStrings(EXPECTED_TOOL_NAMES));
    assert.deepEqual((manifest.activation as { onCapabilities?: string[] } | undefined)?.onCapabilities, ["tool"]);

    const { api, captured } = createCapturingPluginApi({
      server: "http://127.0.0.1:1",
      token: "smoke-token-not-a-real-secret",
      sealMode: true,
      sealKeyFile: path.join(REPO_ROOT, `.openclaw-phoenix-smoke-missing-seal-key-${process.pid}`),
    });
    entry.register(api);

    assert.equal(captured.tools.length, EXPECTED_TOOL_NAMES.length);
    const registeredToolNames = captured.tools.map(({ opts, tool }) => {
      if (opts?.name) {
        return String(opts.name);
      }
      return typeof tool === "object" && tool !== null && "name" in tool
        ? String((tool as { name?: unknown }).name)
        : "";
    });
    assert.deepEqual(sortStrings(registeredToolNames), sortStrings(EXPECTED_TOOL_NAMES));
    for (const expectedToolName of EXPECTED_TOOL_NAMES) {
      const registration = captured.tools.find(({ opts }) => opts?.name === expectedToolName);
      assert.ok(registration, `registered ${expectedToolName}`);
      assert.equal(registration.opts?.optional, true, `${expectedToolName} is optional`);
      assert.equal(typeof registration.tool, "function", `${expectedToolName} registered as a factory`);
      const tool = (registration.tool as (ctx: Record<string, unknown>) => { name: string })(
        { agentId: "main", sessionId: "smoke-session", sessionKey: "smoke-session-key" },
      );
      assert.equal(tool.name, expectedToolName);
    }

    assert.equal(captured.services.length, 1);
    const service = captured.services[0] as { id?: unknown; start?: (ctx: { logger: { warn: (message: string) => void } }) => Promise<void> };
    assert.equal(service.id, "phoenix-startup-check");
    assert.equal(typeof service.start, "function");
    const startupWarnings: string[] = [];
    await assert.doesNotReject(() =>
      service.start?.({ logger: { warn: (message) => startupWarnings.push(message) } }),
    );
    assert.equal(startupWarnings.length, 1);
    assert.match(startupWarnings[0], /Phoenix startup preflight warning \(non-fatal\)/);
    assert.match(startupWarnings[0], /OpenClaw gateway will continue/);

    assert.equal(captured.clis.length, 1);
    const cliRegistration = captured.clis[0] as { registrar: (ctx: Record<string, unknown>) => void; opts?: { commands?: string[] } };
    assert.deepEqual(cliRegistration.opts?.commands, ["phoenix"]);
    const program = createFakeProgram();
    cliRegistration.registrar({ program, config: {}, logger: { info() {}, warn() {} } });
    const phoenixCommand = program.commands.find((command) => command.name === "phoenix");
    assert.ok(phoenixCommand, "registered openclaw phoenix root command");
    assert.equal(phoenixCommand.descriptionText, "Phoenix Secrets Manager helper commands");
    const verifyCommand = phoenixCommand.children.find((command) => command.name === "verify");
    assert.ok(verifyCommand, "registered openclaw phoenix verify subcommand");
    assert.equal(verifyCommand.actions.length, 1);

    t.diagnostic(
      `Loaded ${entry.id}; tools=${sortStrings(registeredToolNames).join(",")}; services=${captured.services.length}; cli=phoenix`,
    );
  });
}
