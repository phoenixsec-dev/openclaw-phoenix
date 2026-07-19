import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Sibling-checkout convention: ../phoenix next to this repo, like the smoke
// test's ../openclaw default. Override with PHOENIX_SRC or PHOENIX_SERVER_BIN.
const REPO_ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const DEFAULT_PHOENIX_SRC = path.resolve(REPO_ROOT, "../phoenix");
const GO_BIN = process.env.GO ?? "go";
const HEALTH_WAIT_ATTEMPTS = 100;
const HEALTH_WAIT_INTERVAL_MS = 100;

export type PhoenixAvailability =
  | { ok: true; mode: "prebuilt"; serverBin: string; cliBin: string }
  | { ok: true; mode: "build"; srcDir: string; goBin: string }
  | { ok: false; reason: string };

export type PhoenixBinaries = {
  serverBin: string;
  cliBin: string;
};

export type CliResult = {
  status: number | null;
  stdout: string;
  stderr: string;
};

// Track everything that must not survive the test process, even on crash.
const liveChildren = new Set<ChildProcess>();
const liveTmpDirs = new Set<string>();
let exitHookInstalled = false;

function installExitHook(): void {
  if (exitHookInstalled) {
    return;
  }
  exitHookInstalled = true;
  process.on("exit", () => {
    for (const child of liveChildren) {
      try {
        child.kill("SIGKILL");
      } catch {
        // best effort
      }
    }
    for (const dir of liveTmpDirs) {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        // best effort
      }
    }
  });
}

async function makeTmpDir(prefix: string): Promise<string> {
  installExitHook();
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), prefix));
  liveTmpDirs.add(dir);
  return dir;
}

async function removeTmpDir(dir: string): Promise<void> {
  await fsp.rm(dir, { recursive: true, force: true });
  liveTmpDirs.delete(dir);
}

export function detectPhoenixAvailability(env: NodeJS.ProcessEnv = process.env): PhoenixAvailability {
  const serverBin = env.PHOENIX_SERVER_BIN?.trim();
  if (serverBin) {
    const cliBin = env.PHOENIX_CLI_BIN?.trim() || path.join(path.dirname(serverBin), "phoenix");
    if (!fs.existsSync(serverBin)) {
      return { ok: false, reason: `PHOENIX_SERVER_BIN does not exist: ${serverBin}` };
    }
    if (!fs.existsSync(cliBin)) {
      return {
        ok: false,
        reason: `phoenix CLI not found at ${cliBin}; set PHOENIX_CLI_BIN to the phoenix CLI binary`,
      };
    }
    return { ok: true, mode: "prebuilt", serverBin, cliBin };
  }

  const srcDir = path.resolve(env.PHOENIX_SRC?.trim() || DEFAULT_PHOENIX_SRC);
  if (!fs.existsSync(path.join(srcDir, "go.mod"))) {
    return {
      ok: false,
      reason:
        `no Phoenix checkout at ${srcDir} (missing go.mod); set PHOENIX_SERVER_BIN to a prebuilt ` +
        "phoenix-server binary or PHOENIX_SRC to a Phoenix source checkout to run integration tests",
    };
  }
  const goProbe = spawnSync(GO_BIN, ["version"], { encoding: "utf8" });
  if (goProbe.error || goProbe.status !== 0) {
    return {
      ok: false,
      reason:
        `Go toolchain "${GO_BIN}" is not runnable (${goProbe.error?.message ?? `exit ${goProbe.status}`}); ` +
        "set GO to a Go binary or PHOENIX_SERVER_BIN to a prebuilt phoenix-server binary",
    };
  }
  return { ok: true, mode: "build", srcDir, goBin: GO_BIN };
}

export async function ensurePhoenixBinaries(
  availability: Extract<PhoenixAvailability, { ok: true }>,
): Promise<PhoenixBinaries> {
  if (availability.mode === "prebuilt") {
    return { serverBin: availability.serverBin, cliBin: availability.cliBin };
  }
  const buildDir = await makeTmpDir("openclaw-phoenix-int-bin-");
  const build = spawnSync(availability.goBin, ["build", "-o", `${buildDir}${path.sep}`, "./cmd/..."], {
    cwd: availability.srcDir,
    encoding: "utf8",
    timeout: 300000,
  });
  if (build.error || build.status !== 0) {
    throw new Error(
      `go build of Phoenix (${availability.srcDir}) failed: ${build.error?.message ?? `exit ${build.status}`}\n${build.stderr}`,
    );
  }
  const serverBin = path.join(buildDir, "phoenix-server");
  const cliBin = path.join(buildDir, "phoenix");
  for (const bin of [serverBin, cliBin]) {
    if (!fs.existsSync(bin)) {
      throw new Error(`go build succeeded but expected binary is missing: ${bin}`);
    }
  }
  return { serverBin, cliBin };
}

export function phoenixServerVersion(binaries: PhoenixBinaries): string {
  const result = spawnSync(binaries.serverBin, ["--version"], { encoding: "utf8" });
  if (result.error || result.status !== 0) {
    return `unknown (${result.error?.message ?? `exit ${result.status}`})`;
  }
  return `${result.stdout}${result.stderr}`.trim();
}

export async function getFreePort(): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const probe = net.createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      if (!address || typeof address === "string") {
        probe.close(() => reject(new Error("could not determine free port")));
        return;
      }
      const { port } = address;
      probe.close((error) => (error ? reject(error) : resolve(port)));
    });
  });
}

export type HttpJsonResponse = {
  statusCode: number;
  body: unknown;
  raw: string;
};

export function httpJson(
  url: string,
  options: {
    method?: "GET" | "POST";
    headers?: Record<string, string>;
    body?: unknown;
    ca?: string;
    cert?: string;
    key?: string;
    timeoutMs?: number;
  } = {},
): Promise<HttpJsonResponse> {
  const parsed = new URL(url);
  const transport = parsed.protocol === "https:" ? https : http;
  const bodyText = options.body === undefined ? undefined : JSON.stringify(options.body);
  return new Promise<HttpJsonResponse>((resolve, reject) => {
    const request = transport.request(
      {
        method: options.method ?? "GET",
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || undefined,
        path: `${parsed.pathname}${parsed.search}`,
        headers: {
          accept: "application/json",
          ...(bodyText ? { "content-type": "application/json" } : {}),
          ...options.headers,
        },
        ...(options.ca ? { ca: options.ca } : {}),
        ...(options.cert ? { cert: options.cert } : {}),
        ...(options.key ? { key: options.key } : {}),
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
        response.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          let body: unknown;
          try {
            body = raw.trim() ? JSON.parse(raw) : undefined;
          } catch {
            body = undefined;
          }
          resolve({ statusCode: response.statusCode ?? 0, body, raw });
        });
      },
    );
    request.setTimeout(options.timeoutMs ?? 10000, () => {
      request.destroy(new Error(`request to ${url} timed out`));
    });
    request.on("error", reject);
    if (bodyText) {
      request.write(bodyText);
    }
    request.end();
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * A throwaway phoenix-server instance rooted in a fresh os.tmpdir() directory.
 * Lifecycle mirrors the Phoenix repo's tests/e2e/lib.sh:
 *   --init writes the store/config and prints a one-time admin token,
 *   the config is patched to listen on 127.0.0.1:<free port>,
 *   then the server runs as a child process until stop()/dispose().
 */
export class PhoenixServer {
  readonly binaries: PhoenixBinaries;
  runDir = "";
  adminToken = "";
  port = 0;
  url = "";
  caCertPath = "";
  private child?: ChildProcess;
  private serverLog: string[] = [];
  private https = false;

  constructor(binaries: PhoenixBinaries) {
    this.binaries = binaries;
  }

  get configPath(): string {
    return path.join(this.runDir, "config.json");
  }

  async init(): Promise<void> {
    this.runDir = await makeTmpDir("openclaw-phoenix-int-run-");
    const init = spawnSync(this.binaries.serverBin, ["--init", this.runDir], { encoding: "utf8" });
    if (init.error || init.status !== 0) {
      throw new Error(
        `phoenix-server --init failed: ${init.error?.message ?? `exit ${init.status}`}\n${init.stderr}`,
      );
    }
    const tokenMatch = /ADMIN TOKEN[\s\S]*?\n([a-f0-9]{32,})/.exec(init.stdout);
    if (!tokenMatch) {
      throw new Error(`could not parse the one-time admin token from phoenix-server --init output:\n${init.stdout}`);
    }
    this.adminToken = tokenMatch[1];
    this.caCertPath = path.join(this.runDir, "ca.crt");
    this.port = await getFreePort();
    await this.patchConfig((config) => {
      (config.server as Record<string, unknown>).listen = `127.0.0.1:${this.port}`;
    });
  }

  async patchConfig(mutate: (config: Record<string, unknown>) => void): Promise<void> {
    const config = JSON.parse(await fsp.readFile(this.configPath, "utf8")) as Record<string, unknown>;
    mutate(config);
    await fsp.writeFile(this.configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
  }

  async start(options: { https?: boolean } = {}): Promise<void> {
    if (this.child) {
      throw new Error("phoenix-server is already running");
    }
    this.https = options.https ?? false;
    this.url = `${this.https ? "https" : "http"}://127.0.0.1:${this.port}`;
    this.serverLog = [];
    const child = spawn(this.binaries.serverBin, ["--config", this.configPath], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout?.on("data", (chunk) => this.serverLog.push(String(chunk)));
    child.stderr?.on("data", (chunk) => this.serverLog.push(String(chunk)));
    this.child = child;
    liveChildren.add(child);
    child.on("exit", () => {
      liveChildren.delete(child);
    });

    const ca = this.https ? await fsp.readFile(this.caCertPath, "utf8") : undefined;
    for (let attempt = 0; attempt < HEALTH_WAIT_ATTEMPTS; attempt += 1) {
      if (child.exitCode !== null) {
        throw new Error(`phoenix-server exited during startup:\n${this.serverLog.join("")}`);
      }
      try {
        const health = await httpJson(`${this.url}/v1/health`, { ca, timeoutMs: 1000 });
        if (health.statusCode === 200) {
          return;
        }
      } catch {
        // not up yet
      }
      await sleep(HEALTH_WAIT_INTERVAL_MS);
    }
    throw new Error(`phoenix-server did not become healthy at ${this.url}:\n${this.serverLog.join("")}`);
  }

  async stop(): Promise<void> {
    const child = this.child;
    if (!child) {
      return;
    }
    this.child = undefined;
    if (child.exitCode === null) {
      const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
      child.kill("SIGTERM");
      const timeout = setTimeout(() => child.kill("SIGKILL"), 3000);
      await exited;
      clearTimeout(timeout);
    }
    liveChildren.delete(child);
  }

  async dispose(): Promise<void> {
    await this.stop();
    if (this.runDir) {
      await removeTmpDir(this.runDir);
    }
  }

  /** Run the phoenix CLI against this server (PHOENIX_SERVER/PHOENIX_TOKEN env). */
  cli(args: string[], options: { token?: string; env?: Record<string, string> } = {}): CliResult {
    const result = spawnSync(this.binaries.cliBin, args, {
      encoding: "utf8",
      env: {
        ...process.env,
        PHOENIX_SERVER: this.url,
        PHOENIX_TOKEN: options.token ?? this.adminToken,
        ...(this.https ? { PHOENIX_CA_CERT: this.caCertPath } : {}),
        ...options.env,
      },
      timeout: 30000,
    });
    if (result.error) {
      throw result.error;
    }
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  }

  /** Run the phoenix CLI and throw when it exits non-zero. */
  cliOk(args: string[], options: { token?: string; env?: Record<string, string> } = {}): CliResult {
    const result = this.cli(args, options);
    if (result.status !== 0) {
      throw new Error(`phoenix ${args.join(" ")} failed (exit ${result.status}):\n${result.stdout}\n${result.stderr}`);
    }
    return result;
  }

  async adminGet(pathname: string): Promise<HttpJsonResponse> {
    return await httpJson(`${this.url}${pathname}`, {
      headers: { authorization: `Bearer ${this.adminToken}` },
      ...(this.https ? { ca: await fsp.readFile(this.caCertPath, "utf8") } : {}),
    });
  }
}

export async function writeCredentialFile(filePath: string, contents: string): Promise<void> {
  await fsp.writeFile(filePath, `${contents}\n`, { encoding: "utf8", mode: 0o600 });
}
