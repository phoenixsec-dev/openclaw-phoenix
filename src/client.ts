import fs from "node:fs/promises";
import { createPrivateKey, createPublicKey } from "node:crypto";
import http from "node:http";
import https from "node:https";
import type { Socket } from "node:net";
import type { PeerCertificate, TLSSocket } from "node:tls";
import { normalizeListPrefix, normalizePhoenixRef } from "./refs.ts";
import type { PhoenixPluginConfig } from "./config.ts";
import type { PhoenixCallerContext } from "./tool-helpers.ts";

export type PhoenixPeerCertificate = {
  subject?: Record<string, string>;
  issuer?: Record<string, string>;
  serialNumber?: string;
  fingerprint256?: string;
  validFrom?: string;
  validTo?: string;
  validNow?: boolean;
  daysRemaining?: number;
};

export type PhoenixApiErrorPayload = {
  type: "approval_required" | "access_denied" | "http_error" | "network_error";
  status: number;
  error: string;
  code?: string;
  detail?: string;
  remediation?: string;
  approvalId?: string;
  expiresAt?: string;
};

export type PhoenixResolveResponse = {
  mode: "plaintext" | "sealed";
  values: Record<string, string>;
  errors: Record<string, string>;
};

export type PhoenixStatusResponse = {
  ok: boolean;
  server: string;
  authMode: "bearer" | "mtls" | "bearer+mTLS";
  serverVersion: string | null;
  versionSource: "rest_api" | "unavailable";
  health: Record<string, unknown>;
  adminStatus?: Record<string, unknown>;
  adminStatusError?: PhoenixApiErrorPayload;
  tls?: PhoenixPeerCertificate;
  notes: string[];
};

export class PhoenixApiError extends Error {
  status: number;
  type: PhoenixApiErrorPayload["type"];
  code?: string;
  detail?: string;
  remediation?: string;
  approvalId?: string;
  expiresAt?: string;

  constructor(payload: PhoenixApiErrorPayload) {
    super(payload.detail ?? payload.error);
    this.name = "PhoenixApiError";
    this.status = payload.status;
    this.type = payload.type;
    this.code = payload.code;
    this.detail = payload.detail;
    this.remediation = payload.remediation;
    this.approvalId = payload.approvalId;
    this.expiresAt = payload.expiresAt;
  }

  toJSON(): PhoenixApiErrorPayload {
    return {
      type: this.type,
      status: this.status,
      error: this.message,
      ...(this.code ? { code: this.code } : {}),
      ...(this.detail ? { detail: this.detail } : {}),
      ...(this.remediation ? { remediation: this.remediation } : {}),
      ...(this.approvalId ? { approvalId: this.approvalId } : {}),
      ...(this.expiresAt ? { expiresAt: this.expiresAt } : {}),
    };
  }
}

type RequestOptions = {
  method: "GET" | "POST";
  pathname: string;
  query?: Record<string, string>;
  body?: unknown;
  toolName?: string;
  caller?: PhoenixCallerContext;
};

type JsonResponse = {
  statusCode: number;
  body: unknown;
  peerCertificate?: PhoenixPeerCertificate;
};

function normalizeAuthMode(config: PhoenixPluginConfig): PhoenixStatusResponse["authMode"] {
  const hasBearer = Boolean(config.token || config.tokenFile);
  const hasMtls = Boolean(config.clientCert && config.clientKey);
  if (hasBearer && hasMtls) {
    return "bearer+mTLS";
  }
  if (hasMtls) {
    return "mtls";
  }
  return "bearer";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function buildCallerHeaders(caller?: PhoenixCallerContext): Record<string, string> {
  if (!caller) {
    return {};
  }
  const headers: Record<string, string> = {};
  if (caller.agentId) {
    headers["X-OpenClaw-Agent"] = caller.agentId;
  }
  if (caller.sessionKey) {
    headers["X-OpenClaw-Session-Key"] = caller.sessionKey;
  }
  if (caller.sessionId) {
    headers["X-OpenClaw-Session-Id"] = caller.sessionId;
  }
  if (caller.messageChannel) {
    headers["X-OpenClaw-Channel"] = caller.messageChannel;
  }
  if (caller.requesterSenderId) {
    headers["X-OpenClaw-Requester-Sender"] = caller.requesterSenderId;
  }
  if (caller.senderIsOwner === true) {
    headers["X-OpenClaw-Sender-Is-Owner"] = "true";
  }
  return headers;
}

const SEAL_KEY_SIZE_BYTES = 32;
const X25519_PRIVATE_KEY_DER_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_PUBLIC_KEY_DER_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function encodeOpaqueSealedToken(envelope: unknown): string {
  return `PHOENIX_SEALED:${Buffer.from(JSON.stringify(envelope), "utf8").toString("base64")}`;
}

function decodeSealPrivateKey(raw: string, source: string): Buffer {
  const encoded = raw.trim();
  if (!encoded) {
    throw new Error(`Phoenix seal key file is empty: ${source}`);
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 !== 0) {
    throw new Error(`Phoenix seal key file contains invalid base64: ${source}`);
  }
  const privateKey = Buffer.from(encoded, "base64");
  if (privateKey.length !== SEAL_KEY_SIZE_BYTES) {
    throw new Error(
      `Phoenix seal key file must contain a base64-encoded ${SEAL_KEY_SIZE_BYTES}-byte private key: ${source}`,
    );
  }
  return privateKey;
}

function deriveSealPublicKey(privateKey: Buffer, source: string): Buffer {
  try {
    const keyObject = createPrivateKey({
      key: Buffer.concat([X25519_PRIVATE_KEY_DER_PREFIX, privateKey]),
      format: "der",
      type: "pkcs8",
    });
    const publicDer = createPublicKey(keyObject).export({ format: "der", type: "spki" });
    if (!Buffer.isBuffer(publicDer) || publicDer.length !== X25519_PUBLIC_KEY_DER_PREFIX.length + SEAL_KEY_SIZE_BYTES) {
      throw new Error("unexpected X25519 public key export format");
    }
    if (!publicDer.subarray(0, X25519_PUBLIC_KEY_DER_PREFIX.length).equals(X25519_PUBLIC_KEY_DER_PREFIX)) {
      throw new Error("unexpected X25519 public key DER prefix");
    }
    return Buffer.from(publicDer.subarray(X25519_PUBLIC_KEY_DER_PREFIX.length));
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Could not derive Phoenix seal public key from ${source}: ${detail}`);
  }
}

async function loadSealPrivateKey(sealKeyFile: string): Promise<Buffer> {
  const stat = await fs.stat(sealKeyFile);
  if (!stat.isFile()) {
    throw new Error(`Phoenix seal key path must be a file: ${sealKeyFile}`);
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(
      `Phoenix seal key file has insecure permissions: ${sealKeyFile} must not be readable, writable, or executable by group or others`,
    );
  }

  const rawPrivateKey = await fs.readFile(sealKeyFile, "utf8");
  return decodeSealPrivateKey(rawPrivateKey, sealKeyFile);
}

async function buildSealHeader(sealKeyFile: string): Promise<string> {
  const privateKey = await loadSealPrivateKey(sealKeyFile);
  const publicKey = deriveSealPublicKey(privateKey, sealKeyFile);
  return publicKey.toString("base64");
}

function normalizePeerCertificate(socket?: Socket | null): PhoenixPeerCertificate | undefined {
  const tlsSocket = socket as TLSSocket | undefined;
  if (!tlsSocket || typeof tlsSocket.getPeerCertificate !== "function") {
    return undefined;
  }
  const certificate = tlsSocket.getPeerCertificate(true) as PeerCertificate | null;
  if (!certificate || Object.keys(certificate).length === 0) {
    return undefined;
  }
  const validFrom = certificate.valid_from;
  const validTo = certificate.valid_to;
  const validToDate = validTo ? new Date(validTo) : undefined;
  const validNow = validToDate ? validToDate.getTime() > Date.now() : undefined;
  const daysRemaining = validToDate ? Math.floor((validToDate.getTime() - Date.now()) / 86400000) : undefined;
  return {
    ...(certificate.subject ? { subject: certificate.subject as Record<string, string> } : {}),
    ...(certificate.issuer ? { issuer: certificate.issuer as Record<string, string> } : {}),
    ...(certificate.serialNumber ? { serialNumber: certificate.serialNumber } : {}),
    ...(certificate.fingerprint256 ? { fingerprint256: certificate.fingerprint256 } : {}),
    ...(validFrom ? { validFrom } : {}),
    ...(validTo ? { validTo } : {}),
    ...(typeof validNow === "boolean" ? { validNow } : {}),
    ...(typeof daysRemaining === "number" ? { daysRemaining } : {}),
  };
}

function toApiError(statusCode: number, body: unknown): PhoenixApiError {
  const detail = isRecord(body) && typeof body.detail === "string" ? body.detail : undefined;
  const remediation =
    isRecord(body) && typeof body.remediation === "string" ? body.remediation : undefined;
  const code = isRecord(body) && typeof body.code === "string" ? body.code : undefined;
  const errorMessage =
    isRecord(body) && typeof body.error === "string"
      ? body.error
      : `Phoenix request failed with HTTP ${statusCode}`;

  if (
    statusCode === 202 ||
    (isRecord(body) && body.status === "approval_required")
  ) {
    throw new PhoenixApiError({
      type: "approval_required",
      status: statusCode,
      error: errorMessage,
      ...(code ? { code } : {}),
      ...(detail ? { detail } : {}),
      ...(remediation ? { remediation } : {}),
      ...(isRecord(body) && typeof body.approval_id === "string"
        ? { approvalId: body.approval_id }
        : {}),
      ...(isRecord(body) && typeof body.expires_at === "string"
        ? { expiresAt: body.expires_at }
        : {}),
    });
  }

  return new PhoenixApiError({
    type: statusCode === 401 || statusCode === 403 ? "access_denied" : "http_error",
    status: statusCode,
    error: errorMessage,
    ...(code ? { code } : {}),
    ...(detail ? { detail } : {}),
    ...(remediation ? { remediation } : {}),
  });
}

export function toPhoenixErrorPayload(error: unknown): PhoenixApiErrorPayload {
  if (error instanceof PhoenixApiError) {
    return error.toJSON();
  }
  const message = error instanceof Error ? error.message : String(error);
  return {
    type: "network_error",
    status: 0,
    error: message,
    detail: message,
  };
}

export function formatPhoenixError(error: unknown): string {
  const payload = toPhoenixErrorPayload(error);
  const lines = [payload.detail ?? payload.error];
  if (payload.code) {
    lines.push(`code: ${payload.code}`);
  }
  if (payload.remediation) {
    lines.push(`remediation: ${payload.remediation}`);
  }
  if (payload.approvalId) {
    lines.push(`approval_id: ${payload.approvalId}`);
  }
  return lines.join("; ");
}

export class PhoenixClient {
  private readonly config: PhoenixPluginConfig;
  private tlsMaterialPromise?: Promise<{ ca?: string; cert?: string; key?: string }>;
  private tokenFilePromise?: Promise<string>;
  private sealHeaderPromise?: Promise<string>;

  constructor(config: PhoenixPluginConfig) {
    this.config = config;
  }

  private async loadBearerToken(): Promise<string | undefined> {
    if (this.config.token) {
      return this.config.token;
    }
    if (!this.config.tokenFile) {
      return undefined;
    }
    if (!this.tokenFilePromise) {
      this.tokenFilePromise = fs.readFile(this.config.tokenFile, "utf8").then((raw) => {
        const token = raw.trim();
        if (!token) {
          throw new Error(`Phoenix token file is empty: ${this.config.tokenFile}`);
        }
        return token;
      });
    }
    return await this.tokenFilePromise;
  }

  private async loadTlsMaterial() {
    if (!this.tlsMaterialPromise) {
      this.tlsMaterialPromise = (async () => ({
        ...(this.config.caCert ? { ca: await fs.readFile(this.config.caCert, "utf8") } : {}),
        ...(this.config.clientCert
          ? { cert: await fs.readFile(this.config.clientCert, "utf8") }
          : {}),
        ...(this.config.clientKey ? { key: await fs.readFile(this.config.clientKey, "utf8") } : {}),
      }))();
    }
    return this.tlsMaterialPromise;
  }

  private async loadSealHeader(): Promise<string> {
    if (!this.config.sealKeyFile) {
      throw new Error("Phoenix sealMode requires sealKeyFile (or PHOENIX_SEAL_KEY)");
    }
    if (!this.sealHeaderPromise) {
      this.sealHeaderPromise = buildSealHeader(this.config.sealKeyFile);
    }
    return this.sealHeaderPromise;
  }

  async validateSealConfiguration(): Promise<void> {
    if (this.config.sealMode) {
      await this.loadSealHeader();
    }
  }

  private async requestJson(options: RequestOptions): Promise<JsonResponse> {
    const url = new URL(options.pathname, `${this.config.server}/`);
    if (options.query) {
      for (const [key, value] of Object.entries(options.query)) {
        url.searchParams.set(key, value);
      }
    }

    const bodyText = options.body === undefined ? undefined : JSON.stringify(options.body);
    const bearerToken = await this.loadBearerToken();
    const headers: Record<string, string> = {
      accept: "application/json",
      ...buildCallerHeaders(options.caller),
      ...(options.toolName ? { "X-Phoenix-Tool": options.toolName } : {}),
      ...(bearerToken ? { authorization: `Bearer ${bearerToken}` } : {}),
      ...(bodyText ? { "content-type": "application/json", "content-length": String(Buffer.byteLength(bodyText)) } : {}),
    };

    if (this.config.sealMode && options.toolName === "phoenix_resolve") {
      headers["X-Phoenix-Seal-Key"] = await this.loadSealHeader();
    }

    const transport = url.protocol === "https:" ? https : http;
    const tlsMaterial = url.protocol === "https:" ? await this.loadTlsMaterial() : {};

    return await new Promise<JsonResponse>((resolve, reject) => {
      const request = transport.request(
        {
          method: options.method,
          protocol: url.protocol,
          hostname: url.hostname,
          port: url.port || undefined,
          path: `${url.pathname}${url.search}`,
          headers,
          ...(url.protocol === "https:" ? tlsMaterial : {}),
        },
        (response) => {
          const chunks: Buffer[] = [];
          response.on("data", (chunk) => {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
          });
          response.on("end", () => {
            const rawBody = Buffer.concat(chunks).toString("utf8");
            let parsedBody: unknown = undefined;
            if (rawBody.trim()) {
              try {
                parsedBody = JSON.parse(rawBody);
              } catch {
                reject(new Error(`Phoenix returned non-JSON response: ${rawBody}`));
                return;
              }
            }
            resolve({
              statusCode: response.statusCode ?? 0,
              body: parsedBody,
              peerCertificate: normalizePeerCertificate(response.socket),
            });
          });
        },
      );

      request.on("error", (error) => {
        reject(
          new PhoenixApiError({
            type: "network_error",
            status: 0,
            error: `Phoenix request failed: ${error.message}`,
            detail: `Could not reach Phoenix at ${this.config.server}`,
            remediation:
              "Check the server URL, network reachability, and any configured CA/client certificate paths.",
          }),
        );
      });

      request.setTimeout(10000, () => {
        request.destroy(
          new PhoenixApiError({
            type: "network_error",
            status: 0,
            error: "Phoenix request timed out",
            detail: `Timed out connecting to ${this.config.server}`,
            remediation:
              "Verify Phoenix is reachable and responding, and confirm any TLS credentials are valid.",
          }),
        );
      });

      if (bodyText) {
        request.write(bodyText);
      }
      request.end();
    });
  }

  async health(options: { toolName?: string; caller?: PhoenixCallerContext } = {}) {
    const response = await this.requestJson({
      method: "GET",
      pathname: "/v1/health",
      toolName: options.toolName,
      caller: options.caller,
    });
    if (response.statusCode !== 200) {
      throw toApiError(response.statusCode, response.body);
    }
    return {
      health: isRecord(response.body) ? response.body : {},
      peerCertificate: response.peerCertificate,
    };
  }

  async resolve(
    refs: string[],
    options: { caller?: PhoenixCallerContext; dryRun?: boolean } = {},
  ): Promise<PhoenixResolveResponse> {
    const normalizedRefs = refs.map((ref) => normalizePhoenixRef(ref, this.config.defaultNamespace));
    const response = await this.requestJson({
      method: "POST",
      pathname: "/v1/resolve",
      ...(options.dryRun ? { query: { dry_run: "true" } } : {}),
      body: { refs: normalizedRefs },
      toolName: "phoenix_resolve",
      caller: options.caller,
    });

    if (response.statusCode === 202) {
      throw toApiError(response.statusCode, response.body);
    }
    if (response.statusCode !== 200) {
      throw toApiError(response.statusCode, response.body);
    }
    if (!isRecord(response.body)) {
      throw new Error("Phoenix resolve response was not an object");
    }

    const errors = isRecord(response.body.errors)
      ? Object.fromEntries(
          Object.entries(response.body.errors).filter((entry): entry is [string, string] => typeof entry[1] === "string"),
        )
      : {};

    if (this.config.sealMode && !options.dryRun) {
      const sealedValues = isRecord(response.body.sealed_values) ? response.body.sealed_values : {};
      return {
        mode: "sealed",
        values: Object.fromEntries(
          Object.entries(sealedValues).map(([ref, envelope]) => [ref, encodeOpaqueSealedToken(envelope)]),
        ),
        errors,
      };
    }

    const values = isRecord(response.body.values)
      ? Object.fromEntries(
          Object.entries(response.body.values).filter((entry): entry is [string, string] => typeof entry[1] === "string"),
        )
      : {};

    return {
      mode: "plaintext",
      values,
      errors,
    };
  }

  async list(prefix?: string, options: { caller?: PhoenixCallerContext } = {}) {
    const normalizedPrefix = normalizeListPrefix(prefix, this.config.defaultNamespace);
    const response = await this.requestJson({
      method: "GET",
      pathname: `/v1/secrets/${normalizedPrefix}`,
      toolName: "phoenix_list",
      caller: options.caller,
    });
    if (response.statusCode !== 200) {
      throw toApiError(response.statusCode, response.body);
    }
    if (!isRecord(response.body)) {
      throw new Error("Phoenix list response was not an object");
    }
    const paths = Array.isArray(response.body.paths)
      ? response.body.paths.filter((entry): entry is string => typeof entry === "string")
      : [];
    return {
      prefix: normalizedPrefix,
      paths,
    };
  }

  async status(options: { caller?: PhoenixCallerContext } = {}): Promise<PhoenixStatusResponse> {
    const notes: string[] = [];
    await this.validateSealConfiguration();
    if (this.config.sealMode) {
      notes.push("Phoenix sealed mode is enabled and the configured seal key file loaded successfully.");
    }

    const { health, peerCertificate } = await this.health({
      toolName: "phoenix_status",
      caller: options.caller,
    });

    let adminStatus: Record<string, unknown> | undefined;
    let adminStatusError: PhoenixApiErrorPayload | undefined;
    try {
      const response = await this.requestJson({
        method: "GET",
        pathname: "/v1/status",
        toolName: "phoenix_status",
        caller: options.caller,
      });
      if (response.statusCode === 200 && isRecord(response.body)) {
        adminStatus = response.body;
      } else if (response.statusCode !== 200) {
        throw toApiError(response.statusCode, response.body);
      }
    } catch (error) {
      adminStatusError = toPhoenixErrorPayload(error);
      notes.push(
        adminStatusError.type === "access_denied"
          ? "Admin-only /v1/status details are unavailable with the current Phoenix credentials."
          : "Could not fetch admin-only /v1/status details.",
      );
    }

    notes.push("Phoenix REST API does not currently expose the server version, so serverVersion is null.");

    return {
      ok: true,
      server: this.config.server,
      authMode: normalizeAuthMode(this.config),
      serverVersion: null,
      versionSource: "unavailable",
      health,
      ...(adminStatus ? { adminStatus } : {}),
      ...(adminStatusError ? { adminStatusError } : {}),
      ...(peerCertificate ? { tls: peerCertificate } : {}),
      notes,
    };
  }
}
