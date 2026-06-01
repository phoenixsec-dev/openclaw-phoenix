import type { PhoenixPluginConfig } from "./config.ts";
import { PhoenixClient, toPhoenixErrorPayload } from "./client.ts";
import { selectPhoenixClientConfigForCaller } from "./identity.ts";
import {
  jsonResult,
  readStringArrayParam,
  readStringParam,
  type PhoenixCallerContext,
} from "./tool-helpers.ts";

const ResolveParameters = {
  type: "object",
  additionalProperties: false,
  properties: {
    refs: {
      type: "array",
      items: { type: "string" },
      description: "One or more phoenix:// refs. Bare ids use defaultNamespace when configured.",
    },
  },
  required: ["refs"],
};

const ListParameters = {
  type: "object",
  additionalProperties: false,
  properties: {
    prefix: {
      type: "string",
      description: "Optional prefix or phoenix:// ref prefix to list under.",
    },
  },
};

const StatusParameters = {
  type: "object",
  additionalProperties: false,
  properties: {},
};

function createClient(config: PhoenixPluginConfig, caller?: PhoenixCallerContext): PhoenixClient {
  return new PhoenixClient(selectPhoenixClientConfigForCaller(config, caller));
}

export function createPhoenixResolveTool(
  config: PhoenixPluginConfig,
  caller?: PhoenixCallerContext,
) {
  return {
    name: "phoenix_resolve",
    label: "Phoenix Resolve",
    description:
      "Resolve one or more phoenix:// refs through Phoenix Secrets Manager. Returns PHOENIX_SEALED tokens when sealMode is enabled.",
    parameters: ResolveParameters,
    execute: async (_toolCallId: string, rawParams: Record<string, unknown>) => {
      try {
        const refs = readStringArrayParam(rawParams, "refs", { required: true }) ?? [];
        const client = createClient(config, caller);
        const result = await client.resolve(refs, { caller });
        const errorCount = Object.keys(result.errors).length;
        const valueCount = Object.keys(result.values).length;
        return jsonResult({
          ok: errorCount === 0,
          partial: errorCount > 0 && valueCount > 0,
          mode: result.mode,
          values: result.values,
          errors: result.errors,
          requested: refs.length,
          resolved: valueCount,
        });
      } catch (error) {
        return jsonResult({
          ok: false,
          error: toPhoenixErrorPayload(error),
        });
      }
    },
  };
}

export function createPhoenixListTool(config: PhoenixPluginConfig, caller?: PhoenixCallerContext) {
  return {
    name: "phoenix_list",
    label: "Phoenix List",
    description: "List secret paths visible to the current Phoenix credentials.",
    parameters: ListParameters,
    execute: async (_toolCallId: string, rawParams: Record<string, unknown>) => {
      try {
        const prefix = readStringParam(rawParams, "prefix");
        const client = createClient(config, caller);
        const result = await client.list(prefix, { caller });
        return jsonResult({
          ok: true,
          prefix: result.prefix,
          count: result.paths.length,
          paths: result.paths,
        });
      } catch (error) {
        return jsonResult({
          ok: false,
          error: toPhoenixErrorPayload(error),
        });
      }
    },
  };
}

export function createPhoenixStatusTool(config: PhoenixPluginConfig, caller?: PhoenixCallerContext) {
  return {
    name: "phoenix_status",
    label: "Phoenix Status",
    description: "Check Phoenix connectivity, admin-visible status, and TLS certificate health.",
    parameters: StatusParameters,
    execute: async () => {
      try {
        const client = createClient(config, caller);
        return jsonResult(await client.status({ caller }));
      } catch (error) {
        return jsonResult({
          ok: false,
          error: toPhoenixErrorPayload(error),
        });
      }
    },
  };
}
