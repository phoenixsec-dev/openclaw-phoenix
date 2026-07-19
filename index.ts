import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { resolvePhoenixPluginConfig, phoenixPluginConfigSchema } from "./src/config.ts";
import {
  createPhoenixListTool,
  createPhoenixResolveTool,
  createPhoenixStatusTool,
} from "./src/tools.ts";
import { registerPhoenixCli } from "./src/cli.ts";
import { runPhoenixStartupPreflightWarningOnly } from "./src/startup.ts";

export default definePluginEntry({
  id: "phoenix-secrets",
  name: "Phoenix Secrets Manager",
  description: "Phoenix runtime secret tools, CLI verification, and startup connectivity checks",
  configSchema: phoenixPluginConfigSchema,
  register(api) {
    const config = resolvePhoenixPluginConfig(api.pluginConfig, {
      resolvePath: api.resolvePath,
    });

    api.registerTool(
      (ctx) =>
        createPhoenixResolveTool(config, {
          agentId: ctx.agentId,
          sessionKey: ctx.sessionKey,
          sessionId: ctx.sessionId,
          messageChannel: ctx.messageChannel,
          requesterSenderId: ctx.requesterSenderId,
          senderIsOwner: ctx.senderIsOwner,
        }),
      { name: "phoenix_resolve", optional: true },
    );

    api.registerTool(
      (ctx) =>
        createPhoenixListTool(config, {
          agentId: ctx.agentId,
          sessionKey: ctx.sessionKey,
          sessionId: ctx.sessionId,
          messageChannel: ctx.messageChannel,
          requesterSenderId: ctx.requesterSenderId,
          senderIsOwner: ctx.senderIsOwner,
        }),
      { name: "phoenix_list", optional: true },
    );

    api.registerTool(
      (ctx) =>
        createPhoenixStatusTool(config, {
          agentId: ctx.agentId,
          sessionKey: ctx.sessionKey,
          sessionId: ctx.sessionId,
          messageChannel: ctx.messageChannel,
          requesterSenderId: ctx.requesterSenderId,
          senderIsOwner: ctx.senderIsOwner,
        }),
      { name: "phoenix_status", optional: true },
    );

    api.registerService({
      id: "phoenix-startup-check",
      start: async (ctx) => {
        await runPhoenixStartupPreflightWarningOnly(config, ctx.logger);
      },
    });

    api.registerCli(
      ({ program, config: openClawConfig, logger }) => {
        registerPhoenixCli({
          program,
          openClawConfig,
          pluginConfig: config,
          logger,
        });
      },
      { commands: ["phoenix"] },
    );
  },
});
