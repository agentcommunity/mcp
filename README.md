# Agent Community MCP connector

`@agentcommunity/mcp` is the official stdio compatibility connector for Agent Community's hosted MCP server at `https://agentcommunity.org/mcp`. It is published by Agent Community from `https://github.com/agentcommunity/mcp`.

It does not implement or copy the server, expose an SDK API, add authentication, or call a tool during startup. It launches the pinned `mcp-remote` transport bridge so stdio-only clients can use the existing anonymous Streamable HTTP endpoint.

## Run

```sh
npx -y @agentcommunity/mcp
```

The installed executable is `agentcommunity-mcp`. Clients with native remote Streamable HTTP support should connect directly to `https://agentcommunity.org/mcp` instead.

## Verify ownership

- Homepage and documentation: https://agentcommunity.org/developers
- Source: https://github.com/agentcommunity/mcp
- Package: https://www.npmjs.com/package/@agentcommunity/mcp
- Hosted server card: https://agentcommunity.org/.well-known/mcp/server-card.json
