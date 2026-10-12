# Tartarus MCP gateway

The `tartarus-mcp` console script implements the local stdio MCP gateway. Its
tool surface and limits are declared in `policies/mcp-policy.yml`; it exposes
no network listener and accepts no free-form shell command.
