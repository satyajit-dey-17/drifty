# Release Notes

## v0.7.0

### Added
- **MCP Server** (`drifty-mcp`) — exposes Drifty as a [Model Context Protocol](https://modelcontextprotocol.io) server so AI assistants (Cursor, Claude Desktop, etc.) can call drift detection directly as a structured tool.
- Two MCP tools available: `detect_drift` (full attribute diff + remediation hints) and `score_drift` (fast severity summary).
- New `drifty-mcp` CLI entrypoint registered via `pyproject.toml` — works out of the box with any MCP-compatible client config.
- MCP is an optional install: `pip install "drifty[mcp]"` — existing users are unaffected.
- `examples/mcp_client_test.py` — raw stdio JSON-RPC smoke test for verifying the MCP server without a subscription or external client.