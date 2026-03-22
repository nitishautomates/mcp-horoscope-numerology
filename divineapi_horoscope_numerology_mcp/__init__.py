"""Divine API - Horoscope & Numerology MCP Server."""
from .server import mcp

def main():
    """Entry point for the MCP server (stdio mode)."""
    mcp.run(transport="stdio")

def main_http():
    """Entry point for the MCP server (HTTP mode)."""
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)
