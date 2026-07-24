# Divine API - Horoscope & Numerology MCP Server

Official MCP server by Divine API for horoscopes, tarot readings, numerology,
love calculators, lifestyle insights, and PDF reports.

Provides **64 tools** across these families:

| Family | Tools | Host |
|--------|-------|------|
| Horoscopes (daily, weekly, monthly, yearly, Chinese, numerology) | 6 | astroapi-5 |
| Tarot and readings | 23 | astroapi-5 |
| Chaldean numerology | 13 | astroapi-7 |
| Core numbers | 1 | astroapi-4 |
| Mobile numerology | 2 | astroapi-7 |
| Calculators (FLAMES, love) | 2 | astroapi-7 |
| Lifestyle (gifts, beauty, fashion) | 3 | astroapi-7 |
| PDF reports (Vedic, Western, numerology, Reports V2) | 14 | pdf |

## Setup

1. Get your API key and auth token from https://divineapi.com/api-keys
2. Set environment variables: `DIVINE_API_KEY` and `DIVINE_AUTH_TOKEN`
3. Add to your MCP client configuration (Claude Desktop, Cursor, etc.)

Documentation: https://developers.divineapi.com

See CHANGELOG.md for recent schema fixes (several tools required parameter
changes to match the live API).
