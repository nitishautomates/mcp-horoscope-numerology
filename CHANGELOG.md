# Changelog

## [1.5.0] - 2026-07-24

### Added

- `divine_name_correction` tool for the new Chaldean Numerology Name Correction endpoint (`/numerology/v1/name-correction`, astroapi-7). Takes `full_name` + birth date and returns the current name number, life path and birthday numbers, an alignment percentage, the target name number, whether the name is already aligned, and suggested corrected spellings. Total tools 63 -> 64. This endpoint takes `full_name`, not `fname`/`lname` like its numerology siblings (verified live: fname/lname returns HTTP 422); deprecated fname/lname inputs are accepted but not forwarded.

## [1.4.2] - 2026-07-08

### Added

Add server-level instructions (how-to-use note read at connect: sign casing, h_day / current-prev-next selectors, PDF branding).

## [1.4.1] - 2026-07-08

### Fixed

**OAuth: clients registered without a scope are no longer rejected when they
request one.** The metadata advertises scope "astrology", so spec-following
connectors (e.g. ChatGPT) may request it even when their dynamic client
registration omitted it; registration now defaults the client scope to
"astrology" (default_scopes). Verified against the full simulated connector
flow: discovery, registration, PKCE authorize, login, token exchange.

## [1.4.0] - 2026-07-08

### Added

**Single-token authentication: `Authorization: Bearer <api_key>:<auth_token>`.**
For platforms that can send only one credential field and no custom headers
(e.g. the Claude Messages API MCP connector). The middleware splits the value
on the first colon and converts it to the internal JWT, exactly like the
X-Divine header pair. Real OAuth JWTs never contain a colon and pass through
untouched. Existing auth methods are unchanged.

## [1.3.0] - 2026-07-08

Param-parity fix batch for the Horoscope & Numerology server. Every change
below was verified against the live backend with curl before coding, and every
changed tool passed a live functional test after coding (23/23 astro,
14/14 PDF, including one real generated report per PDF tool).

### Base import

**v1.2.0 imported from PyPI/production.** The repository was stale at v1.0.0:
the code published to PyPI and running in the production container (v1.2.0)
was never committed to git. This commit's baseline is the extracted PyPI 1.2.0
`server.py`, which adds the `divine_pdf_reports_v2` tool (63 tools total) and
the `ApiKeyToJwtMiddleware` ASGI middleware. All 1.2.0 non-tool changes are
preserved byte-for-byte. Note: none of the parameter bugs below were fixed in
1.2.0; all fixes in this batch are new.

### Fixed (tools that FAILED ON EVERY CALL, now working)

**`divine_daily_horoscope` rewired to `h_day`.** The endpoint requires
`h_day` ('today', 'tomorrow', 'yesterday') and ignores day/month/year
entirely (byte-identical responses with and without them). The old tool sent
only day/month/year, so every call failed with "Please enter valid h_day."
New schema: required `h_day` (validated); day/month/year remain accepted as
deprecated optional inputs for backward compatibility but are not sent
upstream.

**`divine_yearly_horoscope` selector fixed.** The endpoint accepts ONLY
'current', 'prev', or 'next', but the old schema forced a 4-character year, so
'current' was rejected client-side and '2026' rejected server-side: no input
could ever succeed. The length constraint is gone; the value is validated
against the three selectors.

**`divine_love_compatibility` now takes the two signs.** The endpoint requires
`sign_1` and `sign_2`; the old tool sent neither (and `extra="forbid"` blocked
any workaround), failing every call. New required, validated zodiac-sign
params, lowercased before sending.

**`divine_which_animal_are_you` now takes name and birth date.** The endpoint
requires `full_name`, `day`, `month`, `year` (1901 to 2100); the old tool sent
only `lan` and failed every call.

**`divine_core_numbers` schema corrected.** The endpoint requires `full_name`
(it rejects fname/lname) and `method` ('general', 'chaldean', or
'pythagorean'); the old tool sent fname/lname and no method, failing every
call. `gender` is optional (the API accepts it but it provably does not change
the result). fname/lname/lan remain accepted as deprecated optional inputs,
not sent upstream.

**`divine_flames_calculator` field renamed to `your_name` (BREAKING, but the
old tool never worked).** The endpoint requires `your_name`; the old tool sent
`full_name` and got 422 "Please enter your name" on every call.

**Lifestyle tools now send `h_day` and `tzone`.** `divine_zodiac_gift_guru`,
`divine_beauty_by_stars`, and `divine_astro_chic_picks` all require h_day and
tzone (422 without); the old tools sent only sign+lan and failed every call.
h_day is validated client-side ('today', 'tomorrow', 'yesterday').

**`divine_pdf_natal_report` now takes `report_code` and `theme`.** Both are
required by the endpoint (e.g., 'CAREER-REPORT' and '001'); the old tool sent
neither and failed every call.

**`divine_pdf_couple_report` now takes `report_code`.** Required by the
endpoint (e.g., 'ALIGNED-ENERGIES-REPORT'); the old tool failed every call.

**`divine_pdf_numerology_prediction` and `divine_pdf_numerology_report`
schemas corrected.** The endpoints require `full_name` (not fname/lname),
`gender`, and a `report_code` (e.g., 'YEARLY-PREDICTION-3-YEAR' and
'SCHOLARLY-SPIRITS'); the old tools sent fname/lname and none of the rest,
failing every call. Birth time/place are optional for these reports and sent
only when provided. fname/lname remain accepted as deprecated optional inputs,
not sent upstream.

**`divine_pdf_reports_v2` transport fixed (new tool in 1.2.0, broken as
shipped).** The Reports V2 endpoint takes a JSON body with an `x-api-key`
header; the 1.2.0 tool posted form fields with an `api_key` field and got 401
"x-api-key header required" on every call. It now posts JSON with the correct
headers. The endpoint also requires ALL seven branding fields (including
company_mobile) plus footer_text and logo_url, which were missing from the
schema entirely; all are now required params.

### Changed (BREAKING schema tightening that matches API reality)

**PDF branding fields are now required on all 13 classic PDF tools.** The PDF
backend rejects every request that lacks company_name, company_url,
company_email, company_bio, logo_url, or footer_text (400 USER_INPUT_ERROR,
verified on every endpoint individually). They were previously optional and
silently dropped when empty, so any call without full branding failed at the
API. The schema now requires the six fields; only company_mobile remains
optional. This is a breaking schema change for callers who previously passed
branding, and a fix for everyone else, since those calls never succeeded.

**Weekly and monthly horoscope selectors validated.** The endpoints accept
ONLY 'current', 'prev', or 'next'. The old descriptions asked for a
'YYYY-MM-DD' week start and a month number like '03', both of which the API
rejects. Descriptions corrected and values validated client-side.

**API failures now raise ToolError.** `_call_divine_api` previously returned
plain "Error: ..." strings for HTTP errors and returned upstream error
envelopes (success=2/3, status='error') as if they were successes. It now
raises ToolError for non-2xx responses, network errors, and HTTP-200 error
envelopes, so MCP clients see isError: true. Plain "Error: ..." string returns
remain only for client-side enum validation of top-level params.

### Unchanged on purpose

The 12 tarot tools that call /api/v3/ paths where the master collection
documents /api/v2/ are left as-is: both versions are live (v3 returns a
richer 'cards' shape) and collection alignment is a separate decision.
