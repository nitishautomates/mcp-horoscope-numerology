#!/usr/bin/env python3
"""
Divine API - Horoscope & Numerology MCP Server

Official MCP server by Divine API for Horoscope, Tarot, Numerology & PDF Reports.
Provides 63 tools for daily/weekly/monthly/yearly horoscopes, tarot readings,
numerology analysis, love calculators, lifestyle insights, and PDF reports.

Setup:
    1. Get your API key and auth token from https://divineapi.com/api-keys
    2. Set environment variables: DIVINE_API_KEY and DIVINE_AUTH_TOKEN
    3. Add to your MCP client configuration (Claude Desktop, Cursor, etc.)

Documentation: https://developers.divineapi.com
"""

import base64
import json
import os
import secrets
import sys
import time

import httpx
import jwt
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl, BaseModel, Field, ConfigDict, field_validator

# ──────────────────────────────────────────────
# Server Initialization
# ──────────────────────────────────────────────

_TRANSPORT = os.environ.get("MCP_TRANSPORT", "stdio")
_MCP_HOST = os.environ.get("MCP_HOST", "mcp.divineapi.com")
_JWT_SECRET = os.environ.get("MCP_JWT_SECRET", secrets.token_hex(32))

_transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=[
        f"{_MCP_HOST}",
        f"{_MCP_HOST}:*",
        "127.0.0.1:*",
        "localhost:*",
    ],
) if _TRANSPORT == "http" else None


# ──────────────────────────────────────────────
# OAuth Provider — maps OAuth Client ID/Secret to Divine API credentials
# ──────────────────────────────────────────────


class DivineOAuthProvider(OAuthAuthorizationServerProvider):
    """OAuth provider that uses Divine API Key as client_id and Auth Token as client_secret."""

    def __init__(self, jwt_secret: str):
        self._jwt_secret = jwt_secret
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._auth_codes: dict[str, dict] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if client_id in self._clients:
            return self._clients[client_id]
        auto_client = OAuthClientInformationFull(
            client_id=client_id,
            client_secret=None,
            redirect_uris=['https://claude.ai/oauth/callback', 'https://app.claude.ai/oauth/callback', 'https://claude.ai/api/mcp/auth_callback', 'https://app.claude.ai/api/mcp/auth_callback'],
            grant_types=['authorization_code', 'refresh_token'],
            response_types=['code'],
            token_endpoint_auth_method='client_secret_post',
            scope='astrology',
        )
        self._clients[client_id] = auto_client
        return auto_client

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        pending_id = secrets.token_urlsafe(16)
        self._pending_auths = getattr(self, "_pending_auths", {})
        self._pending_auths[pending_id] = {
            "client_id": client.client_id,
            "code_challenge": params.code_challenge,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "scopes": params.scopes or [],
            "state": params.state,
        }
        return f"/divine-login?pending={pending_id}"

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> AuthorizationCode | None:
        data = self._auth_codes.get(authorization_code)
        if not data or data["client_id"] != client.client_id:
            return None
        if time.time() > data["expires_at"]:
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=data["scopes"],
            expires_at=data["expires_at"],
            client_id=data["client_id"],
            code_challenge=data["code_challenge"],
            redirect_uri=AnyUrl(data["redirect_uri"]),
            redirect_uri_provided_explicitly=data["redirect_uri_provided_explicitly"],
        )

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        data = self._auth_codes.pop(authorization_code.code, None)
        if not data:
            raise TokenError(error="invalid_grant", error_description="Authorization code not found")

        payload = {
            "divine_api_key": data.get("divine_api_key", ""),
            "divine_auth_token": data.get("divine_auth_token", ""),
            "exp": int(time.time()) + 86400 * 30,
            "iat": int(time.time()),
        }
        access_token = jwt.encode(payload, self._jwt_secret, algorithm="HS256")

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=86400 * 30,
        )

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        return None

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        raise TokenError(error="unsupported_grant_type", error_description="Refresh tokens not supported")

    async def load_access_token(self, token: str) -> AccessToken | None:
        try:
            payload = jwt.decode(token, self._jwt_secret, algorithms=["HS256"])
            return AccessToken(
                token=token,
                client_id=payload["divine_api_key"],
                scopes=[],
                expires_at=payload.get("exp"),
                resource=None,
            )
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        pass


# Build auth settings for HTTP mode
_auth_settings = None
_auth_provider = None
if _TRANSPORT == "http":
    _auth_provider = DivineOAuthProvider(_JWT_SECRET)
    _auth_settings = AuthSettings(
        issuer_url=f"https://{_MCP_HOST}/horoscope",
        resource_server_url=f"https://{_MCP_HOST}/horoscope",
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["astrology"],
            default_scopes=["astrology"],
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=[],
    )

mcp = FastMCP(
    "divineapi_horoscope_numerology_mcp",
    stateless_http=(_TRANSPORT == "http"),
    transport_security=_transport_security,
    auth=_auth_settings,
    auth_server_provider=_auth_provider,
)

# ──────────────────────────────────────────────
# Configuration — Base URLs for API hosts
# ──────────────────────────────────────────────

API_HOST_4 = "https://astroapi-4.divineapi.com"
API_HOST_5 = "https://astroapi-5.divineapi.com"
API_HOST_7 = "https://astroapi-7.divineapi.com"
API_HOST_PDF = "https://pdf.divineapi.com"

DIVINE_API_KEY = os.environ.get("DIVINE_API_KEY", "")
DIVINE_AUTH_TOKEN = os.environ.get("DIVINE_AUTH_TOKEN", "")

if _TRANSPORT == "stdio" and (not DIVINE_API_KEY or not DIVINE_AUTH_TOKEN):
    print(
        "WARNING: DIVINE_API_KEY and DIVINE_AUTH_TOKEN environment variables are required. "
        "Get yours at https://divineapi.com/api-keys",
        file=sys.stderr,
    )


def _get_credentials(ctx: Context | None = None) -> tuple[str, str]:
    """Extract Divine API credentials from JWT Bearer token, request headers, or env vars."""
    api_key = DIVINE_API_KEY
    auth_token = DIVINE_AUTH_TOKEN
    if ctx:
        try:
            request = getattr(ctx.request_context, "request", None)
            if request and hasattr(request, "headers"):
                auth_header = request.headers.get("authorization", "")
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:]
                    try:
                        payload = jwt.decode(token, _JWT_SECRET, algorithms=["HS256"])
                        api_key = payload.get("divine_api_key", api_key)
                        auth_token = payload.get("divine_auth_token", auth_token)
                    except Exception:
                        pass
                api_key = request.headers.get("x-divine-api-key", api_key)
                auth_token = request.headers.get("x-divine-auth-token", auth_token)
        except Exception:
            pass
    if not api_key or not auth_token:
        raise ValueError(
            "Divine API credentials required. "
            "Set X-Divine-Api-Key and X-Divine-Auth-Token headers, "
            "or DIVINE_API_KEY and DIVINE_AUTH_TOKEN environment variables. "
            "Get yours at https://divineapi.com/api-keys"
        )
    return api_key, auth_token

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

VALID_ZODIAC_SIGNS = {
    "aries", "taurus", "gemini", "cancer", "leo", "virgo",
    "libra", "scorpio", "sagittarius", "capricorn", "aquarius", "pisces",
}

VALID_CHINESE_SIGNS = {
    "rat", "ox", "tiger", "rabbit", "dragon", "snake",
    "horse", "goat", "monkey", "rooster", "dog", "pig",
}

# Day selector used by the daily horoscope, Chinese horoscope, and lifestyle endpoints.
VALID_H_DAYS = {"today", "tomorrow", "yesterday"}

# The weekly/monthly/yearly horoscope endpoints accept ONLY these selectors
# (verified live 2026-07-08; calendar values like '2026-03-16', '03' or '2026'
# are rejected with "Please enter valid ... current, prev or next").
VALID_PERIOD_SELECTORS = {"current", "prev", "next"}

# Calculation methods accepted by the core-numbers endpoint (verified live 2026-07-08).
VALID_CORE_METHODS = {"general", "chaldean", "pythagorean"}

VALID_GENDERS = {"male", "female"}

TOOL_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}

# ──────────────────────────────────────────────
# Pydantic Models
# ──────────────────────────────────────────────


class HoroscopeInput(BaseModel):
    """Input for daily horoscope API calls. Requires zodiac sign, day selector, and timezone."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    sign: str = Field(..., description="Zodiac sign (e.g., 'aries', 'taurus', 'gemini')")
    h_day: str = Field(..., description="Day selector: 'today', 'tomorrow', or 'yesterday'")
    tzone: str = Field(..., description="Timezone offset from UTC (e.g., '5.5' for IST)")
    lan: str = Field(default="en", description="Language code for response (default 'en')")
    day: str | None = Field(default=None, description="Deprecated: ignored by this endpoint, the reading is selected via h_day. Accepted for backward compatibility, not sent to the API.")
    month: str | None = Field(default=None, description="Deprecated: ignored by this endpoint, the reading is selected via h_day. Accepted for backward compatibility, not sent to the API.")
    year: str | None = Field(default=None, description="Deprecated: ignored by this endpoint, the reading is selected via h_day. Accepted for backward compatibility, not sent to the API.")

    @field_validator("sign")
    @classmethod
    def validate_sign(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_ZODIAC_SIGNS:
            raise ValueError(f"Invalid zodiac sign '{v}'. Must be one of: {', '.join(sorted(VALID_ZODIAC_SIGNS))}")
        return v

    @field_validator("h_day")
    @classmethod
    def validate_h_day(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_H_DAYS:
            raise ValueError(f"Invalid h_day '{v}'. Must be one of: {', '.join(sorted(VALID_H_DAYS))}")
        return v


class WeeklyHoroscopeInput(BaseModel):
    """Input for weekly horoscope API calls. Requires zodiac sign and week selector."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    sign: str = Field(..., description="Zodiac sign (e.g., 'aries', 'taurus')")
    week: str = Field(..., description="Week selector: 'current', 'prev', or 'next'. Calendar dates are not accepted by the API.")
    tzone: str = Field(..., description="Timezone offset from UTC (e.g., '5.5')")
    lan: str = Field(default="en", description="Language code for response (default 'en')")

    @field_validator("sign")
    @classmethod
    def validate_sign(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_ZODIAC_SIGNS:
            raise ValueError(f"Invalid zodiac sign '{v}'. Must be one of: {', '.join(sorted(VALID_ZODIAC_SIGNS))}")
        return v

    @field_validator("week")
    @classmethod
    def validate_week(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_PERIOD_SELECTORS:
            raise ValueError(f"Invalid week '{v}'. Must be one of: {', '.join(sorted(VALID_PERIOD_SELECTORS))}")
        return v


class MonthlyHoroscopeInput(BaseModel):
    """Input for monthly horoscope API calls. Requires zodiac sign and month selector."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    sign: str = Field(..., description="Zodiac sign (e.g., 'aries', 'taurus')")
    month: str = Field(..., description="Month selector: 'current', 'prev', or 'next'. Month numbers like '03' are not accepted by the API.")
    tzone: str = Field(..., description="Timezone offset from UTC (e.g., '5.5')")
    lan: str = Field(default="en", description="Language code for response (default 'en')")

    @field_validator("sign")
    @classmethod
    def validate_sign(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_ZODIAC_SIGNS:
            raise ValueError(f"Invalid zodiac sign '{v}'. Must be one of: {', '.join(sorted(VALID_ZODIAC_SIGNS))}")
        return v

    @field_validator("month")
    @classmethod
    def validate_month(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_PERIOD_SELECTORS:
            raise ValueError(f"Invalid month '{v}'. Must be one of: {', '.join(sorted(VALID_PERIOD_SELECTORS))}")
        return v


class YearlyHoroscopeInput(BaseModel):
    """Input for yearly horoscope API calls. Requires zodiac sign and year selector."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    sign: str = Field(..., description="Zodiac sign (e.g., 'aries', 'taurus')")
    year: str = Field(..., description="Year selector: 'current', 'prev', or 'next'. Calendar years like '2026' are not accepted by the API.")
    tzone: str = Field(..., description="Timezone offset from UTC (e.g., '5.5')")
    lan: str = Field(default="en", description="Language code for response (default 'en')")

    @field_validator("sign")
    @classmethod
    def validate_sign(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_ZODIAC_SIGNS:
            raise ValueError(f"Invalid zodiac sign '{v}'. Must be one of: {', '.join(sorted(VALID_ZODIAC_SIGNS))}")
        return v

    @field_validator("year")
    @classmethod
    def validate_year(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_PERIOD_SELECTORS:
            raise ValueError(f"Invalid year '{v}'. Must be one of: {', '.join(sorted(VALID_PERIOD_SELECTORS))}")
        return v


class ChineseHoroscopeInput(BaseModel):
    """Input for Chinese horoscope API calls. Requires Chinese zodiac sign and day reference."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    sign: str = Field(..., description="Chinese zodiac sign (e.g., 'rat', 'ox', 'tiger', 'dragon')")
    h_day: str = Field(..., description="Day reference: 'today', 'tomorrow', or 'yesterday'")
    tzone: str = Field(..., description="Timezone offset from UTC (e.g., '5.5')")
    lan: str = Field(default="en", description="Language code for response (default 'en')")

    @field_validator("sign")
    @classmethod
    def validate_sign(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_CHINESE_SIGNS:
            raise ValueError(f"Invalid Chinese zodiac sign '{v}'. Must be one of: {', '.join(sorted(VALID_CHINESE_SIGNS))}")
        return v


class NumerologyHoroscopeInput(BaseModel):
    """Input for numerology horoscope API calls. Requires life path number, date, and timezone."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    number: str = Field(..., description="Life path number (e.g., '1' through '9', '11', '22')")
    day: str = Field(..., description="Day of the month (e.g., '21')")
    month: str = Field(..., description="Month number (e.g., '03')")
    year: str = Field(..., description="Year (e.g., '2026')")
    tzone: str = Field(..., description="Timezone offset from UTC (e.g., '5.5')")
    lan: str = Field(default="en", description="Language code for response (default 'en')")


class TarotInput(BaseModel):
    """Input for tarot and reading API calls. Minimal input, language only."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    lan: str = Field(default="en", description="Language code for response (default 'en')")


class LoveCompatibilityInput(BaseModel):
    """Input for the love compatibility reading. Requires two zodiac signs."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    sign_1: str = Field(..., description="First person's zodiac sign (e.g., 'aries')")
    sign_2: str = Field(..., description="Second person's zodiac sign (e.g., 'leo')")
    lan: str = Field(default="en", description="Language code for response (default 'en')")

    @field_validator("sign_1", "sign_2")
    @classmethod
    def validate_signs(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_ZODIAC_SIGNS:
            raise ValueError(f"Invalid zodiac sign '{v}'. Must be one of: {', '.join(sorted(VALID_ZODIAC_SIGNS))}")
        return v


class WhichAnimalInput(BaseModel):
    """Input for the spirit animal reading. Requires full name and birth date."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    full_name: str = Field(..., description="Full name of the person (e.g., 'Ram Kumar')", min_length=1, max_length=200)
    day: str = Field(..., description="Birth day (e.g., '15')", min_length=1, max_length=2)
    month: str = Field(..., description="Birth month (e.g., '08')", min_length=1, max_length=2)
    year: str = Field(..., description="Birth year, 1901 to 2100 (e.g., '1990')", min_length=4, max_length=4)
    lan: str = Field(default="en", description="Language code for response (default 'en')")


class NumerologyInput(BaseModel):
    """Input for Chaldean numerology API calls. Requires name and birth date."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    fname: str = Field(..., description="First name (e.g., 'John')", min_length=1, max_length=100)
    lname: str = Field(..., description="Last name (e.g., 'Doe')", min_length=1, max_length=100)
    day: str = Field(..., description="Birth day (e.g., '15')", min_length=1, max_length=2)
    month: str = Field(..., description="Birth month (e.g., '06')", min_length=1, max_length=2)
    year: str = Field(..., description="Birth year (e.g., '1990')", min_length=4, max_length=4)
    lan: str = Field(default="en", description="Language code for response (default 'en')")


class CoreNumbersInput(BaseModel):
    """Input for the core numbers API. Requires full name, birth date, and calculation method."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    full_name: str = Field(..., description="Full name of the person (e.g., 'Rahul Kumar')", min_length=1, max_length=200)
    day: str = Field(..., description="Birth day (e.g., '15')", min_length=1, max_length=2)
    month: str = Field(..., description="Birth month (e.g., '08')", min_length=1, max_length=2)
    year: str = Field(..., description="Birth year (e.g., '1990')", min_length=4, max_length=4)
    method: str = Field(..., description="Calculation method: 'general', 'chaldean', or 'pythagorean'")
    gender: str | None = Field(default=None, description="Optional gender: 'male' or 'female'. Accepted by the API but does not change the result.")
    fname: str | None = Field(default=None, description="Deprecated: this endpoint requires full_name instead. Accepted for backward compatibility, not sent to the API.")
    lname: str | None = Field(default=None, description="Deprecated: this endpoint requires full_name instead. Accepted for backward compatibility, not sent to the API.")
    lan: str | None = Field(default=None, description="Deprecated: not part of this endpoint's schema. Accepted for backward compatibility, not sent to the API.")

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_CORE_METHODS:
            raise ValueError(f"Invalid method '{v}'. Must be one of: {', '.join(sorted(VALID_CORE_METHODS))}")
        return v

    @field_validator("gender")
    @classmethod
    def validate_gender(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.lower().strip()
        if v not in VALID_GENDERS:
            raise ValueError(f"Invalid gender '{v}'. Must be one of: {', '.join(sorted(VALID_GENDERS))}")
        return v


class MobileNumerologyInput(BaseModel):
    """Input for mobile number numerology analysis. Requires name, birth date, and mobile number."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    fname: str = Field(..., description="First name", min_length=1, max_length=100)
    lname: str = Field(..., description="Last name", min_length=1, max_length=100)
    day: str = Field(..., description="Birth day (e.g., '15')")
    month: str = Field(..., description="Birth month (e.g., '06')")
    year: str = Field(..., description="Birth year (e.g., '1990')")
    mobile_number: str = Field(..., description="Mobile number to analyze (e.g., '9876543210')")


class NewMobileNumberInput(BaseModel):
    """Input for the new mobile number suggestion. Requires name and birth date only."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    fname: str = Field(..., description="First name", min_length=1, max_length=100)
    lname: str = Field(..., description="Last name", min_length=1, max_length=100)
    day: str = Field(..., description="Birth day (e.g., '15')")
    month: str = Field(..., description="Birth month (e.g., '06')")
    year: str = Field(..., description="Birth year (e.g., '1990')")
    mobile_number: str | None = Field(default=None, description="Deprecated: ignored by this endpoint, the suggestion is derived from name and birth date alone. Accepted for backward compatibility, not sent to the API.")


class CalculatorInput(BaseModel):
    """Input for love/compatibility calculators. Requires names and genders of both partners."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    your_name: str = Field(..., description="Your name", min_length=1, max_length=200)
    partner_name: str = Field(..., description="Partner's name", min_length=1, max_length=200)
    your_gender: str = Field(..., description="Your gender: 'male' or 'female'")
    partner_gender: str = Field(..., description="Partner's gender: 'male' or 'female'")


class PDFReportInput(BaseModel):
    """Input for PDF report generation. Requires birth data and company branding.

    The PDF backend REQUIRES the six branding fields (company_name, company_url,
    company_email, company_bio, logo_url, footer_text); it rejects requests
    without them (verified live 2026-07-08). Only company_mobile is optional.
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    full_name: str = Field(..., description="Full name of the person", min_length=1, max_length=200)
    day: str = Field(..., description="Birth day (e.g., '15')")
    month: str = Field(..., description="Birth month (e.g., '06')")
    year: str = Field(..., description="Birth year (e.g., '1990')")
    hour: str = Field(..., description="Birth hour in 24h format (e.g., '14')")
    min: str = Field(..., description="Birth minute (e.g., '30')")
    sec: str = Field(default="0", description="Birth second (e.g., '0')")
    gender: str = Field(..., description="Gender: 'male' or 'female'")
    place: str = Field(..., description="Birth place (e.g., 'New Delhi')")
    lat: str = Field(..., description="Latitude of birth place (e.g., '28.7041')")
    lon: str = Field(..., description="Longitude of birth place (e.g., '77.1025')")
    tzone: str = Field(..., description="Timezone offset from UTC (e.g., '5.5')")
    lan: str = Field(default="en", description="Language code for report (default 'en')")
    company_name: str = Field(..., description="Company name printed on the PDF (required by the API)", min_length=1)
    company_url: str = Field(..., description="Company URL printed on the PDF (required by the API)", min_length=1)
    company_email: str = Field(..., description="Company email printed on the PDF (required by the API)", min_length=1)
    company_bio: str = Field(..., description="Company bio/description printed on the PDF (required by the API)", min_length=1)
    logo_url: str = Field(..., description="Logo image URL printed on the PDF (required by the API)", min_length=1)
    footer_text: str = Field(..., description="Footer text printed on the PDF (required by the API)", min_length=1)
    company_mobile: str = Field(default="", description="Optional company phone for branding on PDF")


class PDFMatchmakingInput(BaseModel):
    """Input for PDF matchmaking report. Requires birth data for two persons and optional company branding."""

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    # Person 1
    p1_full_name: str = Field(..., description="Full name of person 1", min_length=1)
    p1_day: str = Field(..., description="Birth day of person 1")
    p1_month: str = Field(..., description="Birth month of person 1")
    p1_year: str = Field(..., description="Birth year of person 1")
    p1_hour: str = Field(..., description="Birth hour of person 1 in 24h format")
    p1_min: str = Field(..., description="Birth minute of person 1")
    p1_sec: str = Field(default="0", description="Birth second of person 1")
    p1_gender: str = Field(..., description="Gender of person 1: 'male' or 'female'")
    p1_place: str = Field(..., description="Birth place of person 1")
    p1_lat: str = Field(..., description="Latitude of person 1's birth place")
    p1_lon: str = Field(..., description="Longitude of person 1's birth place")
    p1_tzone: str = Field(..., description="Timezone of person 1")

    # Person 2
    p2_full_name: str = Field(..., description="Full name of person 2", min_length=1)
    p2_day: str = Field(..., description="Birth day of person 2")
    p2_month: str = Field(..., description="Birth month of person 2")
    p2_year: str = Field(..., description="Birth year of person 2")
    p2_hour: str = Field(..., description="Birth hour of person 2 in 24h format")
    p2_min: str = Field(..., description="Birth minute of person 2")
    p2_sec: str = Field(default="0", description="Birth second of person 2")
    p2_gender: str = Field(..., description="Gender of person 2: 'male' or 'female'")
    p2_place: str = Field(..., description="Birth place of person 2")
    p2_lat: str = Field(..., description="Latitude of person 2's birth place")
    p2_lon: str = Field(..., description="Longitude of person 2's birth place")
    p2_tzone: str = Field(..., description="Timezone of person 2")

    lan: str = Field(default="en", description="Language code for report (default 'en')")
    company_name: str = Field(..., description="Company name printed on the PDF (required by the API)", min_length=1)
    company_url: str = Field(..., description="Company URL printed on the PDF (required by the API)", min_length=1)
    company_email: str = Field(..., description="Company email printed on the PDF (required by the API)", min_length=1)
    company_bio: str = Field(..., description="Company bio/description printed on the PDF (required by the API)", min_length=1)
    logo_url: str = Field(..., description="Logo image URL printed on the PDF (required by the API)", min_length=1)
    footer_text: str = Field(..., description="Footer text printed on the PDF (required by the API)", min_length=1)
    company_mobile: str = Field(default="", description="Optional company phone for branding on PDF")


class NatalReportInput(PDFReportInput):
    """Input for the Western natal PDF report. Adds the report_code and theme selectors the API requires."""

    report_code: str = Field(..., description="Report code selecting which natal report to generate (e.g., 'CAREER-REPORT'). Required by the API; see the Divine API docs for the full list of codes.")
    theme: str = Field(..., description="Visual theme code for the PDF (e.g., '001'). Required by the API.")


class CoupleReportInput(PDFMatchmakingInput):
    """Input for the Western couple PDF report. Adds the report_code selector the API requires."""

    report_code: str = Field(..., description="Report code selecting which couple report to generate (e.g., 'ALIGNED-ENERGIES-REPORT'). Required by the API; see the Divine API docs for the full list of codes.")


class NumerologyPDFInput(BaseModel):
    """Input for numerology PDF reports. Requires full name, birth date, gender, report code, and branding.

    The backend requires full_name (not fname/lname), gender, report_code, and
    the six branding fields (verified live 2026-07-08). Birth time and place are
    optional and only sent when provided; the reports generate without them.
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    full_name: str = Field(..., description="Full name of the person (e.g., 'Rahul Kumar')", min_length=1, max_length=200)
    day: str = Field(..., description="Birth day (e.g., '15')")
    month: str = Field(..., description="Birth month (e.g., '08')")
    year: str = Field(..., description="Birth year (e.g., '1990')")
    gender: str = Field(..., description="Gender: 'male' or 'female'")
    report_code: str = Field(..., description="Report code selecting the report to generate. Required by the API. Example: 'YEARLY-PREDICTION-3-YEAR' for the prediction report, 'SCHOLARLY-SPIRITS' for the numerology report; see the Divine API docs for the full list of codes.")
    lan: str = Field(default="en", description="Language code for report (default 'en')")
    company_name: str = Field(..., description="Company name printed on the PDF (required by the API)", min_length=1)
    company_url: str = Field(..., description="Company URL printed on the PDF (required by the API)", min_length=1)
    company_email: str = Field(..., description="Company email printed on the PDF (required by the API)", min_length=1)
    company_bio: str = Field(..., description="Company bio/description printed on the PDF (required by the API)", min_length=1)
    logo_url: str = Field(..., description="Logo image URL printed on the PDF (required by the API)", min_length=1)
    footer_text: str = Field(..., description="Footer text printed on the PDF (required by the API)", min_length=1)
    company_mobile: str = Field(default="", description="Optional company phone for branding on PDF")
    hour: str | None = Field(default=None, description="Optional birth hour in 24h format; not required for these reports, sent only if provided")
    min: str | None = Field(default=None, description="Optional birth minute; sent only if provided")
    sec: str | None = Field(default=None, description="Optional birth second; sent only if provided")
    place: str | None = Field(default=None, description="Optional birth place; sent only if provided")
    lat: str | None = Field(default=None, description="Optional latitude; sent only if provided")
    lon: str | None = Field(default=None, description="Optional longitude; sent only if provided")
    tzone: str | None = Field(default=None, description="Optional timezone offset; sent only if provided")
    fname: str | None = Field(default=None, description="Deprecated: this endpoint requires full_name instead. Accepted for backward compatibility, not sent to the API.")
    lname: str | None = Field(default=None, description="Deprecated: this endpoint requires full_name instead. Accepted for backward compatibility, not sent to the API.")

    @field_validator("gender")
    @classmethod
    def validate_gender(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in VALID_GENDERS:
            raise ValueError(f"Invalid gender '{v}'. Must be one of: {', '.join(sorted(VALID_GENDERS))}")
        return v


# ──────────────────────────────────────────────
# Shared API Client
# ──────────────────────────────────────────────


async def _call_divine_api(
    endpoint: str,
    payload: dict,
    base_url: str = API_HOST_5,
    api_key: str | None = None,
    auth_token: str | None = None,
) -> str:
    """Make a POST request to Divine API and return formatted JSON response.

    Raises ToolError on any failure (non-2xx, network error, or an upstream
    error envelope returned with HTTP 200) so MCP clients see isError: true
    instead of a success result whose text merely contains 'Error: ...'.
    """
    payload["api_key"] = api_key or DIVINE_API_KEY
    clean_payload = {k: v for k, v in payload.items() if v is not None}
    url = f"{base_url}{endpoint}"
    bearer = auth_token or DIVINE_AUTH_TOKEN

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                headers={"Authorization": f"Bearer {bearer}"},
                data=clean_payload,
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as e:
        raise ToolError(_handle_http_error(e)) from e
    except httpx.TimeoutException as e:
        raise ToolError("Request timed out. The Divine API server may be slow. Please try again.") from e
    except httpx.ConnectError as e:
        raise ToolError("Could not connect to Divine API. Please check your internet connection.") from e
    except Exception as e:
        raise ToolError(f"Unexpected error - {type(e).__name__}: {str(e)}") from e

    # Some endpoints return HTTP 200 with an error envelope in the body.
    # Two shapes are used across the Divine API hosts:
    #   legacy (astroapi-4/5, pdf):  {"success": 2 or 3, "msg": "..."}
    #   newer (astroapi-7):          {"status": "error", "message": "...", ...}
    # A successful legacy response is success==1; newer success omits "success".
    if isinstance(data, dict):
        if data.get("status") == "error" or ("success" in data and str(data.get("success")) != "1"):
            msg = data.get("message") or data.get("msg") or "Divine API returned an error."
            raise ToolError(f"Divine API error: {msg}")

    return json.dumps(data, indent=2, ensure_ascii=False)


def _handle_http_error(e: httpx.HTTPStatusError) -> str:
    """Return actionable error messages for HTTP errors."""
    status = e.response.status_code
    if status == 401:
        return (
            "Error: Authentication failed (401). "
            "Please check your DIVINE_API_KEY and DIVINE_AUTH_TOKEN environment variables. "
            "Get your credentials at https://divineapi.com/api-keys"
        )
    elif status == 403:
        return (
            "Error: Access forbidden (403). "
            "Your API plan may not include Horoscope & Numerology APIs. "
            "Check your subscription at https://divineapi.com/pricing"
        )
    elif status == 429:
        return (
            "Error: Rate limit exceeded (429). "
            "You've exceeded your request limit or are sending too many concurrent requests. "
            "Please wait and try again."
        )
    elif status == 404:
        return "Error: Endpoint not found (404). This API endpoint may not be available on your plan."
    else:
        body = ""
        try:
            body = e.response.text[:500]
        except Exception:
            pass
        return f"Error: API returned status {status}. Response: {body}"


# ──────────────────────────────────────────────
# Payload Helpers
# ──────────────────────────────────────────────


def _horoscope_payload(params: HoroscopeInput) -> dict:
    """Build the daily horoscope payload. Deprecated day/month/year inputs are NOT forwarded."""
    return {
        "sign": params.sign,
        "h_day": params.h_day,
        "tzone": params.tzone,
        "lan": params.lan,
    }


def _weekly_horoscope_payload(params: WeeklyHoroscopeInput) -> dict:
    return {
        "sign": params.sign,
        "week": params.week,
        "tzone": params.tzone,
        "lan": params.lan,
    }


def _monthly_horoscope_payload(params: MonthlyHoroscopeInput) -> dict:
    return {
        "sign": params.sign,
        "month": params.month,
        "tzone": params.tzone,
        "lan": params.lan,
    }


def _yearly_horoscope_payload(params: YearlyHoroscopeInput) -> dict:
    return {
        "sign": params.sign,
        "year": params.year,
        "tzone": params.tzone,
        "lan": params.lan,
    }


def _chinese_payload(params: ChineseHoroscopeInput) -> dict:
    return {
        "sign": params.sign,
        "h_day": params.h_day,
        "tzone": params.tzone,
        "lan": params.lan,
    }


def _numerology_horoscope_payload(params: NumerologyHoroscopeInput) -> dict:
    return {
        "number": params.number,
        "day": params.day,
        "month": params.month,
        "year": params.year,
        "tzone": params.tzone,
        "lan": params.lan,
    }


def _tarot_payload(params: TarotInput) -> dict:
    return {
        "lan": params.lan,
    }


def _numerology_payload(params: NumerologyInput) -> dict:
    return {
        "fname": params.fname,
        "lname": params.lname,
        "day": params.day,
        "month": params.month,
        "year": params.year,
        "lan": params.lan,
    }


def _mobile_numerology_payload(params: MobileNumerologyInput) -> dict:
    return {
        "fname": params.fname,
        "lname": params.lname,
        "day": params.day,
        "month": params.month,
        "year": params.year,
        "mobile_number": params.mobile_number,
    }


def _new_mobile_number_payload(params: NewMobileNumberInput) -> dict:
    """Build the new-mobile-number payload. The deprecated mobile_number input is NOT forwarded."""
    return {
        "fname": params.fname,
        "lname": params.lname,
        "day": params.day,
        "month": params.month,
        "year": params.year,
    }


def _love_compatibility_payload(params: LoveCompatibilityInput) -> dict:
    return {
        "sign_1": params.sign_1,
        "sign_2": params.sign_2,
        "lan": params.lan,
    }


def _which_animal_payload(params: WhichAnimalInput) -> dict:
    return {
        "full_name": params.full_name,
        "day": params.day,
        "month": params.month,
        "year": params.year,
        "lan": params.lan,
    }


def _core_numbers_payload(params: CoreNumbersInput) -> dict:
    """Build the core-numbers payload. Deprecated fname/lname/lan inputs are NOT forwarded."""
    payload = {
        "full_name": params.full_name,
        "day": params.day,
        "month": params.month,
        "year": params.year,
        "method": params.method,
    }
    if params.gender:
        payload["gender"] = params.gender
    return payload


def _calculator_payload(params: CalculatorInput) -> dict:
    return {
        "your_name": params.your_name,
        "partner_name": params.partner_name,
        "your_gender": params.your_gender,
        "partner_gender": params.partner_gender,
    }


def _pdf_report_payload(params: PDFReportInput) -> dict:
    payload = {
        "full_name": params.full_name,
        "day": params.day,
        "month": params.month,
        "year": params.year,
        "hour": params.hour,
        "min": params.min,
        "sec": params.sec,
        "gender": params.gender,
        "place": params.place,
        "lat": params.lat,
        "lon": params.lon,
        "tzone": params.tzone,
        "lan": params.lan,
        "company_name": params.company_name,
        "company_url": params.company_url,
        "company_email": params.company_email,
        "company_bio": params.company_bio,
        "logo_url": params.logo_url,
        "footer_text": params.footer_text,
    }
    if params.company_mobile:
        payload["company_mobile"] = params.company_mobile
    return payload


def _natal_report_payload(params: NatalReportInput) -> dict:
    payload = _pdf_report_payload(params)
    payload["report_code"] = params.report_code
    payload["theme"] = params.theme
    return payload


def _pdf_matchmaking_payload(params: PDFMatchmakingInput) -> dict:
    payload = {
        "p1_full_name": params.p1_full_name,
        "p1_day": params.p1_day,
        "p1_month": params.p1_month,
        "p1_year": params.p1_year,
        "p1_hour": params.p1_hour,
        "p1_min": params.p1_min,
        "p1_sec": params.p1_sec,
        "p1_gender": params.p1_gender,
        "p1_place": params.p1_place,
        "p1_lat": params.p1_lat,
        "p1_lon": params.p1_lon,
        "p1_tzone": params.p1_tzone,
        "p2_full_name": params.p2_full_name,
        "p2_day": params.p2_day,
        "p2_month": params.p2_month,
        "p2_year": params.p2_year,
        "p2_hour": params.p2_hour,
        "p2_min": params.p2_min,
        "p2_sec": params.p2_sec,
        "p2_gender": params.p2_gender,
        "p2_place": params.p2_place,
        "p2_lat": params.p2_lat,
        "p2_lon": params.p2_lon,
        "p2_tzone": params.p2_tzone,
        "lan": params.lan,
        "company_name": params.company_name,
        "company_url": params.company_url,
        "company_email": params.company_email,
        "company_bio": params.company_bio,
        "logo_url": params.logo_url,
        "footer_text": params.footer_text,
    }
    if params.company_mobile:
        payload["company_mobile"] = params.company_mobile
    return payload


def _couple_report_payload(params: CoupleReportInput) -> dict:
    payload = _pdf_matchmaking_payload(params)
    payload["report_code"] = params.report_code
    return payload


def _numerology_pdf_payload(params: NumerologyPDFInput) -> dict:
    """Build a numerology PDF payload. Deprecated fname/lname inputs are NOT forwarded.

    Optional birth time/place fields are sent only when provided.
    """
    payload = {
        "full_name": params.full_name,
        "day": params.day,
        "month": params.month,
        "year": params.year,
        "gender": params.gender,
        "report_code": params.report_code,
        "lan": params.lan,
        "company_name": params.company_name,
        "company_url": params.company_url,
        "company_email": params.company_email,
        "company_bio": params.company_bio,
        "logo_url": params.logo_url,
        "footer_text": params.footer_text,
    }
    if params.company_mobile:
        payload["company_mobile"] = params.company_mobile
    for key in ("hour", "min", "sec", "place", "lat", "lon", "tzone"):
        val = getattr(params, key)
        if val is not None:
            payload[key] = val
    return payload


# ══════════════════════════════════════════════
# HOROSCOPE TOOLS (6) — astroapi-5.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_daily_horoscope", annotations=TOOL_ANNOTATIONS)
async def divine_daily_horoscope(params: HoroscopeInput, ctx: Context) -> str:
    """Get daily horoscope for a zodiac sign. Returns love, career, health, and overall predictions.

    The reading is selected with h_day ('today', 'tomorrow', or 'yesterday').
    For a broader outlook, also call divine_weekly_horoscope and divine_monthly_horoscope in parallel.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v5/daily-horoscope", _horoscope_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_weekly_horoscope", annotations=TOOL_ANNOTATIONS)
async def divine_weekly_horoscope(params: WeeklyHoroscopeInput, ctx: Context) -> str:
    """Get weekly horoscope for a zodiac sign. Returns predictions covering love, career,
    health, and finances for the entire week.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v5/weekly-horoscope", _weekly_horoscope_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_monthly_horoscope", annotations=TOOL_ANNOTATIONS)
async def divine_monthly_horoscope(params: MonthlyHoroscopeInput, ctx: Context) -> str:
    """Get monthly horoscope for a zodiac sign. Returns detailed predictions for the month
    covering love, career, health, and financial outlook.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v5/monthly-horoscope", _monthly_horoscope_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_yearly_horoscope", annotations=TOOL_ANNOTATIONS)
async def divine_yearly_horoscope(params: YearlyHoroscopeInput, ctx: Context) -> str:
    """Get yearly horoscope for a zodiac sign. Returns comprehensive annual predictions
    covering major life themes, career, relationships, and personal growth.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v5/yearly-horoscope", _yearly_horoscope_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_chinese_horoscope", annotations=TOOL_ANNOTATIONS)
async def divine_chinese_horoscope(params: ChineseHoroscopeInput, ctx: Context) -> str:
    """Get Chinese zodiac horoscope for today, tomorrow, or yesterday.

    Returns predictions based on the Chinese zodiac animal sign including
    luck, love, career, and health insights.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/chinese-horoscope", _chinese_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_numerology_horoscope", annotations=TOOL_ANNOTATIONS)
async def divine_numerology_horoscope(params: NumerologyHoroscopeInput, ctx: Context) -> str:
    """Get numerology-based horoscope for a life path number and date.

    Returns daily numerological predictions based on the given number,
    including lucky colors, compatibility, and guidance.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v2/numerology-horoscope", _numerology_horoscope_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# TAROT & READINGS TOOLS (23) — astroapi-5.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_yes_or_no_tarot", annotations=TOOL_ANNOTATIONS)
async def divine_yes_or_no_tarot(params: TarotInput, ctx: Context) -> str:
    """Draw a tarot card for a yes/no question. Returns card name, image, and interpretation.

    Perfect for quick decision-making questions with a clear yes or no answer.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v2/yes-or-no-tarot", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_daily_tarot", annotations=TOOL_ANNOTATIONS)
async def divine_daily_tarot(params: TarotInput, ctx: Context) -> str:
    """Draw a daily tarot card with interpretation and guidance.

    Returns a tarot card for the day with its meaning, advice, and symbolism
    to guide your daily decisions and awareness.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v2/daily-tarot", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_fortune_cookie", annotations=TOOL_ANNOTATIONS)
async def divine_fortune_cookie(params: TarotInput, ctx: Context) -> str:
    """Get a fortune cookie message with wisdom and lucky numbers.

    Returns a randomized fortune cookie with a wisdom message,
    lucky numbers, and a lesson for the day.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v2/fortune-cookie", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_coffee_cup_reading", annotations=TOOL_ANNOTATIONS)
async def divine_coffee_cup_reading(params: TarotInput, ctx: Context) -> str:
    """Get a Turkish coffee cup reading with symbols and meanings.

    Returns an interpretation of coffee cup symbols covering past,
    present, and future insights in the tradition of tasseography.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v2/coffee-cup-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_career_daily_reading", annotations=TOOL_ANNOTATIONS)
async def divine_career_daily_reading(params: TarotInput, ctx: Context) -> str:
    """Get daily career guidance and professional insights.

    Returns a card-based reading focused on career, workplace dynamics,
    professional growth, and financial opportunities.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/career-daily-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_angel_reading", annotations=TOOL_ANNOTATIONS)
async def divine_angel_reading(params: TarotInput, ctx: Context) -> str:
    """Receive an angel card reading with divine guidance.

    Returns an angel card message with spiritual guidance, affirmations,
    and divine insights for your current life situation.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/divine-angel-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_magic_reading", annotations=TOOL_ANNOTATIONS)
async def divine_magic_reading(params: TarotInput, ctx: Context) -> str:
    """Get a magical reading with mystical insights.

    Returns a mystical card reading with magical symbolism, enchanted
    guidance, and cosmic wisdom for your journey.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v2/divine-magic-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_dream_come_true_reading", annotations=TOOL_ANNOTATIONS)
async def divine_dream_come_true_reading(params: TarotInput, ctx: Context) -> str:
    """Discover insights about manifesting your dreams.

    Returns a reading focused on goal achievement, dream manifestation,
    and the energetic alignment needed to realize your aspirations.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/dream-come-true-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_egyptian_prediction", annotations=TOOL_ANNOTATIONS)
async def divine_egyptian_prediction(params: TarotInput, ctx: Context) -> str:
    """Get predictions based on ancient Egyptian divination.

    Returns mystical predictions drawn from ancient Egyptian wisdom,
    including symbolic imagery and esoteric guidance.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/egyptian-prediction", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_erotic_love_reading", annotations=TOOL_ANNOTATIONS)
async def divine_erotic_love_reading(params: TarotInput, ctx: Context) -> str:
    """Get an intimate love and passion reading.

    Returns insights about romantic passion, physical attraction,
    and intimate connections in your love life.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/erotic-love-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_ex_flame_reading", annotations=TOOL_ANNOTATIONS)
async def divine_ex_flame_reading(params: TarotInput, ctx: Context) -> str:
    """Get insights about a past relationship.

    Returns a reading about an ex-partner or past flame, including
    lessons learned, closure guidance, and whether reconnection is advised.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/ex-flame-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_flirt_love_reading", annotations=TOOL_ANNOTATIONS)
async def divine_flirt_love_reading(params: TarotInput, ctx: Context) -> str:
    """Get playful love and flirtation insights.

    Returns a lighthearted reading about romantic attraction, flirtation
    energy, and how to navigate new romantic interests.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/flirt-love-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_heartbreak_reading", annotations=TOOL_ANNOTATIONS)
async def divine_heartbreak_reading(params: TarotInput, ctx: Context) -> str:
    """Get guidance for healing from heartbreak.

    Returns a compassionate reading with insights on emotional healing,
    self-recovery, and moving forward after a breakup or loss.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v2/heartbreak-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_in_depth_love_reading", annotations=TOOL_ANNOTATIONS)
async def divine_in_depth_love_reading(params: TarotInput, ctx: Context) -> str:
    """Get a comprehensive love and relationship reading.

    Returns a detailed multi-card spread covering your love life,
    relationship dynamics, emotional needs, and romantic future.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/in-depth-love-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_know_your_friend_reading", annotations=TOOL_ANNOTATIONS)
async def divine_know_your_friend_reading(params: TarotInput, ctx: Context) -> str:
    """Get insights about a friendship.

    Returns a reading about friendship dynamics, trust, loyalty,
    and the deeper nature of a platonic relationship.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/know-your-friend-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_love_compatibility", annotations=TOOL_ANNOTATIONS)
async def divine_love_compatibility(params: LoveCompatibilityInput, ctx: Context) -> str:
    """Check love compatibility between two zodiac signs.

    Requires the two signs (sign_1 and sign_2). Returns a compatibility reading
    with insights on emotional harmony, challenges, and the overall potential
    of the romantic pairing.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v2/love-compatibility", _love_compatibility_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_love_triangle_reading", annotations=TOOL_ANNOTATIONS)
async def divine_love_triangle_reading(params: TarotInput, ctx: Context) -> str:
    """Get insights on a love triangle situation using tarot.

    Returns a reading about complicated romantic dynamics involving
    multiple people, with guidance on navigating the situation.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v2/love-triangle-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_made_for_each_other", annotations=TOOL_ANNOTATIONS)
async def divine_made_for_each_other(params: TarotInput, ctx: Context) -> str:
    """Discover if you and your partner are made for each other.

    Returns a reading that evaluates soul-level compatibility,
    karmic connections, and whether the relationship is destined.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/made-for-each-other-or-not-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_power_life_reading", annotations=TOOL_ANNOTATIONS)
async def divine_power_life_reading(params: TarotInput, ctx: Context) -> str:
    """Get a power life reading for strength and empowerment.

    Returns insights about your personal power, life force energy,
    inner strengths, and how to harness them for success.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/power-life-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_past_lives_connection", annotations=TOOL_ANNOTATIONS)
async def divine_past_lives_connection(params: TarotInput, ctx: Context) -> str:
    """Explore past life connections and karmic ties.

    Returns a reading about past life relationships, karmic lessons
    carried forward, and soul connections from previous incarnations.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/past-lives-connection-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_past_present_future", annotations=TOOL_ANNOTATIONS)
async def divine_past_present_future(params: TarotInput, ctx: Context) -> str:
    """Get a past, present, and future three-card tarot spread.

    Returns a classic three-card reading with insights into what
    has passed, the current situation, and what lies ahead.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v3/past-present-future-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_which_animal_are_you", annotations=TOOL_ANNOTATIONS)
async def divine_which_animal_are_you(params: WhichAnimalInput, ctx: Context) -> str:
    """Discover your spirit animal through a divination reading.

    Requires full name and birth date (year 1901 to 2100). Returns your spirit
    animal match along with its symbolic meaning, personality traits, and
    spiritual guidance it offers.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v2/which-animal-are-you-reading", _which_animal_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_wisdom_reading", annotations=TOOL_ANNOTATIONS)
async def divine_wisdom_reading(params: TarotInput, ctx: Context) -> str:
    """Get a wisdom reading with timeless insights and guidance.

    Returns a card reading focused on wisdom, life lessons, philosophical
    insights, and spiritual growth for your current journey.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/api/v2/wisdom-reading", _tarot_payload(params), API_HOST_5, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# NUMEROLOGY — CHALDEAN (12) — astroapi-7.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_loshu_grid", annotations=TOOL_ANNOTATIONS)
async def divine_loshu_grid(params: NumerologyInput, ctx: Context) -> str:
    """Generate Lo Shu Grid for numerological analysis.

    Returns the Lo Shu magic square grid based on name and birth date,
    revealing personality patterns, strengths, and weaknesses through
    number placement in the 3x3 grid.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/loshu-grid", _numerology_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_zodiac_planet_number", annotations=TOOL_ANNOTATIONS)
async def divine_zodiac_planet_number(params: NumerologyInput, ctx: Context) -> str:
    """Get zodiac sign, ruling planet, and numerological number associations.

    Returns the connection between your zodiac sign, its ruling planet,
    and the numerological numbers that influence your personality and destiny.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/zodiac-planet-number", _numerology_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_luck_numerology", annotations=TOOL_ANNOTATIONS)
async def divine_luck_numerology(params: NumerologyInput, ctx: Context) -> str:
    """Get lucky numbers, colors, and days based on numerology.

    Returns your personal lucky numbers, favorable colors, auspicious days,
    and other fortune-enhancing insights derived from your name and birth date.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/luck-numerology", _numerology_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_name_number", annotations=TOOL_ANNOTATIONS)
async def divine_name_number(params: NumerologyInput, ctx: Context) -> str:
    """Calculate your name number using Chaldean numerology.

    Returns the numerological value of your name, its meaning, personality
    traits associated with the number, and its influence on your life path.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/name-number", _numerology_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_birthday_number", annotations=TOOL_ANNOTATIONS)
async def divine_birthday_number(params: NumerologyInput, ctx: Context) -> str:
    """Calculate your birthday number and its significance.

    Returns the numerological birthday number derived from your date of birth,
    along with its meaning, talents, and gifts it bestows.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/birthday-number", _numerology_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_missing_numbers", annotations=TOOL_ANNOTATIONS)
async def divine_missing_numbers(params: NumerologyInput, ctx: Context) -> str:
    """Find missing numbers in your numerological chart.

    Returns the numbers absent from your name and birth date analysis,
    revealing areas of challenge, karmic lessons, and qualities to develop.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/missing-numbers", _numerology_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_driver_conductor_numbers", annotations=TOOL_ANNOTATIONS)
async def divine_driver_conductor_numbers(params: NumerologyInput, ctx: Context) -> str:
    """Calculate driver and conductor numbers from your birth date.

    Returns the driver (birth day) and conductor (full birth date) numbers,
    explaining how they influence your personality, behavior, and destiny.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/driver-and-conductor-numbers", _numerology_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_two_numbers_arrows", annotations=TOOL_ANNOTATIONS)
async def divine_two_numbers_arrows(params: NumerologyInput, ctx: Context) -> str:
    """Analyze two-number arrow patterns in your Lo Shu Grid.

    Returns the directional arrows formed by pairs of numbers in the grid,
    indicating specific personality traits and life tendencies.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/two-numbers-arrows", _numerology_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_three_numbers_arrows", annotations=TOOL_ANNOTATIONS)
async def divine_three_numbers_arrows(params: NumerologyInput, ctx: Context) -> str:
    """Analyze three-number arrow patterns in your Lo Shu Grid.

    Returns the directional arrows formed by triplets of numbers in the grid,
    revealing dominant personality patterns and life path indicators.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/three-numbers-arrows", _numerology_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_repeating_numbers", annotations=TOOL_ANNOTATIONS)
async def divine_repeating_numbers(params: NumerologyInput, ctx: Context) -> str:
    """Find repeating numbers in your numerological profile.

    Returns numbers that appear multiple times in your chart,
    indicating amplified energies, strengths, or challenges in your life.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/repeating-numbers", _numerology_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_yearly_prediction", annotations=TOOL_ANNOTATIONS)
async def divine_yearly_prediction(params: NumerologyInput, ctx: Context) -> str:
    """Get yearly numerological predictions based on your personal year number.

    Returns detailed predictions for the year covering career, relationships,
    health, and personal growth based on your numerological cycle.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/yearly-prediction", _numerology_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_numerology_gemstones", annotations=TOOL_ANNOTATIONS)
async def divine_numerology_gemstones(params: NumerologyInput, ctx: Context) -> str:
    """Get recommended gemstones based on your numerological profile.

    Returns gemstone recommendations aligned with your numerological numbers,
    including their healing properties, wearing instructions, and benefits.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/gemstones", _numerology_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# CORE NUMBERS (1) — astroapi-4.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_core_numbers", annotations=TOOL_ANNOTATIONS)
async def divine_core_numbers(params: CoreNumbersInput, ctx: Context) -> str:
    """Calculate all core numerology numbers from full name and birth date.

    Requires full_name and a calculation method ('general', 'chaldean', or
    'pythagorean'). Returns the core numbers: Life Path, Destiny Path,
    Birth Day, Attitude, Pinnacles, Challenges, and more, with interpretations.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/core-numbers", _core_numbers_payload(params), API_HOST_4, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# MOBILE NUMEROLOGY (2) — astroapi-7.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_new_mobile_number", annotations=TOOL_ANNOTATIONS)
async def divine_new_mobile_number(params: NewMobileNumberInput, ctx: Context) -> str:
    """Get a numerologically favorable new mobile number suggestion.

    Analyzes your name and birth date to suggest mobile numbers
    that are numerologically aligned with your personal vibrations.
    No existing mobile number is needed.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/new-mobile-number", _new_mobile_number_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_analyze_mobile_number", annotations=TOOL_ANNOTATIONS)
async def divine_analyze_mobile_number(params: MobileNumerologyInput, ctx: Context) -> str:
    """Analyze the numerological significance of a mobile number.

    Returns a detailed analysis of how your current mobile number
    aligns with your personal numerology, and its impact on your life.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/analyze-mobile-number", _mobile_numerology_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# CALCULATORS (2) — astroapi-7.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_flames_calculator", annotations=TOOL_ANNOTATIONS)
async def divine_flames_calculator(
    your_name: str,
    partner_name: str,
    ctx: Context,
) -> str:
    """Calculate FLAMES compatibility between two people.

    FLAMES stands for Friends, Lovers, Affectionate, Marriage, Enemies, Siblings.
    Returns the relationship type based on name analysis.
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = {"your_name": your_name, "partner_name": partner_name}
    return await _call_divine_api("/calculator/v1/flames-calculator", payload, API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_love_calculator", annotations=TOOL_ANNOTATIONS)
async def divine_love_calculator(params: CalculatorInput, ctx: Context) -> str:
    """Calculate love compatibility percentage between two people.

    Returns a love compatibility score with analysis based on names
    and genders, including relationship strengths and advice.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/calculator/v1/love-calculator", _calculator_payload(params), API_HOST_7, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# LIFESTYLE (3) — astroapi-7.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_zodiac_gift_guru", annotations=TOOL_ANNOTATIONS)
async def divine_zodiac_gift_guru(
    sign: str,
    h_day: str,
    tzone: str,
    ctx: Context,
    lan: str = "en",
) -> str:
    """Get personalized gift suggestions based on zodiac sign.

    Requires h_day ('today', 'tomorrow', or 'yesterday') and a timezone offset
    (e.g., '5.5'). Returns curated gift ideas tailored to the personality traits
    and preferences associated with the given zodiac sign.
    """
    h_day = h_day.lower().strip()
    if h_day not in VALID_H_DAYS:
        return f"Error: Invalid h_day '{h_day}'. Must be one of: {', '.join(sorted(VALID_H_DAYS))}"
    api_key, auth_token = _get_credentials(ctx)
    payload = {"sign": sign, "h_day": h_day, "tzone": tzone, "lan": lan}
    return await _call_divine_api("/api/v1/zodiac-gift-guru", payload, API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_beauty_by_stars", annotations=TOOL_ANNOTATIONS)
async def divine_beauty_by_stars(
    sign: str,
    h_day: str,
    tzone: str,
    ctx: Context,
    lan: str = "en",
) -> str:
    """Get beauty and skincare tips based on zodiac sign.

    Requires h_day ('today', 'tomorrow', or 'yesterday') and a timezone offset
    (e.g., '5.5'). Returns personalized beauty recommendations, skincare
    routines, and wellness advice aligned with your zodiac sign traits.
    """
    h_day = h_day.lower().strip()
    if h_day not in VALID_H_DAYS:
        return f"Error: Invalid h_day '{h_day}'. Must be one of: {', '.join(sorted(VALID_H_DAYS))}"
    api_key, auth_token = _get_credentials(ctx)
    payload = {"sign": sign, "h_day": h_day, "tzone": tzone, "lan": lan}
    return await _call_divine_api("/api/v1/beauty-by-the-stars", payload, API_HOST_7, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_astro_chic_picks", annotations=TOOL_ANNOTATIONS)
async def divine_astro_chic_picks(
    sign: str,
    h_day: str,
    tzone: str,
    ctx: Context,
    lan: str = "en",
) -> str:
    """Get fashion and style recommendations based on zodiac sign.

    Requires h_day ('today', 'tomorrow', or 'yesterday') and a timezone offset
    (e.g., '5.5'). Returns trendy fashion picks, style advice, and wardrobe
    suggestions personalized to the aesthetic preferences of your zodiac sign.
    """
    h_day = h_day.lower().strip()
    if h_day not in VALID_H_DAYS:
        return f"Error: Invalid h_day '{h_day}'. Must be one of: {', '.join(sorted(VALID_H_DAYS))}"
    api_key, auth_token = _get_credentials(ctx)
    payload = {"sign": sign, "h_day": h_day, "tzone": tzone, "lan": lan}
    return await _call_divine_api("/api/v1/astro-chic-picks", payload, API_HOST_7, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# PDF REPORTS — VEDIC (9) — pdf.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_pdf_kundali_sampoorna", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_kundali_sampoorna(params: PDFReportInput, ctx: Context) -> str:
    """Generate a comprehensive Sampoorna Kundali PDF report.

    Returns a complete Vedic birth chart report including planetary positions,
    dasha periods, yogas, doshas, and detailed life predictions.
    Supports optional company branding on the PDF.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/indian-api/v2/kundali-sampoorna", _pdf_report_payload(params), API_HOST_PDF, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_pdf_kundali_ananta", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_kundali_ananta(params: PDFReportInput, ctx: Context) -> str:
    """Generate an Ananta Kundali PDF report with extended analysis.

    Returns a detailed Vedic astrology report with extended planetary analysis,
    divisional charts, and in-depth dasha predictions in PDF format.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/indian-api/v2/kundali-ananta", _pdf_report_payload(params), API_HOST_PDF, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_pdf_kundali_prakash", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_kundali_prakash(params: PDFReportInput, ctx: Context) -> str:
    """Generate a Prakash Kundali PDF report with essential analysis.

    Returns a concise Vedic astrology report with key planetary positions,
    basic dasha analysis, and essential life predictions in PDF format.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/indian-api/v2/kundali-prakash", _pdf_report_payload(params), API_HOST_PDF, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_pdf_match_making", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_match_making(params: PDFMatchmakingInput, ctx: Context) -> str:
    """Generate a Vedic matchmaking (Kundali Milan) PDF report.

    Returns a comprehensive compatibility report for two individuals including
    Ashtakoota matching, Mangal Dosha analysis, and marriage compatibility score.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/indian-api/v2/match-making", _pdf_matchmaking_payload(params), API_HOST_PDF, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_pdf_government_job", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_government_job(params: PDFReportInput, ctx: Context) -> str:
    """Generate a government job prospects PDF report based on Vedic astrology.

    Returns an astrological analysis of government job potential, competitive exam
    success probability, and favorable periods for public sector employment.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/indian-api/v2/government-job-report", _pdf_report_payload(params), API_HOST_PDF, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_pdf_foreign_travel", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_foreign_travel(params: PDFReportInput, ctx: Context) -> str:
    """Generate a foreign travel and settlement prospects PDF report.

    Returns an astrological analysis of overseas travel potential,
    immigration prospects, and favorable periods for foreign settlement.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/indian-api/v2/foreign-travel-settlement", _pdf_report_payload(params), API_HOST_PDF, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_pdf_vedic_5year", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_vedic_5year(params: PDFReportInput, ctx: Context) -> str:
    """Generate a 5-year Vedic yearly prediction PDF report.

    Returns year-by-year predictions for the next 5 years covering career,
    relationships, health, finances, and major life events.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/indian-api/v2/vedic-yearly-prediction-5-year", _pdf_report_payload(params), API_HOST_PDF, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_pdf_vedic_10year", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_vedic_10year(params: PDFReportInput, ctx: Context) -> str:
    """Generate a 10-year Vedic yearly prediction PDF report.

    Returns year-by-year predictions for the next 10 years covering career,
    relationships, health, finances, and major life events.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/indian-api/v2/vedic-yearly-prediction-10-year", _pdf_report_payload(params), API_HOST_PDF, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_pdf_vedic_15year", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_vedic_15year(params: PDFReportInput, ctx: Context) -> str:
    """Generate a 15-year Vedic yearly prediction PDF report.

    Returns year-by-year predictions for the next 15 years covering career,
    relationships, health, finances, and major life events.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/indian-api/v2/vedic-yearly-prediction-15-year", _pdf_report_payload(params), API_HOST_PDF, api_key=api_key, auth_token=auth_token)


# ══════════════════════════════════════════════
# PDF REPORTS — WESTERN & NUMEROLOGY (5) — pdf.divineapi.com
# ══════════════════════════════════════════════


@mcp.tool(name="divine_pdf_natal_report", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_natal_report(params: NatalReportInput, ctx: Context) -> str:
    """Generate a Western astrology natal chart PDF report.

    Requires a report_code (e.g., 'CAREER-REPORT') and theme (e.g., '001') in
    addition to birth data and branding. Returns a comprehensive natal chart
    report based on Western astrology, including sun/moon/rising signs,
    planetary aspects, and house placements.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/astrology/v2/report", _natal_report_payload(params), API_HOST_PDF, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_pdf_couple_report", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_couple_report(params: CoupleReportInput, ctx: Context) -> str:
    """Generate a Western astrology couple compatibility PDF report.

    Requires a report_code (e.g., 'ALIGNED-ENERGIES-REPORT') in addition to the
    two persons' birth data and branding. Returns a detailed synastry report
    for two people including planetary aspects, composite chart analysis, and
    relationship compatibility insights.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/astrology/v1/couple", _couple_report_payload(params), API_HOST_PDF, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_pdf_numerology_prediction", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_numerology_prediction(params: NumerologyPDFInput, ctx: Context) -> str:
    """Generate a numerology prediction PDF report.

    Requires full_name, gender, a report_code (e.g., 'YEARLY-PREDICTION-3-YEAR'),
    and branding. Returns a comprehensive numerology prediction report with life
    path analysis, personal year forecasts, and detailed number interpretations
    in PDF format.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v1/prediction_reports", _numerology_pdf_payload(params), API_HOST_PDF, api_key=api_key, auth_token=auth_token)


@mcp.tool(name="divine_pdf_numerology_report", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_numerology_report(params: NumerologyPDFInput, ctx: Context) -> str:
    """Generate a full numerology analysis PDF report.

    Requires full_name, gender, a report_code (e.g., 'SCHOLARLY-SPIRITS'), and
    branding. Returns a detailed numerology report covering all core numbers,
    Lo Shu Grid, name analysis, and comprehensive life path interpretations in
    PDF format.
    """
    api_key, auth_token = _get_credentials(ctx)
    return await _call_divine_api("/numerology/v2/report", _numerology_pdf_payload(params), API_HOST_PDF, api_key=api_key, auth_token=auth_token)


async def _call_reports_v2(payload: dict, api_key: str, auth_token: str) -> str:
    """POST to the Reports V2 endpoint, which uses a JSON body and an x-api-key header.

    Unlike every other Divine API endpoint (form fields + api_key field), Reports V2
    rejects form-encoded requests with 401 'x-api-key header required'
    (verified live 2026-07-08). Raises ToolError on any failure.
    """
    url = f"{API_HOST_PDF}/api/v1/reports/generate"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                headers={
                    "Authorization": f"Bearer {auth_token}",
                    "x-api-key": api_key,
                },
                json=payload,
                timeout=120.0,
            )
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as e:
        raise ToolError(_handle_http_error(e)) from e
    except httpx.TimeoutException as e:
        raise ToolError("Request timed out. The Divine API server may be slow. Please try again.") from e
    except httpx.ConnectError as e:
        raise ToolError("Could not connect to Divine API. Please check your internet connection.") from e
    except Exception as e:
        raise ToolError(f"Unexpected error - {type(e).__name__}: {str(e)}") from e

    if isinstance(data, dict) and data.get("error"):
        raise ToolError(f"Divine API error: {data.get('error')}")
    return json.dumps(data, indent=2, ensure_ascii=False)


@mcp.tool(name="divine_pdf_reports_v2", annotations=TOOL_ANNOTATIONS)
async def divine_pdf_reports_v2(
    report_type: str = Field(..., description="Report type (e.g., 'vedic-career-report', 'vedic-marriage-report', 'western-natal-report', 'numerology-report')"),
    full_name: str = Field(..., description="Full name of the person"),
    day: str = Field(..., description="Birth day (e.g., '15')"),
    month: str = Field(..., description="Birth month (e.g., '06')"),
    year: str = Field(..., description="Birth year (e.g., '1990')"),
    hour: str = Field(..., description="Birth hour in 24h format (e.g., '14')"),
    min: str = Field(..., description="Birth minute (e.g., '30')"),
    sec: str = Field(default="0", description="Birth second"),
    gender: str = Field(..., description="Gender: 'male' or 'female'"),
    place: str = Field(..., description="Birth place (e.g., 'New Delhi')"),
    lat: str = Field(..., description="Latitude (e.g., '28.6139')"),
    lon: str = Field(..., description="Longitude (e.g., '77.2090')"),
    tzone: str = Field(..., description="Timezone offset (e.g., '5.5')"),
    company_name: str = Field(..., description="Company name printed on the report (required by the API)"),
    company_url: str = Field(..., description="Company URL printed on the report (required by the API)"),
    company_email: str = Field(..., description="Company email printed on the report (required by the API)"),
    company_mobile: str = Field(..., description="Company mobile printed on the report (required by the API)"),
    company_bio: str = Field(..., description="Company bio printed on the report (required by the API)"),
    footer_text: str = Field(..., description="Footer text printed on the report (required by the API)"),
    logo_url: str = Field(..., description="Logo image URL printed on the report (required by the API)"),
    ctx: Context = None,
) -> str:
    """Generate a comprehensive PDF report using Divine API Reports V2.

    Supports multiple report types including vedic career, marriage, health,
    western natal, and numerology reports. All seven branding fields are
    required by this endpoint. Returns URLs to the generated report
    (reportId, htmlUrl, pdfUrl, statusUrl).
    """
    api_key, auth_token = _get_credentials(ctx)
    payload = {
        "report_type": report_type, "full_name": full_name,
        "day": day, "month": month, "year": year,
        "hour": hour, "min": min, "sec": sec, "gender": gender,
        "place": place, "lat": lat, "lon": lon, "tzone": tzone,
        "company_name": company_name, "company_url": company_url,
        "company_email": company_email, "company_mobile": company_mobile,
        "company_bio": company_bio, "footer_text": footer_text,
        "logo_url": logo_url,
    }
    return await _call_reports_v2(payload, api_key, auth_token)


# ──────────────────────────────────────────────
# OAuth Login Form — /divine-login
# ──────────────────────────────────────────────

_LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Divine API - Connect Your Account</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
               min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .card { background: #fff; border-radius: 16px; padding: 40px; max-width: 420px; width: 90%;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
        .logo { text-align: center; margin-bottom: 24px; font-size: 28px; }
        h1 { font-size: 22px; color: #1a1a2e; margin-bottom: 8px; text-align: center; }
        p { color: #666; font-size: 14px; margin-bottom: 24px; text-align: center; }
        label { display: block; font-size: 13px; font-weight: 600; color: #333; margin-bottom: 6px; }
        input { width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 8px;
                font-size: 14px; margin-bottom: 16px; transition: border-color 0.2s; }
        input:focus { outline: none; border-color: #0f3460; }
        button { width: 100%; padding: 14px; background: #0f3460; color: #fff; border: none;
                 border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer;
                 transition: background 0.2s; }
        button:hover { background: #1a1a2e; }
        .help { text-align: center; margin-top: 16px; font-size: 12px; color: #999; }
        .help a { color: #0f3460; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">&#128302;</div>
        <h1>Connect Divine API</h1>
        <p>Enter your Divine API credentials to connect Divine API tools to Claude.</p>
        <form method="POST" action="/divine-login/submit">
            <input type="hidden" name="pending" value="{pending_id}">
            <label>API Key</label>
            <input type="text" name="api_key" placeholder="Your Divine API Key" required>
            <label>Auth Token</label>
            <input type="password" name="auth_token" placeholder="Your Divine Auth Token" required>
            <button type="submit">Connect</button>
        </form>
        <p class="help">Get your credentials at <a href="https://divineapi.com/api-keys" target="_blank">divineapi.com/api-keys</a></p>
    </div>
<script>
});
</script>
</body>
</html>"""


if _TRANSPORT == "http":
    @mcp.custom_route("/divine-login", methods=["GET"])
    async def divine_login_form(request):
        from starlette.responses import HTMLResponse
        pending_id = request.query_params.get("pending", "")
        html = _LOGIN_HTML.replace("{pending_id}", pending_id)
        return HTMLResponse(html)

    @mcp.custom_route("/divine-login/submit", methods=["POST"])
    async def divine_login_submit(request):
        from starlette.responses import RedirectResponse
        form = await request.form()
        pending_id = form.get("pending", "")
        api_key = form.get("api_key", "")
        auth_token = form.get("auth_token", "")

        if not _auth_provider or not hasattr(_auth_provider, "_pending_auths"):
            from starlette.responses import HTMLResponse
            return HTMLResponse("Error: Invalid session", status_code=400)

        pending = _auth_provider._pending_auths.pop(pending_id, None)
        if not pending:
            from starlette.responses import HTMLResponse
            return HTMLResponse("Error: Session expired. Please try connecting again.", status_code=400)

        # Create auth code with Divine API credentials embedded
        code = secrets.token_urlsafe(32)
        _auth_provider._auth_codes[code] = {
            "client_id": pending["client_id"],
            "divine_api_key": api_key,
            "divine_auth_token": auth_token,
            "code_challenge": pending["code_challenge"],
            "redirect_uri": pending["redirect_uri"],
            "redirect_uri_provided_explicitly": pending["redirect_uri_provided_explicitly"],
            "scopes": pending["scopes"],
            "expires_at": time.time() + 300,
        }

        # Redirect back to Claude with the auth code
        redirect_url = construct_redirect_uri(
            pending["redirect_uri"],
            code=code,
            state=pending.get("state"),
        )
        return RedirectResponse(url=redirect_url, status_code=302)


# ──────────────────────────────────────────────
# HTTP / ASGI App
# ──────────────────────────────────────────────




class ApiKeyToJwtMiddleware:
    """ASGI middleware that converts direct DivineAPI credentials into the JWT
    Bearer token the MCP auth layer expects. Two client shapes are supported:

    1. X-Divine-Api-Key + X-Divine-Auth-Token headers (VS Code, OpenAI, Gemini,
       custom clients).
    2. Authorization: Bearer <api_key>:<auth_token> - a single-field credential
       combo for platforms that cannot send custom headers (e.g. the Claude
       Messages API MCP connector). A real OAuth-issued JWT never contains a
       colon, so valid tokens are never touched.
    """

    def __init__(self, app, jwt_secret):
        self.app = app
        self.jwt_secret = jwt_secret

    def _mint(self, api_key, auth_token):
        return jwt.encode(
            {
                "divine_api_key": api_key,
                "divine_auth_token": auth_token,
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
            },
            self.jwt_secret,
            algorithm="HS256",
        )

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers_list = scope.get("headers", [])
            headers_dict = {k: v for k, v in headers_list}
            api_key = headers_dict.get(b"x-divine-api-key", b"").decode()
            auth_token = headers_dict.get(b"x-divine-auth-token", b"").decode()
            bearer = ""
            for k, v in headers_list:
                if k == b"authorization" and v.startswith(b"Bearer "):
                    bearer = v[7:].decode()
                    break

            token = None
            if api_key and auth_token and not bearer:
                token = self._mint(api_key, auth_token)
            elif ":" in bearer:
                combo_key, _, combo_token = bearer.partition(":")
                if combo_key and combo_token:
                    token = self._mint(combo_key.strip(), combo_token.strip())

            if token:
                new_headers = [(k, v) for k, v in headers_list if k != b"authorization"]
                new_headers.append((b"authorization", f"Bearer {token}".encode()))
                scope = dict(scope, headers=new_headers)

        await self.app(scope, receive, send)


def create_http_app():
    """Create ASGI app for production HTTP deployment with uvicorn."""
    from starlette.middleware.cors import CORSMiddleware

    app = mcp.streamable_http_app()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=[
            "mcp-protocol-version",
            "mcp-session-id",
            "Authorization",
            "Content-Type",
            "X-Divine-Api-Key",
            "X-Divine-Auth-Token",
        ],
        expose_headers=["mcp-session-id"],
    )
    return ApiKeyToJwtMiddleware(app, _JWT_SECRET)


# Module-level ASGI app for uvicorn (only created in HTTP mode)
app = create_http_app() if _TRANSPORT == "http" else None


# ──────────────────────────────────────────────
# Server Entry Point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    if _TRANSPORT == "http":
        mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)
    else:
        mcp.run(transport="stdio")
