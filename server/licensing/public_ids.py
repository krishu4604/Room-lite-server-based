"""Read-only public-ID metadata. Never joins rooms or grants RTC permissions.

Room searches require an operator-configured, authorized lookup account. None of
the signing material is returned to Android or loaded from captured log files.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from licensing.service import Denied

ROOM_SEARCH = "https://api.starmakerstudios.com/api/v17/android/tvp/en-IN/phone/xxhdpi/ktv/search/room"


def decimal(value):
    # Decimal strings preserve IDs larger than JavaScript's exact integer range.
    if type(value) is int:
        value = str(value)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,19}", value.strip()):
        raise Denied("Enter a positive decimal ID.")
    number = int(value)
    if not 0 < number < 2**63:
        raise Denied("ID is outside the supported range.")
    return str(number)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url, headers):
    try:
        with build_opener(NoRedirect()).open(Request(url, headers=headers), timeout=10) as response:
            if response.status != 200:
                raise Denied("Public-ID upstream returned a non-success HTTP status.")
            raw = response.read(131073)
            if len(raw) > 131072:
                raise Denied("Public-ID upstream response exceeded the metadata size limit.")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise Denied("Public-ID upstream returned an unexpected JSON structure.")
            return data
    except HTTPError as error:
        # Error bodies/URLs/headers can contain credentials. Return only an HTTP
        # status and a tightly bounded numeric application code, never raw text.
        status = error.code if type(error.code) is int and 100 <= error.code <= 599 else 0
        app_code = ""
        try:
            body = error.read(8193)
            if len(body) <= 8192:
                data = json.loads(body)
                item = data.get("dm_error", data.get("error", {})) if isinstance(data, dict) else {}
                code = item.get("code", item.get("error_code")) if isinstance(item, dict) else None
                if (type(code) is int or isinstance(code, str)) and re.fullmatch(r"[0-9]{1,12}", str(code)):
                    app_code = " (application code " + str(code) + ")"
        except Exception:
            pass
        finally:
            error.close()
        detail = " Credentials or request signature were rejected; this alone does not prove an expired login." if status == 401 else (
            " Access was refused; account permissions or hosting-network restrictions may be involved." if status == 403 else (
            " Upstream rate limit reached. Wait before retrying." if status == 429 else " Retry later or check the server's lookup configuration."))
        raise Denied("Public-ID upstream HTTP " + str(status) + app_code + "." + detail) from None
    except (TimeoutError, socket.timeout):
        raise Denied("Public-ID lookup timed out between the server and upstream service. Retry later.") from None
    except URLError as error:
        if isinstance(error.reason, (TimeoutError, socket.timeout)):
            raise Denied("Public-ID lookup timed out between the server and upstream service. Retry later.") from None
        if isinstance(error.reason, ssl.SSLError):
            raise Denied("Public-ID upstream TLS verification failed on the server. Do not disable certificate verification.") from None
        raise Denied("Public-ID server could not connect to the upstream service (DNS/network failure).") from None
    except ssl.SSLError:
        raise Denied("Public-ID upstream TLS verification failed on the server. Do not disable certificate verification.") from None
    except (json.JSONDecodeError, UnicodeError):
        raise Denied("Public-ID upstream returned an unreadable JSON response, possibly a hosting-network block page.") from None
    except Denied:
        raise
    except Exception:
        # Exceptions can contain signed URLs or headers: do not propagate them.
        raise Denied("Public-ID lookup unavailable. Check the server lookup configuration and retry.") from None


def room_match(data, index):
    matches = set()
    pending = [data]
    visited = 0
    while pending:
        value = pending.pop()
        visited += 1
        if visited > 10000:
            raise Denied("Room lookup response is too complex.")
        if isinstance(value, dict):
            if "index" in value and "room_id" in value:
                try:
                    if decimal(value["index"]) == index:
                        matches.add(decimal(value["room_id"]))
                except Denied:
                    pass
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    if len(matches) != 1:
        raise Denied("No unique exact room-number match. Nothing was joined.")
    return matches.pop()


class PublicIds:
    def __init__(self, transport=fetch, environment=None):
        self.transport = transport
        self.environment = os.environ if environment is None else environment

    def resolve(self, kind, value, lookup_account=None):
        value = decimal(value)
        if lookup_account is not None and kind != "room_index":
            raise Denied("Account credentials are only accepted for room-number lookup.")
        if kind == "sid":
            data = self.transport("https://pay.starmakerstudios.com/rapid/user?" +
                                  urlencode({"category": "6", "id": value}),
                                  {"Accept": "application/json", "Origin": "https://m.starmakerstudios.com"})
            user = data.get("user")
            if not isinstance(user, dict):
                raise Denied("No account found for this public SID.")
            internal = decimal(user.get("uid"))
        elif kind == "room_index":
            internal = self.room(value, lookup_account)
        else:
            raise Denied("Unsupported public-ID type.")
        result = {"kind": kind, "public_id": value, "internal_id": internal}
        if lookup_account is not None:
            result["credential_source"] = "selected_account"
        return result

    def room(self, index, lookup_account=None):
        names = ("CONSUMER_KEY", "CONSUMER_SECRET", "OAUTH_TOKEN", "OAUTH_SECRET")
        values = {name: self.environment.get("ROOMLITE_LOOKUP_" + name, "") for name in names}
        if lookup_account is not None:
            # Signed active-device request only. Never persist these values or
            # mutate global configuration/another user's lookup account.
            if not isinstance(lookup_account, dict) or set(lookup_account) != {"uid", "oauth_token", "oauth_secret"}:
                raise Denied("Invalid selected-account lookup credentials. Sign in again.")
            decimal(lookup_account.get("uid"))
            for source, target in (("oauth_token", "OAUTH_TOKEN"), ("oauth_secret", "OAUTH_SECRET")):
                item = lookup_account.get(source)
                if not isinstance(item, str) or not 1 <= len(item) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in item):
                    raise Denied("Selected account needs a valid OAuth token and secret. Sign in again.")
                values[target] = item
        if any(not isinstance(v, str) or not v or len(v) > 8192 for v in values.values()):
            raise Denied("Live room-number lookup is not configured on the server. Consumer signing credentials are required; selected-account lookup also needs its login token and secret.")
        user_agent = self.environment.get("ROOMLITE_LOOKUP_USER_AGENT", "")
        if not isinstance(user_agent, str) or not 1 <= len(user_agent) <= 512 or any(ord(c) < 32 or ord(c) > 126 for c in user_agent):
            raise Denied("Set the authorized lookup client's User-Agent on the server. Internal room IDs still work.")
        # Empty context values succeeded in the approved live lookup. They are
        # optional, not missing account credentials, and must not block lookup.
        context = {name: self.environment.get("ROOMLITE_LOOKUP_" + name, "") for name in ("SEARCH_KEY", "SESSION_ID")}
        if any(not isinstance(v, str) or len(v) > 8192 for v in context.values()):
            raise Denied("Invalid room-search context configuration.")
        query = {"keyword": index, "page": "1", "source": "party", "sug_type": "",
                 "trigger_type": "manual_input", "search_key": context["SEARCH_KEY"], "session_id": context["SESSION_ID"]}
        oauth = {"oauth_consumer_key": values["CONSUMER_KEY"], "oauth_token": values["OAUTH_TOKEN"],
                 "oauth_nonce": secrets.token_hex(16), "oauth_timestamp": str(int(time.time())),
                 "oauth_signature_method": "HMAC-SHA1", "oauth_version": "1.0"}
        enc = lambda s: quote(str(s), safe="")
        pairs = sorted((enc(k), enc(v)) for k, v in {**query, **oauth}.items())
        # Same canonical signing URL used by the existing backend's v17 signer.
        signing_url = ROOM_SEARCH.replace("api.starmakerstudios.com", "starmakerapp-hrd.appspot.com").replace("/v17/", "/v16/")
        base = "GET&" + enc(signing_url) + "&" + enc("&".join(k + "=" + v for k, v in pairs))
        key = enc(values["CONSUMER_SECRET"]) + "&" + enc(values["OAUTH_SECRET"])
        oauth["oauth_signature"] = base64.b64encode(hmac.new(key.encode(), base.encode(), hashlib.sha1).digest()).decode()
        headers = {"Accept": "application/json", "country": "in", "User-Agent": user_agent, "Authorization": "OAuth " +
                   ", ".join(enc(k) + '=\"' + enc(v) + '\"' for k, v in sorted(oauth.items()))}
        return room_match(self.transport(ROOM_SEARCH + "?" + urlencode(query), headers), index)
