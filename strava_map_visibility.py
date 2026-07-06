#!/usr/bin/env python3
"""Manage Strava activity map visibility in bulk, with CSV audit output.

Authorship note: This code was written entirely by ChatGPT under human
supervision and with partial human verification.

The script reads authentication details from Firefox HAR files saved while you were
logged in to strava.com. It then calls the same Strava web endpoints that appeared
in the captured network traffic.

The primary purpose is to inspect and update map visibility for selected Strava
activities. The CSV output is used as an audit log, verification aid, and safe
step-by-step workflow for testing before bulk changes.

Default export/audit columns:
  activity_id,start_time_utc,start_time_local,type,name,map_visible

When --set-map-visible is used, extra columns are written:
  desired_map_visible,stream_length,update_status,update_error

Security note: HAR files can contain live session cookies. Keep them private.
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import email.utils
import html
import json
import re
import sys
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9 fallback
    ZoneInfo = None  # type: ignore


@dataclass
class HarAuth:
    cookies: Dict[str, str] = field(default_factory=dict)
    csrf_token: Optional[str] = None
    user_agent: Optional[str] = None
    accept_language: Optional[str] = None
    athlete_id: Optional[str] = None
    source_files: List[str] = field(default_factory=list)


@dataclass
class MapVisibilityInfo:
    visible: bool
    length: int
    has_map: bool


NO_MAP_ACTIVITY_TYPES = {"weighttraining"}


def activity_type_has_no_map(activity_type: str) -> bool:
    """Return True for Strava activity types where map visibility is not applicable."""
    normalized = re.sub(r"[\s_-]+", "", activity_type.strip().lower())
    return normalized in NO_MAP_ACTIVITY_TYPES


class StravaExportError(RuntimeError):
    pass


class StravaAuthError(StravaExportError):
    pass


def load_json_lenient(text: str) -> Any:
    """Load JSON, accepting a HAR file that accidentally starts with an extra brace."""
    cleaned = text.lstrip("\ufeff\n\r\t ")
    if re.match(r'^\{\s*\{\s*"log"', cleaned):
        cleaned = cleaned[1:]
    return json.loads(cleaned)


def read_har_documents(path: Path) -> List[Tuple[str, Dict[str, Any]]]:
    """Read one HAR file or every .har file inside a zip archive."""
    if not path.exists():
        raise StravaExportError(f"File not found: {path}")

    documents: List[Tuple[str, Dict[str, Any]]] = []
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as zf:
            names = [name for name in zf.namelist() if name.lower().endswith(".har")]
            if not names:
                names = zf.namelist()
            for name in names:
                raw = zf.read(name).decode("utf-8", errors="replace")
                documents.append((f"{path}:{name}", load_json_lenient(raw)))
    else:
        raw = path.read_text(encoding="utf-8", errors="replace")
        documents.append((str(path), load_json_lenient(raw)))
    return documents


def response_text(entry: Dict[str, Any]) -> str:
    content = entry.get("response", {}).get("content", {}) or {}
    text = content.get("text") or ""
    if content.get("encoding") == "base64":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return text


def header_map(headers: Sequence[Dict[str, str]]) -> Dict[str, str]:
    return {h.get("name", "").lower(): h.get("value", "") for h in headers}


def parse_cookie_header(cookie_header: str) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if name:
            cookies[name] = value.strip()
    return cookies


def is_strava_url(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host == "strava.com" or host.endswith(".strava.com")


def find_athlete_id_in_text(text: str) -> Optional[str]:
    patterns = [
        r'"currentAthlete"\s*:\s*\{[^{}]*"id"\s*:\s*"?(\d+)"?',
        r'"athleteProfileId"\s*:\s*"?(\d+)"?',
        r'"currentAthleteId"\s*:\s*"?(\d+)"?',
        r'/athletes/(\d+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None


def extract_auth_from_hars(paths: Sequence[Path]) -> HarAuth:
    auth = HarAuth()
    for path in paths:
        for source_name, har in read_har_documents(path):
            auth.source_files.append(source_name)
            entries = har.get("log", {}).get("entries", [])
            for entry in entries:
                request = entry.get("request", {})
                url = request.get("url", "")
                if not is_strava_url(url):
                    continue

                headers = header_map(request.get("headers", []))
                if headers.get("cookie"):
                    auth.cookies.update(parse_cookie_header(headers["cookie"]))
                if headers.get("user-agent"):
                    auth.user_agent = headers["user-agent"]
                if headers.get("accept-language"):
                    auth.accept_language = headers["accept-language"]
                if headers.get("x-csrf-token"):
                    auth.csrf_token = headers["x-csrf-token"]

                if auth.athlete_id is None:
                    match = re.search(r"/athletes/(\d+)", url)
                    if match:
                        auth.athlete_id = match.group(1)

                if auth.athlete_id is None:
                    text = response_text(entry)
                    found = find_athlete_id_in_text(text)
                    if found:
                        auth.athlete_id = found

    if not auth.cookies:
        raise StravaExportError("No Strava cookies were found in the HAR file(s).")
    return auth


def parse_year_month(value: str) -> dt.date:
    value = value.strip()
    match = re.fullmatch(r"(\d{4})-?(\d{2})", value)
    if not match:
        raise argparse.ArgumentTypeError("Expected YYYY-MM or YYYYMM")
    year = int(match.group(1))
    month = int(match.group(2))
    if not 1 <= month <= 12:
        raise argparse.ArgumentTypeError("Month must be between 01 and 12")
    return dt.date(year, month, 1)


def parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError("Expected true or false")


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def iter_months(start: dt.date, end: dt.date) -> Iterable[dt.date]:
    current = dt.date(start.year, start.month, 1)
    end = dt.date(end.year, end.month, 1)
    while current <= end:
        yield current
        if current.month == 12:
            current = dt.date(current.year + 1, 1, 1)
        else:
            current = dt.date(current.year, current.month + 1, 1)


def parse_activity_props(raw_attr: str) -> Optional[Dict[str, Any]]:
    """Parse the data-react-props attribute embedded in Strava's interval response."""
    unescaped = html.unescape(raw_attr)
    candidates = [
        unescaped,
        # The attribute sits inside a JavaScript string, so some JSON string escapes
        # can be escaped one extra time. Decode only the sequences that break JSON.
        unescaped.replace("\\\\u", "\\u").replace("\\\\\"", "\\\""),
    ]
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return None


def parse_activities_from_interval(js_text: str) -> List[Dict[str, Any]]:
    """Extract activities from the monthly /interval response."""
    activities: List[Dict[str, Any]] = []
    seen_ids = set()

    patterns = [
        r"data-react-props=\\'(.+?)\\'",  # attribute inside jQuery(...).html("...")
        r"data-react-props='(.+?)'",
        r'data-react-props="(.+?)"',
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, js_text, flags=re.DOTALL):
            props = parse_activity_props(match.group(1))
            if not props:
                continue
            entries = props.get("appContext", {}).get("preFetchedEntries", [])
            for entry in entries:
                activity = entry.get("activity") if isinstance(entry, dict) else None
                if not isinstance(activity, dict):
                    continue
                if activity.get("ownedByCurrentAthlete") is False:
                    continue
                activity_id = str(activity.get("id") or activity.get("id_str") or "")
                if not activity_id or activity_id in seen_ids:
                    continue
                seen_ids.add(activity_id)
                activities.append(activity)

    return activities


def normalize_activity(activity: Dict[str, Any], timezone_name: str) -> Dict[str, str]:
    activity_id = str(activity.get("id") or activity.get("id_str") or "")
    start_raw = str(activity.get("startDate") or activity.get("start_date") or "")
    start_utc = start_raw
    start_local = start_raw

    if start_raw:
        try:
            parsed = dt.datetime.fromisoformat(start_raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            start_utc = parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
            if ZoneInfo is not None:
                start_local = parsed.astimezone(ZoneInfo(timezone_name)).isoformat()
        except Exception:
            pass

    return {
        "activity_id": activity_id,
        "start_time_utc": start_utc,
        "start_time_local": start_local,
        "type": str(activity.get("type") or activity.get("sport_type") or ""),
        "name": str(activity.get("activityName") or activity.get("name") or ""),
    }


def require_requests():
    try:
        import requests  # type: ignore
    except ImportError as exc:
        raise StravaExportError(
            "The 'requests' package is missing. Install it with: pip install requests"
        ) from exc
    return requests


def update_session_csrf_token(session: Any, token: Optional[str]) -> bool:
    """Store a CSRF token on the session. Returns True if it changed."""
    if not token:
        return False
    token = token.strip()
    if not token:
        return False
    old_token = session.headers.get("X-CSRF-Token")
    if old_token == token:
        return False
    session.headers.update({"X-CSRF-Token": token})
    return True


def extract_csrf_token_from_html(text: str) -> Optional[str]:
    """Extract a Rails-style csrf-token meta value from an HTML response."""
    if "csrf-token" not in text:
        return None

    patterns = [
        r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']csrf-token["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return html.unescape(match.group(1))
    return None


def refresh_csrf_from_response(session: Any, response: Any) -> bool:
    """Refresh the session CSRF token from a Strava response, if one is supplied."""
    token = response.headers.get("X-CSRF-Token") or response.headers.get("x-csrf-token")
    if token:
        return update_session_csrf_token(session, token)

    content_type = (response.headers.get("Content-Type") or "").lower()
    if "text/html" in content_type:
        try:
            return update_session_csrf_token(session, extract_csrf_token_from_html(response.text))
        except Exception:
            return False

    return False


def make_session(auth: HarAuth):
    requests = require_requests()
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": auth.user_agent
            or "Mozilla/5.0 (X11; Linux x86_64) Strava HAR export script",
            "Accept-Language": auth.accept_language or "en-US,en;q=0.9",
            "X-Requested-With": "XMLHttpRequest",
        }
    )
    if auth.csrf_token:
        update_session_csrf_token(session, auth.csrf_token)

    for name, value in auth.cookies.items():
        session.cookies.set(name, value, domain=".strava.com")
    return session


def format_duration(seconds: float) -> str:
    seconds_int = int(round(seconds))
    minutes, sec = divmod(seconds_int, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {sec}s"
    if minutes:
        return f"{minutes}m {sec}s"
    return f"{sec}s"


def retry_after_seconds(response: Any, fallback_seconds: int) -> int:
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        retry_after = retry_after.strip()
        try:
            return max(1, int(float(retry_after)))
        except ValueError:
            try:
                retry_at = email.utils.parsedate_to_datetime(retry_after)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=dt.timezone.utc)
                return max(1, int((retry_at - dt.datetime.now(dt.timezone.utc)).total_seconds()))
            except Exception:
                pass

    return max(1, fallback_seconds)


@dataclass
class StravaClient:
    session: Any
    requests_module: Any
    timeout: int
    retries: int
    sleep_seconds: float
    rate_limit_sleep: int
    max_rate_limit_retries: int
    last_request_finished_at: Optional[float] = None

    def wait_for_spacing(self) -> None:
        """Enforce a minimum delay between two Strava HTTP calls."""
        if self.sleep_seconds <= 0 or self.last_request_finished_at is None:
            return
        elapsed = time.monotonic() - self.last_request_finished_at
        remaining = self.sleep_seconds - elapsed
        if remaining > 0:
            time.sleep(remaining)

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        """Perform a Strava request with spacing, CSRF refresh, and rate-limit waiting."""
        transient_attempt = 0
        rate_limit_attempt = 0

        while True:
            self.wait_for_spacing()
            try:
                response = self.session.request(
                    method,
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    **kwargs,
                )
            except self.requests_module.RequestException as exc:
                if transient_attempt >= self.retries:
                    raise StravaExportError(f"Network error after {self.retries + 1} attempts: {exc}") from exc
                transient_attempt += 1
                sleep_for = min(60, 2**transient_attempt)
                print(
                    f"Network error; retrying in {format_duration(sleep_for)} "
                    f"({transient_attempt}/{self.retries})",
                    file=sys.stderr,
                )
                time.sleep(sleep_for)
                continue

            self.last_request_finished_at = time.monotonic()
            refresh_csrf_from_response(self.session, response)

            if response.status_code == 429:
                rate_limit_attempt += 1
                if self.max_rate_limit_retries and rate_limit_attempt > self.max_rate_limit_retries:
                    return response
                sleep_for = retry_after_seconds(response, self.rate_limit_sleep)
                print(
                    "Rate limited by Strava (HTTP 429); sleeping for "
                    f"{format_duration(sleep_for)} before retrying...",
                    file=sys.stderr,
                )
                time.sleep(sleep_for)
                continue

            if response.status_code in {500, 502, 503, 504} and transient_attempt < self.retries:
                transient_attempt += 1
                sleep_for = min(60, 2**transient_attempt)
                print(
                    f"Strava returned HTTP {response.status_code}; retrying in "
                    f"{format_duration(sleep_for)} ({transient_attempt}/{self.retries})",
                    file=sys.stderr,
                )
                time.sleep(sleep_for)
                continue

            return response

    def get(self, url: str, **kwargs: Any) -> Any:
        return self.request("GET", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Any:
        return self.request("PUT", url, **kwargs)


def ensure_not_rejected(response: Any) -> None:
    if response.status_code in (401, 403) or "/login" in response.url:
        raise StravaAuthError("Strava rejected the session. Save a fresh HAR while logged in and try again.")


def fetch_month_activities(
    client: StravaClient,
    athlete_id: str,
    month: dt.date,
) -> List[Dict[str, Any]]:
    ym = f"{month.year:04d}{month.month:02d}"
    url = f"https://www.strava.com/athletes/{athlete_id}/interval"
    params = {
        "interval": ym,
        "interval_type": "month",
        "chart_type": "miles",
        "year_offset": "0",
        "_": str(int(time.time() * 1000)),
    }
    headers = {
        "Accept": "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript",
        "Referer": f"https://www.strava.com/athletes/{athlete_id}",
    }
    response = client.get(url, headers=headers, params=params)
    ensure_not_rejected(response)
    if response.status_code >= 400:
        raise StravaExportError(f"Could not fetch month {ym}: HTTP {response.status_code}")
    return parse_activities_from_interval(response.text)


def privacy_value_is_visible(value: Any) -> bool:
    # In the captured Strava response, 0 means visible. Fully visible maps had privacy=[0,0,...].
    return value == 0 or value is False or value == "0"


def stream_length(streams: Dict[str, Any]) -> int:
    candidates: List[int] = []
    for key in ("privacy", "latlng", "distance", "altitude", "time"):
        value = streams.get(key)
        if isinstance(value, list):
            candidates.append(len(value))
    return max(candidates) if candidates else 0


def compute_map_visibility_info(streams: Dict[str, Any], mode: str) -> MapVisibilityInfo:
    length = stream_length(streams)
    has_map = length > 0 and isinstance(streams.get("latlng"), list) and bool(streams.get("latlng"))

    privacy = streams.get("privacy")
    if isinstance(privacy, list) and privacy:
        visible_flags = [privacy_value_is_visible(value) for value in privacy]
        visible = all(visible_flags) if mode == "full" else any(visible_flags)
        return MapVisibilityInfo(visible=visible, length=length, has_map=has_map)

    # Fallback: if Strava returns GPS points but no privacy stream, treat the map as visible.
    if has_map:
        return MapVisibilityInfo(visible=True, length=length, has_map=True)

    return MapVisibilityInfo(visible=False, length=length, has_map=False)


def fetch_activity_streams(client: StravaClient, activity_id: str) -> Optional[Dict[str, Any]]:
    url = f"https://www.strava.com/activities/{activity_id}/streams"
    params = [
        ("stream_types[]", "latlng"),
        ("stream_types[]", "privacy"),
        ("stream_types[]", "distance"),
        ("stream_types[]", "altitude"),
        ("_", str(int(time.time() * 1000))),
    ]
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Referer": f"https://www.strava.com/activities/{activity_id}/edit_map_visibility",
    }
    response = client.get(url, headers=headers, params=params)
    ensure_not_rejected(response)

    # Activities without GPS streams can legitimately return 404 or an empty response.
    if response.status_code == 404:
        return None
    if response.status_code >= 400:
        raise StravaExportError(f"Could not fetch streams for activity {activity_id}: HTTP {response.status_code}")

    try:
        streams = response.json()
    except ValueError as exc:
        raise StravaExportError(f"Strava returned non-JSON streams for activity {activity_id}") from exc
    if not isinstance(streams, dict):
        return None
    return streams


def fetch_map_visibility_info(client: StravaClient, activity_id: str, visibility_mode: str) -> MapVisibilityInfo:
    streams = fetch_activity_streams(client, activity_id)
    if streams is None:
        return MapVisibilityInfo(visible=False, length=0, has_map=False)
    return compute_map_visibility_info(streams, visibility_mode)


def fetch_edit_map_visibility_page(client: StravaClient, activity_id: str) -> None:
    """Load the edit page so an HTML csrf-token meta tag can refresh the session token."""
    url = f"https://www.strava.com/activities/{activity_id}/edit_map_visibility"
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": f"https://www.strava.com/activities/{activity_id}",
    }
    response = client.get(url, headers=headers)
    if response.status_code == 401 or "/login" in response.url:
        raise StravaAuthError("Strava rejected the session. Save a fresh HAR while logged in and try again.")
    if response.status_code >= 400:
        raise StravaExportError(f"Could not load edit map visibility page for activity {activity_id}: HTTP {response.status_code}")


def build_stream_privacy_payload(target_visible: bool, length: int) -> Dict[str, Any]:
    if length <= 0:
        raise StravaExportError("Cannot update map visibility without a positive stream length.")
    if target_visible:
        sub_streams: List[List[int]] = []
    else:
        sub_streams = [[0, max(0, length - 1)]]
    return {"sub_streams": sub_streams, "length": length}


def put_map_visibility(
    client: StravaClient,
    activity_id: str,
    target_visible: bool,
    length: int,
    refresh_edit_page: bool,
) -> int:
    if refresh_edit_page or not client.session.headers.get("X-CSRF-Token"):
        fetch_edit_map_visibility_page(client, activity_id)

    url = f"https://www.strava.com/activities/{activity_id}/stream_privacy"
    payload = build_stream_privacy_payload(target_visible, length)
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json;charset=utf-8",
        "Origin": "https://www.strava.com",
        "Referer": f"https://www.strava.com/activities/{activity_id}/edit_map_visibility",
    }
    response = client.put(url, headers=headers, json=payload)

    # If the CSRF token was stale, fetch the edit page and retry once with a fresh token.
    if response.status_code in (403, 422) and not refresh_edit_page:
        print(
            f"  {activity_id}: update rejected once; refreshing CSRF token and retrying...",
            file=sys.stderr,
        )
        fetch_edit_map_visibility_page(client, activity_id)
        response = client.put(url, headers=headers, json=payload)

    if response.status_code == 401 or "/login" in response.url:
        raise StravaAuthError("Strava rejected the session. Save a fresh HAR while logged in and try again.")
    if response.status_code not in (200, 202, 204):
        raise StravaExportError(f"Could not update map visibility for activity {activity_id}: HTTP {response.status_code}")
    return response.status_code


def activities_from_har(paths: Sequence[Path]) -> List[Dict[str, Any]]:
    activities: List[Dict[str, Any]] = []
    seen_ids = set()
    for path in paths:
        for _source_name, har in read_har_documents(path):
            for entry in har.get("log", {}).get("entries", []):
                url = entry.get("request", {}).get("url", "")
                if "/interval" not in url:
                    continue
                for activity in parse_activities_from_interval(response_text(entry)):
                    activity_id = str(activity.get("id") or "")
                    if activity_id and activity_id not in seen_ids:
                        seen_ids.add(activity_id)
                        activities.append(activity)
    return activities


def default_from_month() -> dt.date:
    # Strava's public launch was around 2009. Use --from for older imported history.
    return dt.date(2009, 1, 1)


def read_processed_activity_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            return {str(row.get("activity_id") or "") for row in reader if row.get("activity_id")}
    except Exception:
        return set()


def dedupe_keep_order(values: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        value = str(value).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def read_activity_ids_file(path: Path) -> List[str]:
    """Read activity IDs from a text file or a CSV with an activity_id column."""
    if not path.exists():
        raise StravaExportError(f"Activity ID file not found: {path}")

    with path.open("r", encoding="utf-8", newline="") as handle:
        sample = handle.read(4096)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample) if sample.strip() else csv.excel
        except csv.Error:
            dialect = csv.excel

        reader = csv.reader(handle, dialect)
        rows = [[cell.strip() for cell in row] for row in reader if row and any(cell.strip() for cell in row)]

    if not rows:
        return []

    first = [cell.lower() for cell in rows[0]]
    ids: List[str] = []
    if "activity_id" in first:
        index = first.index("activity_id")
        data_rows = rows[1:]
        for row in data_rows:
            if len(row) > index:
                value = row[index].strip().strip('"').strip("'")
                if value and value.isdigit():
                    ids.append(value)
    else:
        for row in rows:
            value = row[0].strip().strip('"').strip("'")
            if not value or value.startswith("#") or value.lower() == "activity_id":
                continue
            if value.isdigit():
                ids.append(value)

    return dedupe_keep_order(ids)


def default_failed_ids_path(output_path: Path) -> Path:
    return output_path.with_name(f"{output_path.stem}_failed_ids.txt")


def prepare_failed_ids_file(path: Path, resume: bool) -> set[str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not resume and path.exists():
        path.unlink()
    return set(read_activity_ids_file(path)) if path.exists() else set()


def append_failed_activity_id(path: Path, activity_id: str, seen: set[str]) -> None:
    if not activity_id or activity_id in seen:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="") as handle:
        handle.write(f"{activity_id}\n")
    seen.add(activity_id)


def build_arg_parser() -> argparse.ArgumentParser:
    today = dt.datetime.now().date().replace(day=1)
    parser = argparse.ArgumentParser(
        description="Export Strava activity time, type, name, and map visibility to CSV. Optionally update map visibility."
    )
    parser.add_argument(
        "--har",
        action="append",
        required=True,
        help="Firefox HAR file or zip containing a HAR. Repeat this option for multiple files.",
    )
    parser.add_argument("--output", "-o", default="strava_activities_map_visibility.csv", help="Output CSV path.")
    parser.add_argument("--athlete-id", help="Override athlete ID detected from the HAR.")
    parser.add_argument(
        "--activity-id",
        action="append",
        help="Process one specific activity ID. Repeat for multiple IDs. If used, monthly activity-list fetching is skipped.",
    )
    parser.add_argument(
        "--activity-ids-file",
        action="append",
        help=(
            "Process activity IDs from a file. The file may contain one ID per line or be a CSV with an "
            "activity_id column. Repeat for multiple files. If used, monthly activity-list fetching is skipped."
        ),
    )
    parser.add_argument(
        "--from",
        dest="from_month",
        type=parse_year_month,
        default=default_from_month(),
        help="First month, YYYY-MM. Default: 2009-01.",
    )
    parser.add_argument(
        "--to",
        dest="to_month",
        type=parse_year_month,
        default=today,
        help=f"Last month, YYYY-MM. Default: {today:%Y-%m}.",
    )
    parser.add_argument("--timezone", default="Europe/Budapest", help="Timezone for start_time_local. Default: Europe/Budapest.")
    parser.add_argument(
        "--sleep",
        type=float,
        default=10.0,
        help="Minimum seconds between Strava HTTP requests. Default: 10.",
    )
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds. Default: 30.")
    parser.add_argument(
        "--retries",
        type=int,
        default=5,
        help="Retries for transient network/5xx errors. Default: 5. HTTP 429 is handled separately.",
    )
    parser.add_argument(
        "--rate-limit-sleep",
        type=int,
        default=930,
        help="Seconds to sleep after HTTP 429 when Strava does not send Retry-After. Default: 930.",
    )
    parser.add_argument(
        "--max-rate-limit-retries",
        type=int,
        default=0,
        help="Maximum HTTP 429 retries per request. Default: 0, meaning unlimited retries.",
    )
    parser.add_argument("--limit", type=int, help="Process only the first N fetched activities. Useful for testing.")
    parser.add_argument(
        "--visibility-mode",
        choices=("any", "full"),
        default="any",
        help="any=true if any part of the map is visible; full=true only if every privacy point is visible. Default: any.",
    )
    parser.add_argument(
        "--set-map-visible",
        type=parse_bool,
        metavar="true|false",
        help=(
            "Set each selected activity's map visibility to this value. Without --yes, this only writes a preview CSV "
            "and does not modify Strava."
        ),
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Actually perform updates when --set-map-visible is used. Without this, update mode is preview-only.",
    )
    parser.add_argument(
        "--force-update",
        action="store_true",
        help="Send the update even when the current value already matches the requested value.",
    )
    parser.add_argument(
        "--refresh-edit-page",
        action="store_true",
        help="Load /edit_map_visibility before each PUT to refresh the CSRF token. Safer, but costs one extra request per update.",
    )
    parser.add_argument(
        "--verify-after-update",
        action="store_true",
        help="Fetch streams again after each update and record the verified value. Costs one extra request per updated activity.",
    )
    parser.add_argument(
        "--failed-ids-output",
        help=(
            "When a real update fails for a single activity, append its ID to this file and continue. "
            "Default: <output file name without .csv>_failed_ids.txt."
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="If the output CSV already exists, skip activity IDs already present in it.",
    )
    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Stop at the first per-activity read/update error. Default: write the error to CSV and continue.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only parse the HAR and print detected auth/profile details; do not call Strava.",
    )
    return parser


def collect_activity_rows(args: argparse.Namespace, client: StravaClient, auth: HarAuth, har_paths: Sequence[Path]) -> List[Dict[str, str]]:
    explicit_ids: List[str] = []
    if args.activity_id:
        explicit_ids.extend(str(activity_id) for activity_id in args.activity_id)
    if args.activity_ids_file:
        for ids_path in args.activity_ids_file:
            explicit_ids.extend(read_activity_ids_file(Path(ids_path)))

    explicit_ids = dedupe_keep_order(explicit_ids)
    if explicit_ids:
        rows = [
            {
                "activity_id": activity_id,
                "start_time_utc": "",
                "start_time_local": "",
                "type": "",
                "name": "",
            }
            for activity_id in explicit_ids
        ]
        return rows[: args.limit] if args.limit is not None else rows

    all_activities: Dict[str, Dict[str, Any]] = {}
    months = list(iter_months(args.from_month, args.to_month))
    print(f"Fetching activity list for {len(months)} months...", file=sys.stderr)
    for index, month in enumerate(months, start=1):
        activities = fetch_month_activities(client, auth.athlete_id or "", month)
        for activity in activities:
            activity_id = str(activity.get("id") or "")
            if activity_id:
                all_activities[activity_id] = activity
        print(f"  {index}/{len(months)} {month:%Y-%m}: {len(activities)} activities", file=sys.stderr)

    normalized_rows = [normalize_activity(activity, args.timezone) for activity in all_activities.values()]
    normalized_rows.sort(key=lambda row: row.get("start_time_utc", ""))
    if args.limit is not None:
        normalized_rows = normalized_rows[: args.limit]
    return normalized_rows


def output_fieldnames(update_mode: bool, verify_after_update: bool) -> List[str]:
    fieldnames = ["activity_id", "start_time_utc", "start_time_local", "type", "name", "map_visible"]
    if update_mode:
        fieldnames.extend(["desired_map_visible", "stream_length", "update_status", "update_error"])
        if verify_after_update:
            fieldnames.append("verified_map_visible")
    return fieldnames


def open_output(path: Path, fieldnames: List[str], resume: bool):
    append = resume and path.exists() and path.stat().st_size > 0
    handle = path.open("a" if append else "w", encoding="utf-8", newline="")
    writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
    if not append:
        writer.writeheader()
    return handle, writer


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    har_paths = [Path(p) for p in args.har]
    update_mode = args.set_map_visible is not None

    try:
        auth = extract_auth_from_hars(har_paths)
        if args.athlete_id:
            auth.athlete_id = args.athlete_id
        if not auth.athlete_id and not args.activity_id and not args.activity_ids_file:
            raise StravaExportError("Could not detect athlete ID. Pass it with --athlete-id.")

        if args.from_month > args.to_month:
            raise StravaExportError("--from must be earlier than or equal to --to.")

        if args.dry_run:
            parsed_activities = activities_from_har(har_paths)
            print("HAR parse OK")
            print(f"  sources: {len(auth.source_files)}")
            print(f"  athlete_id: {auth.athlete_id or 'not found'}")
            print(f"  cookies: {len(auth.cookies)} found")
            print(f"  csrf_token: {'yes' if auth.csrf_token else 'no'}")
            print(f"  user_agent: {auth.user_agent or 'not found'}")
            print(f"  activities found inside HAR interval responses: {len(parsed_activities)}")
            for activity in parsed_activities[:5]:
                normalized = normalize_activity(activity, args.timezone)
                print(
                    f"    {normalized['start_time_local']} | {normalized['type']} | "
                    f"{normalized['name']} | {normalized['activity_id']}"
                )
            if update_mode:
                print(f"  requested map visibility target: {bool_text(args.set_map_visible)}")
                print(f"  update execution: {'enabled by --yes' if args.yes else 'preview only; add --yes to modify Strava'}")
            return 0

        requests_module = require_requests()
        session = make_session(auth)
        client = StravaClient(
            session=session,
            requests_module=requests_module,
            timeout=args.timeout,
            retries=args.retries,
            sleep_seconds=args.sleep,
            rate_limit_sleep=args.rate_limit_sleep,
            max_rate_limit_retries=args.max_rate_limit_retries,
        )

        if update_mode and not args.yes:
            print(
                "Preview mode: --set-map-visible was provided without --yes, so no Strava changes will be made.",
                file=sys.stderr,
            )
        if update_mode and not auth.csrf_token:
            print(
                "No CSRF token found in HAR; the script will load the edit page before each update attempt.",
                file=sys.stderr,
            )
            args.refresh_edit_page = True

        normalized_rows = collect_activity_rows(args, client, auth, har_paths)

        output_path = Path(args.output)
        failed_ids_path: Optional[Path] = None
        failed_ids_seen: set[str] = set()
        if update_mode and args.yes:
            failed_ids_path = Path(args.failed_ids_output) if args.failed_ids_output else default_failed_ids_path(output_path)
            failed_ids_seen = prepare_failed_ids_file(failed_ids_path, args.resume)
            print(f"Failed update IDs will be written to: {failed_ids_path}", file=sys.stderr)

        processed_ids = read_processed_activity_ids(output_path) if args.resume else set()
        if processed_ids:
            before = len(normalized_rows)
            normalized_rows = [row for row in normalized_rows if row.get("activity_id") not in processed_ids]
            print(
                f"Resume enabled: skipping {before - len(normalized_rows)} activities already present in {output_path}",
                file=sys.stderr,
            )

        action = "Fetching/updating map visibility" if update_mode else "Fetching map visibility"
        print(f"{action} for {len(normalized_rows)} activities...", file=sys.stderr)

        fieldnames = output_fieldnames(update_mode, args.verify_after_update)
        handle, writer = open_output(output_path, fieldnames, args.resume)
        with handle:
            total = len(normalized_rows)
            for index, row in enumerate(normalized_rows, start=1):
                activity_id = row["activity_id"]
                try:
                    if activity_type_has_no_map(row.get("type", "")):
                        row["map_visible"] = "false"
                        if update_mode:
                            row["desired_map_visible"] = bool_text(args.set_map_visible)
                            row["stream_length"] = "0"
                            row["update_status"] = "skipped_weight_training_no_map"
                            row["update_error"] = ""
                            if args.verify_after_update:
                                row["verified_map_visible"] = ""
                        writer.writerow(row)
                        handle.flush()
                        if update_mode:
                            print(
                                f"  {index}/{total} {activity_id}: type={row.get('type', '')} "
                                f"target={bool_text(args.set_map_visible)} status={row.get('update_status', '')}",
                                file=sys.stderr,
                            )
                        else:
                            print(
                                f"  {index}/{total} {activity_id}: type={row.get('type', '')} map_visible=false",
                                file=sys.stderr,
                            )
                        continue

                    streams = fetch_activity_streams(client, activity_id)
                    if streams is None:
                        info = MapVisibilityInfo(visible=False, length=0, has_map=False)
                        info_any = info
                        info_full = info
                    else:
                        info = compute_map_visibility_info(streams, args.visibility_mode)
                        info_any = compute_map_visibility_info(streams, "any")
                        info_full = compute_map_visibility_info(streams, "full")
                    row["map_visible"] = bool_text(info.visible)

                    if update_mode:
                        row["desired_map_visible"] = bool_text(args.set_map_visible)
                        row["stream_length"] = str(info.length)
                        row["update_error"] = ""

                        # For updates, "true" means the whole map should be visible,
                        # while "false" means no part of the map should be visible.
                        already_matching_target = info_full.visible if args.set_map_visible else not info_any.visible

                        if not info.has_map or info.length <= 0:
                            row["update_status"] = "skipped_no_map_stream"
                        elif already_matching_target and not args.force_update:
                            row["update_status"] = "skipped_already_matching"
                        elif not args.yes:
                            row["update_status"] = "preview_would_update"
                        else:
                            status_code = put_map_visibility(
                                client,
                                activity_id,
                                args.set_map_visible,
                                info.length,
                                args.refresh_edit_page,
                            )
                            row["update_status"] = f"updated_http_{status_code}"
                            if args.verify_after_update:
                                verified = fetch_map_visibility_info(client, activity_id, args.visibility_mode)
                                row["verified_map_visible"] = bool_text(verified.visible)

                    writer.writerow(row)
                    handle.flush()

                    if update_mode:
                        print(
                            f"  {index}/{total} {activity_id}: map_visible={row['map_visible']} "
                            f"target={bool_text(args.set_map_visible)} status={row.get('update_status', '')}",
                            file=sys.stderr,
                        )
                    else:
                        print(f"  {index}/{total} {activity_id}: map_visible={row['map_visible']}", file=sys.stderr)

                except StravaAuthError:
                    raise
                except StravaExportError as exc:
                    if update_mode and args.yes and failed_ids_path is not None:
                        append_failed_activity_id(failed_ids_path, activity_id, failed_ids_seen)
                    if args.stop_on_error:
                        raise
                    row["map_visible"] = row.get("map_visible", "")
                    if update_mode:
                        row["desired_map_visible"] = bool_text(args.set_map_visible)
                        row["stream_length"] = row.get("stream_length", "")
                        row["update_status"] = "error"
                        row["update_error"] = str(exc)
                    writer.writerow(row)
                    handle.flush()
                    print(f"  {index}/{total} {activity_id}: ERROR: {exc}", file=sys.stderr)

        print(f"Done: {output_path}", file=sys.stderr)
        return 0

    except StravaExportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
