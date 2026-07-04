#!/usr/bin/env python3
"""Export Netflix cookies from a local Firefox profile.

The generated Base64 blob can be pasted into the add-on setting
"Authentication cookie blob". This helper intentionally reads only local
Firefox profiles and filters the result to Netflix cookie hosts.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen


REQUIRED_COOKIE_NAMES = {"NetflixId", "SecureNetflixId", "nfvdid"}


@dataclass
class FirefoxProfile:
    name: str
    path: Path
    is_default: bool

    @property
    def cookie_db(self) -> Path:
        return self.path / "cookies.sqlite"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export Netflix cookies from a Firefox profile as a Base64 JSON blob."
    )
    parser.add_argument(
        "--profile",
        help="Firefox profile directory, or the cookies.sqlite file itself.",
    )
    parser.add_argument(
        "--profile-root",
        help="Firefox profile root containing profiles.ini.",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List discovered Firefox profiles and exit.",
    )
    parser.add_argument(
        "--format",
        choices=("blob", "json"),
        default="blob",
        help="Output format. Default: blob.",
    )
    parser.add_argument(
        "--output",
        help="Write output to this file instead of stdout.",
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Do not fail if one of the expected Netflix login cookies is missing.",
    )
    parser.add_argument(
        "--include-expired",
        action="store_true",
        help="Include cookies whose expiry timestamp is already in the past.",
    )
    parser.add_argument(
        "--kodi-url",
        help="Kodi webserver URL, for example http://libreelec.local:8080. "
             "If set, the blob is imported into the add-on through JSON-RPC.",
    )
    parser.add_argument(
        "--kodi-user",
        help="Kodi webserver username. Can also be embedded in --kodi-url.",
    )
    parser.add_argument(
        "--kodi-password",
        help="Kodi webserver password. Can also be embedded in --kodi-url.",
    )
    parser.add_argument(
        "--kodi-timeout",
        type=float,
        default=10,
        help="Kodi JSON-RPC timeout in seconds. Default: 10.",
    )
    parser.add_argument(
        "--print-after-kodi-import",
        action="store_true",
        help="Print the Base64 blob even when --kodi-url imported it successfully.",
    )
    return parser.parse_args()


def candidate_firefox_roots() -> list[Path]:
    roots: list[Path] = []
    home = Path.home()

    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.append(Path(appdata) / "Mozilla" / "Firefox")

    localappdata = os.environ.get("LOCALAPPDATA")
    if localappdata:
        packages = Path(localappdata) / "Packages"
        roots.extend(packages.glob("Mozilla.Firefox*/LocalCache/Roaming/Mozilla/Firefox"))

    roots.extend(
        [
            home / ".mozilla" / "firefox",
            home / "snap" / "firefox" / "common" / ".mozilla" / "firefox",
            home / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox",
            home / "Library" / "Application Support" / "Firefox",
        ]
    )

    seen: set[Path] = set()
    unique_roots: list[Path] = []
    for root in roots:
        try:
            resolved = root.expanduser().resolve()
        except OSError:
            continue
        if resolved in seen or not resolved.exists():
            continue
        seen.add(resolved)
        unique_roots.append(resolved)
    return unique_roots


def read_profiles_from_root(root: Path) -> list[FirefoxProfile]:
    profiles_ini = root / "profiles.ini"
    profiles: list[FirefoxProfile] = []

    if profiles_ini.exists():
        config = configparser.ConfigParser()
        config.read(profiles_ini, encoding="utf-8")
        for section in config.sections():
            if not section.startswith("Profile"):
                continue
            profile_path = config.get(section, "Path", fallback=None)
            if not profile_path:
                continue
            is_relative = config.getint(section, "IsRelative", fallback=1)
            path = root / profile_path if is_relative else Path(profile_path)
            profiles.append(
                FirefoxProfile(
                    name=config.get(section, "Name", fallback=section),
                    path=path.expanduser(),
                    is_default=config.getint(section, "Default", fallback=0) == 1,
                )
            )

    if profiles:
        return profiles

    for cookie_db in root.glob("*/cookies.sqlite"):
        profiles.append(
            FirefoxProfile(
                name=cookie_db.parent.name,
                path=cookie_db.parent,
                is_default=False,
            )
        )
    return profiles


def discover_profiles(profile_root: str | None = None) -> list[FirefoxProfile]:
    roots = [Path(profile_root).expanduser()] if profile_root else candidate_firefox_roots()
    profiles: list[FirefoxProfile] = []
    seen: set[Path] = set()

    for root in roots:
        for profile in read_profiles_from_root(root):
            try:
                resolved = profile.path.resolve()
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            profiles.append(
                FirefoxProfile(
                    name=profile.name,
                    path=resolved,
                    is_default=profile.is_default,
                )
            )
    return profiles


def choose_profile(profiles: list[FirefoxProfile]) -> FirefoxProfile:
    usable = [profile for profile in profiles if profile.cookie_db.exists()]
    if not usable:
        raise RuntimeError("No Firefox profile with cookies.sqlite was found.")

    default_profiles = [profile for profile in usable if profile.is_default]
    if default_profiles:
        return default_profiles[0]

    return max(usable, key=lambda profile: profile.cookie_db.stat().st_mtime)


def resolve_profile_arg(profile_arg: str) -> FirefoxProfile:
    path = Path(profile_arg).expanduser().resolve()
    if path.name == "cookies.sqlite":
        path = path.parent
    return FirefoxProfile(name=path.name, path=path, is_default=False)


def sqlite_readonly_uri(path: Path) -> str:
    return "file:{}?mode=ro".format(quote(path.resolve().as_posix()))


def get_table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute("PRAGMA table_info({})".format(table_name)).fetchall()
    return {row[1] for row in rows}


def read_cookie_rows(db_path: Path, include_expired: bool) -> list[dict[str, object]]:
    conn = sqlite3.connect(sqlite_readonly_uri(db_path), uri=True, timeout=2)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        columns = get_table_columns(conn, "moz_cookies")
        required_columns = {"name", "value", "host", "path", "expiry", "isSecure", "isHttpOnly"}
        missing_columns = required_columns - columns
        if missing_columns:
            raise RuntimeError(
                "cookies.sqlite has an unsupported moz_cookies schema; missing: {}".format(
                    ", ".join(sorted(missing_columns))
                )
            )

        now = int(time.time())
        cookies: list[dict[str, object]] = []
        rows = conn.execute(
            """
            SELECT name, value, host, path, expiry, isSecure, isHttpOnly
            FROM moz_cookies
            WHERE lower(host) LIKE '%netflix%'
            """
        )
        for row in rows:
            expires = int(row["expiry"]) if row["expiry"] is not None else None
            if not include_expired and expires and expires > 0 and expires < now:
                continue

            cookies.append(
                {
                    "name": row["name"],
                    "value": row["value"],
                    "domain": row["host"],
                    "path": row["path"] or "/",
                    "secure": bool(row["isSecure"]),
                    "httpOnly": bool(row["isHttpOnly"]),
                    "expires": expires,
                }
            )
        cookies.sort(key=lambda item: (str(item["domain"]), str(item["path"]), str(item["name"])))
        return cookies
    finally:
        conn.close()


def read_cookie_rows_with_copy(profile: FirefoxProfile, include_expired: bool) -> list[dict[str, object]]:
    with tempfile.TemporaryDirectory(prefix="firefox-netflix-cookies-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        for filename in ("cookies.sqlite", "cookies.sqlite-wal", "cookies.sqlite-shm"):
            source = profile.path / filename
            if source.exists():
                shutil.copy2(source, tmp_path / filename)
        return read_cookie_rows(tmp_path / "cookies.sqlite", include_expired)


def export_profile_cookies(profile: FirefoxProfile, include_expired: bool) -> list[dict[str, object]]:
    if not profile.cookie_db.exists():
        raise RuntimeError("No cookies.sqlite found in {}".format(profile.path))

    try:
        return read_cookie_rows(profile.cookie_db, include_expired)
    except sqlite3.OperationalError as exc:
        print(
            "Direct read failed ({}); retrying from a temporary copy.".format(exc),
            file=sys.stderr,
        )
        return read_cookie_rows_with_copy(profile, include_expired)


def encode_blob(cookies: list[dict[str, object]], output_format: str) -> str:
    payload = {"cookies": cookies}
    if output_format == "json":
        return json.dumps(payload, indent=2, sort_keys=True)

    raw_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.b64encode(raw_json).decode("ascii")


def write_output(text: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).expanduser().write_text(text + "\n", encoding="utf-8")
        return
    print(text)


def normalize_kodi_url(raw_url: str) -> tuple[str, str, str]:
    if "://" not in raw_url:
        raw_url = "http://" + raw_url

    parsed = urlsplit(raw_url)
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = "[{}]".format(host)
    netloc = "{}:{}".format(host, parsed.port) if parsed.port else host

    path = parsed.path.rstrip("/")
    if not path.endswith("/jsonrpc"):
        path = (path or "") + "/jsonrpc"
    safe_url = urlunsplit((parsed.scheme, netloc, path, "", ""))
    return safe_url, username, password


def kodi_json_rpc(
    kodi_url: str,
    username: str,
    password: str,
    timeout: float,
    method: str,
    params: dict[str, object],
) -> object:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if username or password:
        token = base64.b64encode("{}:{}".format(username, password).encode("utf-8")).decode("ascii")
        headers["Authorization"] = "Basic {}".format(token)

    request = Request(
        kodi_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except HTTPError as exc:
        raise RuntimeError("Kodi JSON-RPC HTTP error {}: {}".format(exc.code, exc.reason)) from exc
    except URLError as exc:
        raise RuntimeError("Kodi JSON-RPC connection failed: {}".format(exc.reason)) from exc

    result = json.loads(body)
    if "error" in result:
        error = result["error"]
        raise RuntimeError(
            "Kodi JSON-RPC error {}: {}".format(error.get("code", "?"), error.get("message", "?"))
        )
    return result.get("result")


def import_blob_to_kodi(cookie_blob: str, args: argparse.Namespace) -> None:
    kodi_url, url_user, url_password = normalize_kodi_url(args.kodi_url)
    username = args.kodi_user if args.kodi_user is not None else url_user
    password = args.kodi_password if args.kodi_password is not None else url_password
    addon_params = "/action/import_auth_cookie_blob/?{}".format(
        urlencode({"ignore_login": "true", "blob": cookie_blob})
    )
    kodi_json_rpc(
        kodi_url=kodi_url,
        username=username,
        password=password,
        timeout=args.kodi_timeout,
        method="Addons.ExecuteAddon",
        params={
            "addonid": "plugin.video.netflix",
            "params": addon_params,
            "wait": True,
        },
    )
    print("Imported authentication cookie blob into Kodi add-on settings.", file=sys.stderr)


def print_profiles(profiles: list[FirefoxProfile]) -> None:
    if not profiles:
        print("No Firefox profiles found.")
        return

    for profile in profiles:
        marker = "default" if profile.is_default else "-"
        cookie_state = "cookies.sqlite" if profile.cookie_db.exists() else "no cookies.sqlite"
        print("{}\t{}\t{}\t{}".format(marker, profile.name, cookie_state, profile.path))


def main() -> int:
    args = parse_args()

    if args.profile:
        profile = resolve_profile_arg(args.profile)
        profiles = [profile]
    else:
        profiles = discover_profiles(args.profile_root)
        if args.list_profiles:
            print_profiles(profiles)
            return 0
        profile = choose_profile(profiles)

    cookies = export_profile_cookies(profile, args.include_expired)
    if not cookies:
        print("No Netflix cookies found in {}.".format(profile.cookie_db), file=sys.stderr)
        return 2

    cookie_names = {str(cookie["name"]) for cookie in cookies}
    missing = REQUIRED_COOKIE_NAMES - cookie_names
    if missing and not args.allow_partial:
        print(
            "Missing expected Netflix login cookies: {}.".format(", ".join(sorted(missing))),
            file=sys.stderr,
        )
        print("Use --allow-partial if you still want to export this cookie set.", file=sys.stderr)
        return 3

    blob_text = encode_blob(cookies, "blob")
    if args.kodi_url:
        import_blob_to_kodi(blob_text, args)

    text = blob_text if args.format == "blob" else encode_blob(cookies, args.format)
    if args.output or not args.kodi_url or args.print_after_kodi_import:
        write_output(text, args.output)
    print(
        "Exported {} Netflix cookies from {}.".format(len(cookies), profile.path),
        file=sys.stderr,
    )
    if missing:
        print("Warning: missing {}".format(", ".join(sorted(missing))), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
