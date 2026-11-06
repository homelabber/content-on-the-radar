"""Read-only Sentinel Content hub catalog monitor with a durable notification outbox."""

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID
from datetime import datetime, timezone

LOG = logging.getLogger("sentinel_content_monitor")
PORTAL = "https://security.microsoft.com/"


class MonitorError(Exception):
    pass


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def text(value: object, field: str, required: bool = False) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise MonitorError(f"{field} must be a {'nonempty ' if required else ''}string")
    return value.strip()


def flag(value: object, field: str) -> bool:
    if value is None:
        return False
    if value in ("true", "false"):
        return value == "true"
    if not isinstance(value, bool):
        raise MonitorError(f"{field} must be a boolean or 'true'/'false'")
    return value


def load_config(path: Path) -> dict:
    with path.open(encoding="utf-8-sig") as stream:
        config = json.load(stream)
    if not isinstance(config, dict):
        raise MonitorError("Configuration must be a JSON object")
    for field in ("subscription_id", "resource_group", "workspace"):
        config[field] = text(config.get(field), field, required=True)
    try:
        UUID(config["subscription_id"])
    except ValueError as exc:
        raise MonitorError("subscription_id must be a UUID") from exc
    for field in ("resource_group", "workspace"):
        if any(character in config[field] for character in "/\\?#"):
            raise MonitorError(f"{field} must be a resource name, not a path")
    config["api_version"] = text(
        config.get("api_version", "2025-09-01"), "api_version", required=True
    )
    config["authentication"] = config.get("authentication", "azure_cli")
    if config["authentication"] not in ("azure_cli", "azure_identity"):
        raise MonitorError("authentication must be azure_cli or azure_identity")
    database = Path(text(config.get("database", "data/catalog.sqlite3"), "database", True))
    config["database"] = database if database.is_absolute() else path.parent / database
    config["webhook_url_env"] = text(
        config.get("webhook_url_env", "SENTINEL_CONTENT_WEBHOOK_URL"),
        "webhook_url_env", True,
    )
    publishers = config.get("publisher_filter", [])
    if not isinstance(publishers, list):
        raise MonitorError("publisher_filter must be an array of publisher names")
    config["publisher_filter"] = [text(p, "publisher_filter entry", True) for p in publishers]
    return config


def catalog_url(config: dict) -> str:
    path = (
        f"/subscriptions/{quote(config['subscription_id'], safe='')}"
        f"/resourceGroups/{quote(config['resource_group'], safe='')}"
        "/providers/Microsoft.OperationalInsights"
        f"/workspaces/{quote(config['workspace'], safe='')}"
        "/providers/Microsoft.SecurityInsights/contentProductPackages"
    )
    return "https://management.azure.com" + path + "?" + urlencode({
        "api-version": config["api_version"],
        "$expand": "properties/installed",
    })


def cli_token(subscription_id: str) -> str:
    executable = shutil.which("az")
    if not executable:
        raise MonitorError("Azure CLI not found; install it or configure azure_identity authentication")
    try:
        result = subprocess.run(
            [executable, "account", "get-access-token", "--subscription", subscription_id,
             "--resource", "https://management.azure.com/", "--query", "accessToken",
             "--output", "tsv", "--only-show-errors"],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except subprocess.TimeoutExpired:
        raise MonitorError("Azure CLI token acquisition timed out") from None
    if result.returncode != 0 or not result.stdout.strip():
        raise MonitorError("Azure CLI authentication failed; sign in to the configured subscription")
    return result.stdout.strip()


def validate_catalog_url(url: str, initial_url: str) -> None:
    parsed = urlsplit(url)
    original = urlsplit(initial_url)
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != "management.azure.com"
        or parsed.path.casefold() != original.path.casefold()
        or parsed.fragment
    ):
        raise MonitorError("Refusing a catalog continuation outside the requested ARM resource")


def request_json(
    url: str, *, token: str | None = None, payload: dict | None = None,
) -> object:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers)
    opener = build_opener(NoRedirects())
    for attempt in range(4):
        try:
            with opener.open(request, timeout=60) as response:
                body = response.read()
                if payload is not None:
                    return None
                return json.loads(body)
        except HTTPError as exc:
            # Retry only read requests; POST delivery can succeed before a timeout.
            if payload is None and exc.code in (429, 500, 502, 503, 504) and attempt < 3:
                retry_after = exc.headers.get("Retry-After", "")
                delay = min(int(retry_after), 60) if retry_after.isdigit() else 2 ** attempt
                time.sleep(delay)
                continue
            raise MonitorError(f"HTTP {exc.code} from {'notification' if payload else 'catalog'} endpoint") from None
        except URLError:
            raise MonitorError("Network/TLS failure contacting the configured endpoint") from None
    raise MonitorError("Catalog request exhausted retries")


def normalize(raw: object) -> dict:
    if not isinstance(raw, dict) or not isinstance(raw.get("properties"), dict):
        raise MonitorError("Catalog item is missing its properties object")
    props = raw["properties"]
    author = props.get("author") or {}
    if not isinstance(author, dict):
        raise MonitorError("Catalog author must be an object")
    return {
        "content_id": text(props.get("contentId"), "contentId", True),
        "kind": text(props.get("contentKind"), "contentKind", True),
        "name": text(props.get("displayName"), "displayName", True),
        "publisher": text(props.get("publisherDisplayName") or author.get("name"), "publisher"),
        "version": text(props.get("version"), "version", True),
        "installed_version": text(props.get("installedVersion"), "installedVersion"),
        "first_publish_date": text(props.get("firstPublishDate"), "firstPublishDate"),
        "last_publish_date": text(props.get("lastPublishDate"), "lastPublishDate"),
        "deprecated": flag(props.get("isDeprecated"), "isDeprecated"),
        "preview": flag(props.get("isPreview"), "isPreview"),
    }


def package_key(package: dict) -> str:
    return json.dumps([package["kind"], package["content_id"]], separators=(",", ":"))


def fetch_catalog(initial_url: str, get_page: Callable[[str], object]) -> dict[str, dict]:
    url = initial_url
    visited: set[str] = set()
    packages: dict[str, dict] = {}
    while url:
        validate_catalog_url(url, initial_url)
        if url in visited or len(visited) >= 10000:
            raise MonitorError("Catalog pagination loop or excessive page count")
        visited.add(url)
        page = get_page(url)
        if not isinstance(page, dict) or not isinstance(page.get("value"), list):
            raise MonitorError("Catalog response must contain a value array")
        for raw in page["value"]:
            package = normalize(raw)
            key = package_key(package)
            if key in packages:
                raise MonitorError("Catalog returned a duplicate stable package identifier")
            packages[key] = package
        url = text(page.get("nextLink"), "nextLink")
    if not packages:
        raise MonitorError("Empty catalog rejected; previous baseline is preserved")
    return packages


def changes(previous: dict[str, dict], current: dict[str, dict]) -> list[dict]:
    found = []
    for key, package in sorted(current.items()):
        old = previous.get(key)
        kinds = []
        if old is None:
            kinds.append("new_package")
        elif old["version"] != package["version"]:
            kinds.append("published_version_changed")
        gap = (package["installed_version"], package["version"])
        old_gap = (old["installed_version"], old["version"]) if old else None
        if gap[0] and gap[0] != gap[1] and gap != old_gap:
            kinds.append("installed_version_gap")
        if package["deprecated"] and (old is None or not old["deprecated"]):
            kinds.append("deprecated")
        for kind in kinds:
            found.append({
                "change_type": kind, "package": package,
                "previous_version": old["version"] if old else None,
            })
    return found


def connect(path: Path, scope: str) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    try:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS packages (
                package_key TEXT PRIMARY KEY, payload TEXT NOT NULL, present INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, detected_at TEXT NOT NULL,
                payload TEXT NOT NULL, delivery_status TEXT NOT NULL, delivered_at TEXT
            );
        """)
        with transaction(db):
            row = db.execute("SELECT value FROM metadata WHERE key = 'scope'").fetchone()
            if row and row["value"] != scope:
                raise MonitorError("Database belongs to another workspace; use a separate database")
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('scope', ?)", (scope,))
    except (MonitorError, sqlite3.Error):
        db.close()
        raise
    return db


class transaction:
    def __init__(self, db: sqlite3.Connection):
        self.db = db

    def __enter__(self):
        self.db.execute("BEGIN IMMEDIATE")
        return self.db

    def __exit__(self, kind, value, traceback):
        self.db.execute("ROLLBACK" if kind else "COMMIT")


def metadata(db: sqlite3.Connection, key: str, value: str) -> None:
    db.execute("INSERT OR REPLACE INTO metadata VALUES (?, ?)", (key, value))


def check(
    db: sqlite3.Connection, retrieve: Callable[[], dict[str, dict]], publishers: list[str],
) -> dict:
    with transaction(db):
        current = retrieve()
        initialized = db.execute(
            "SELECT value FROM metadata WHERE key = 'last_success'"
        ).fetchone() is not None
        # Retain previously seen items when a catalog entry temporarily disappears.
        previous = {
            row["package_key"]: json.loads(row["payload"])
            for row in db.execute("SELECT package_key, payload FROM packages")
        }
        detected = changes(previous, current) if initialized else []
        now = timestamp()
        allow = {publisher.casefold() for publisher in publishers}
        for event in detected:
            selected = not allow or event["package"]["publisher"].casefold() in allow
            db.execute(
                "INSERT INTO events (detected_at, payload, delivery_status) VALUES (?, ?, ?)",
                (now, json.dumps(event), "pending" if selected else "filtered"),
            )
        db.execute("UPDATE packages SET present = 0")
        db.executemany(
            "INSERT OR REPLACE INTO packages VALUES (?, ?, 1)",
            [(key, json.dumps(package)) for key, package in current.items()],
        )
        metadata(db, "last_success", now)
        return {"baseline_created": not initialized, "catalog_count": len(current),
                "changes_detected": len(detected), "last_success": now}


def pending_rows(db: sqlite3.Connection, limit: int = 25) -> list:
    return db.execute(
        "SELECT * FROM events WHERE delivery_status = 'pending' ORDER BY id LIMIT ?", (limit,)
    ).fetchall()


def digest(rows: list, scope: str) -> dict:
    events = []
    lines = ["Microsoft Sentinel Content Hub changes", f"Workspace: {scope}"]
    for row in rows:
        event = json.loads(row["payload"])
        package = event["package"]
        events.append({"event_id": row["id"], "detected_at": row["detected_at"], **event})
        lines.append(
            f"- {event['change_type']}: {package['name']} ({package['publisher'] or 'Unknown publisher'}); "
            f"published={package['version']}; installed={package['installed_version'] or 'not installed'}; "
            f"previous={event['previous_version'] or 'not previously seen'}"
        )
    lines.append(f"Open Microsoft Defender > Microsoft Sentinel > Content management > Content hub: {PORTAL}")
    batch_id = hashlib.sha256(
        (scope + ":" + ",".join(str(row["id"]) for row in rows)).encode()
    ).hexdigest()
    return {"schema_version": 1, "digest_id": batch_id, "workspace": scope,
            "text": "\n".join(lines), "content_hub_url": PORTAL, "events": events}


def deliver(
    db: sqlite3.Connection, scope: str, url: str,
    post: Callable[[str, dict], object],
) -> int:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.fragment:
        raise MonitorError("Webhook must be an HTTPS URL without userinfo or a fragment")
    # Serialize senders so overlapping scheduled processes cannot send the same batch.
    with transaction(db):
        rows = pending_rows(db)
        if not rows:
            return 0
        post(url, digest(rows, scope))
        db.executemany(
            "UPDATE events SET delivery_status = 'delivered', delivered_at = ? WHERE id = ?",
            [(timestamp(), row["id"]) for row in rows],
        )
        return len(rows)


def run(args: argparse.Namespace) -> None:
    config = load_config(args.config.resolve())
    scope = urlsplit(catalog_url(config)).path.casefold()
    with closing(connect(config["database"], scope)) as db:
        if args.command == "check":
            if args.fixture:
                def retrieve():
                    with args.fixture.open(encoding="utf-8-sig") as stream:
                        page = json.load(stream)
                    if isinstance(page, dict) and page.get("nextLink"):
                        raise MonitorError("Fixtures must contain a complete catalog, not a partial page")
                    return fetch_catalog(catalog_url(config), lambda _: page)
                result = check(db, retrieve, config["publisher_filter"])
            else:
                if config["subscription_id"] == str(UUID(int=0)) or any(
                    config[field].startswith("YOUR-") for field in ("resource_group", "workspace")
                ):
                    raise MonitorError("Replace placeholder subscription and workspace settings before a live check")
                if config["authentication"] == "azure_cli":
                    def retrieve():
                        token = cli_token(config["subscription_id"])
                        return fetch_catalog(
                            catalog_url(config), lambda url: request_json(url, token=token),
                        )
                    result = check(db, retrieve, config["publisher_filter"])
                else:
                    result = identity_check(db, config)
            print(json.dumps(result, indent=2))
            rows = pending_rows(db)
            if rows:
                print(json.dumps(digest(rows, scope), indent=2))
            if args.send:
                url = os.environ.get(config["webhook_url_env"])
                if not url:
                    raise MonitorError(f"Set {config['webhook_url_env']} before using --send")
                sent = deliver(db, scope, url, lambda u, p: request_json(u, payload=p))
                LOG.info("Delivered %s events (at most 25 per run)", sent)
        elif args.command == "history":
            rows = db.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (args.limit,)
            ).fetchall()
            print(json.dumps([
                {**dict(row), "payload": json.loads(row["payload"])} for row in rows
            ], indent=2))
        elif args.command == "status":
            state = dict(db.execute("SELECT key, value FROM metadata"))
            state["catalog_count"] = db.execute(
                "SELECT COUNT(*) FROM packages WHERE present = 1"
            ).fetchone()[0]
            state["pending_count"] = db.execute(
                "SELECT COUNT(*) FROM events WHERE delivery_status = 'pending'"
            ).fetchone()[0]
            print(json.dumps(state, indent=2))


def identity_check(db: sqlite3.Connection, config: dict) -> dict:
    try:
        from azure.identity import DefaultAzureCredential
        from azure.core.exceptions import AzureError
    except ImportError as exc:
        raise MonitorError("Install requirements-azure.txt for azure_identity authentication") from exc
    with DefaultAzureCredential() as credential:
        def retrieve():
            def get_page(url):
                token = credential.get_token("https://management.azure.com/.default")
                return request_json(url, token=token.token)
            return fetch_catalog(catalog_url(config), get_page)
        try:
            return check(db, retrieve, config["publisher_filter"])
        except AzureError:
            raise MonitorError("Azure authentication failed; check sign-in or managed identity") from None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.json"))
    commands = parser.add_subparsers(dest="command", required=True)
    checker = commands.add_parser("check", help="Refresh catalog and preview pending notifications")
    checker.add_argument("--send", action="store_true", help="Explicitly send one pending webhook batch")
    checker.add_argument("--fixture", type=Path, help="Use a synthetic complete API response offline")
    history = commands.add_parser("history", help="Print durable change history as JSON")
    history.add_argument("--limit", type=int, choices=range(1, 1001), default=100, metavar="1-1000")
    commands.add_parser("status", help="Show last successful check and outbox backlog")
    args = parser.parse_args()
    if args.command == "check" and args.fixture and args.send:
        parser.error("--fixture cannot be combined with --send; keep demo data offline")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        run(args)
    except (MonitorError, OSError, sqlite3.Error, ValueError) as exc:
        LOG.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
