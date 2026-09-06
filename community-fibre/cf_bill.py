#!/usr/bin/env python3
"""
Log in to Community Fibre My Account, diagnose the post-login redirect loop,
and download the most recent bill.

Credentials come from the environment, never from this file:

    export CF_EMAIL='you@example.com'
    read -rs CF_PASSWORD && export CF_PASSWORD   # typed, not echoed, not in shell history
    python3 cf_bill.py

Useful flags:
    --headed        watch the browser drive itself
    --entry URL     start somewhere other than the default
    --fresh         ignore any saved session and log in from scratch
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import TimeoutError as PWTimeout
from playwright.sync_api import sync_playwright

# Community Fibre moved billing behind "My Account" in March 2026. Two portal
# hostnames are publicly referenced; the entry point below is a starting guess
# and the script records wherever it actually gets redirected to.
DEFAULT_ENTRY = "https://myaccount.communityfibre.co.uk/"
KNOWN_PORTAL_HOSTS = {
    "myaccount.communityfibre.co.uk",
    "portal.communityfibre.co.uk",
    "www.communityfibre.co.uk",
}

OUT_DIR = Path(__file__).parent / "out"
STATE_FILE = OUT_DIR / "session_state.json"
LOOP_THRESHOLD = 4  # same URL seen this many times => we are going in circles


def log(msg: str) -> None:
    print(f"[cf] {msg}", flush=True)


def norm(url: str) -> str:
    """URL identity for loop detection: scheme+host+path, query stripped.

    Auth bounces usually vary only in query params (?redirect=, ?state=), so
    including the query would hide the loop rather than reveal it.
    """
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}{p.path}"


class Tracer:
    """Records every navigation hop and every cookie the server tries to set.

    The interesting comparison for a redirect loop is between the cookies the
    server *sent* (Set-Cookie response headers) and the cookies the browser
    *kept*. A cookie the browser silently drops - wrong Domain, SameSite=None
    without Secure, an already-past Expires - looks like a successful login to
    the login page and like an anonymous visitor to every page after it, which
    is precisely a bounce between the two.
    """

    def __init__(self) -> None:
        self.hops: list[dict] = []
        self.set_cookies: list[dict] = []

    def attach(self, page) -> None:
        page.on("response", self._on_response)

    def _on_response(self, response) -> None:
        try:
            req = response.request
            if req.resource_type != "document":
                return  # only navigations matter for a redirect loop

            headers = response.all_headers()
            location = headers.get("location")
            self.hops.append(
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "status": response.status,
                    "url": response.url,
                    "location": location,
                }
            )

            # all_headers() folds repeated Set-Cookie into one newline-joined
            # value, so split it back out.
            raw = headers.get("set-cookie")
            if raw:
                for line in raw.split("\n"):
                    if line.strip():
                        self.set_cookies.append(
                            {"from": response.url, "header": line.strip()}
                        )

            arrow = f" -> {location}" if location else ""
            log(f"  {response.status} {response.url}{arrow}")
        except Exception as exc:  # a torn-down response must not kill the run
            log(f"  (trace error: {exc})")

    def looping(self) -> tuple[bool, list[str]]:
        seen: dict[str, int] = {}
        for hop in self.hops:
            key = norm(hop["url"])
            seen[key] = seen.get(key, 0) + 1
        repeats = [u for u, n in seen.items() if n >= LOOP_THRESHOLD]
        return bool(repeats), repeats


def cookie_diagnosis(tracer: Tracer, context) -> dict:
    """Diff what the server tried to set against what the browser actually holds."""
    held = context.cookies()
    held_names = {c["name"] for c in held}

    offered: dict[str, str] = {}
    for entry in tracer.set_cookies:
        name = entry["header"].split("=", 1)[0].strip()
        offered[name] = entry["header"]

    dropped = []
    for name, header in offered.items():
        if name in held_names:
            continue
        attrs = header.lower()
        reasons = []
        if "samesite=none" in attrs and "secure" not in attrs:
            reasons.append("SameSite=None without Secure - browsers reject this")
        if re.search(r"max-age=0(\s*;|\s*$)", attrs):
            reasons.append("Max-Age=0 - server is deleting it")
        if "expires=" in attrs and "max-age=" not in attrs:
            reasons.append("has an Expires date - check it is in the future")
        m = re.search(r"domain=([^;]+)", attrs)
        if m:
            reasons.append(f"scoped to domain {m.group(1).strip()}")
        dropped.append(
            {"name": name, "header": header, "possible_reasons": reasons or ["unknown"]}
        )

    return {
        "cookies_browser_holds": [
            {
                "name": c["name"],
                "domain": c["domain"],
                "path": c["path"],
                "secure": c.get("secure"),
                "sameSite": c.get("sameSite"),
                "expires": c.get("expires"),
            }
            for c in held
        ],
        "cookies_server_offered_but_browser_dropped": dropped,
    }


def find_login_fields(page):
    """Locate the credential inputs by structure rather than by hardcoded selectors.

    The portal's markup has not been inspected, so anchor on the one element
    that is unambiguous - the password input - and take the nearest preceding
    text/email input as the username field.
    """
    pw = page.locator("input[type='password']").first
    try:
        pw.wait_for(state="visible", timeout=20_000)
    except PWTimeout:
        return None, None

    for sel in (
        "input[type='email']",
        "input[name*='email' i]",
        "input[name*='user' i]",
        "input[autocomplete='username']",
        "input[type='text']",
    ):
        cand = page.locator(sel).first
        if cand.count() and cand.is_visible():
            return cand, pw
    return None, pw


def submit_login(page, user_field, pw_field, email: str, password: str) -> None:
    if user_field is None:
        raise RuntimeError(
            "Could not find a username field next to the password field. "
            "Re-run with --headed to see the page."
        )
    user_field.fill(email)
    pw_field.fill(password)

    for sel in (
        "button[type='submit']",
        "input[type='submit']",
        "button:has-text('Sign in')",
        "button:has-text('Log in')",
        "button:has-text('Login')",
    ):
        btn = page.locator(sel).first
        if btn.count() and btn.is_visible():
            btn.click()
            return
    pw_field.press("Enter")  # fall back to submitting the form directly


def looks_logged_in(page) -> bool:
    """Heuristic: we are past the wall if there is no password box and the URL
    is not a sign-in route."""
    path = urlsplit(page.url).path.lower()
    if any(k in path for k in ("sign-in", "signin", "login", "auth")):
        return False
    return page.locator("input[type='password']").count() == 0


def find_latest_bill(page) -> list[dict]:
    """Collect every candidate bill/invoice link on the current page."""
    anchors = page.eval_on_selector_all(
        "a",
        """els => els.map(e => ({
             text: (e.innerText || '').trim().slice(0, 120),
             href: e.href || '',
             download: e.getAttribute('download') || ''
           }))""",
    )
    wanted = re.compile(r"bill|invoice|statement|\.pdf", re.I)
    return [
        a
        for a in anchors
        if a["href"] and wanted.search(a["href"] + " " + a["text"] + " " + a["download"])
    ]


def download_bill(context, href: str) -> Path | None:
    """Fetch a bill over the logged-in session.

    Navigating to a download URL is not an option: Playwright aborts the
    navigation with "Download is starting" the moment the response turns out
    to be an attachment. Using the context's request API reuses the session
    cookies and hands back the bytes directly.
    """
    try:
        resp = context.request.get(href)
    except Exception as exc:
        log(f"could not fetch {href}: {exc}")
        return None

    if not resp.ok:
        log(f"could not fetch {href}: HTTP {resp.status}")
        return None

    body = resp.body()
    if not body:
        log(f"empty response from {href}")
        return None

    headers = {k.lower(): v for k, v in resp.headers.items()}
    name = None
    disp = headers.get("content-disposition", "")
    m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)', disp)
    if m:
        name = m.group(1).strip()
    if not name:
        name = Path(urlsplit(href).path).name or "bill"
    if not Path(name).suffix:
        name += ".pdf" if body[:4] == b"%PDF" else ".bin"

    if body[:4] != b"%PDF":
        log(f"warning: {name} does not look like a PDF (starts {body[:8]!r})")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    dest = OUT_DIR / name
    dest.write_bytes(body)
    return dest


def write_report(tracer: Tracer, context, extra: dict) -> Path:
    looping, repeats = tracer.looping()
    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "redirect_loop_detected": looping,
        "urls_repeated": repeats,
        "navigation_hops": tracer.hops,
        **cookie_diagnosis(tracer, context),
        **extra,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / "diagnosis.json"
    path.write_text(json.dumps(report, indent=2))
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--entry", default=DEFAULT_ENTRY)
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--fresh", action="store_true", help="ignore saved session")
    ap.add_argument("--timeout", type=int, default=45_000)
    args = ap.parse_args()

    email = os.environ.get("CF_EMAIL")
    password = os.environ.get("CF_PASSWORD")
    if not email or not password:
        print(
            "Set CF_EMAIL and CF_PASSWORD first, e.g.\n"
            "  export CF_EMAIL='you@example.com'\n"
            "  read -rs CF_PASSWORD && export CF_PASSWORD",
            file=sys.stderr,
        )
        return 2

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if args.fresh and STATE_FILE.exists():
        STATE_FILE.unlink()

    tracer = Tracer()
    bills: list[dict] = []
    saved: list[str] = []

    with sync_playwright() as pw:
        # CF_CHROMIUM lets you pin a specific Chromium build; without it
        # Playwright uses the one it manages itself.
        launch_kwargs = {"headless": not args.headed}
        if os.environ.get("CF_CHROMIUM"):
            launch_kwargs["executable_path"] = os.environ["CF_CHROMIUM"]
        browser = pw.chromium.launch(**launch_kwargs)
        context = browser.new_context(
            storage_state=str(STATE_FILE) if STATE_FILE.exists() else None,
            accept_downloads=True,
        )
        context.set_default_timeout(args.timeout)
        page = context.new_page()
        tracer.attach(page)

        log(f"opening {args.entry}")
        page.goto(args.entry, wait_until="domcontentloaded")

        if not looks_logged_in(page):
            log("login form present - signing in")
            user_field, pw_field = find_login_fields(page)
            submit_login(page, user_field, pw_field, email, password)
            try:
                page.wait_for_load_state("networkidle", timeout=args.timeout)
            except PWTimeout:
                log("page never went idle - a redirect loop would look like this")
        else:
            log("already signed in from saved session")

        looping, repeats = tracer.looping()
        if looping:
            log("REDIRECT LOOP DETECTED. Repeated URLs:")
            for url in repeats:
                log(f"  {url}")
        elif looks_logged_in(page):
            log(f"signed in - landed on {page.url}")
            context.storage_state(path=str(STATE_FILE))

            bills = find_latest_bill(page)
            if not bills:
                # Not on the billing page yet; try obvious in-app routes.
                for path in ("/bills", "/billing", "/invoices", "/account/bills"):
                    target = f"{urlsplit(page.url).scheme}://{urlsplit(page.url).netloc}{path}"
                    try:
                        page.goto(target, wait_until="domcontentloaded")
                    except Exception:
                        continue
                    bills = find_latest_bill(page)
                    if bills:
                        log(f"found bill links at {target}")
                        break

            log(f"{len(bills)} candidate bill link(s) found")
            for bill in bills[:3]:
                dest = download_bill(context, bill["href"])
                if dest:
                    saved.append(str(dest))
                    log(f"saved {dest}")
        else:
            log(f"not signed in and not looping - stopped at {page.url}")

        page.screenshot(path=str(OUT_DIR / "final_page.png"), full_page=True)
        report = write_report(
            tracer, context, {"bill_links_found": bills, "files_saved": saved}
        )
        log(f"report: {report}")
        browser.close()

    return 0 if saved or not tracer.hops else (1 if tracer.looping()[0] else 0)


if __name__ == "__main__":
    raise SystemExit(main())
