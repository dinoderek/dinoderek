# Community Fibre bill fetcher + login-loop diagnostic

Logs in to Community Fibre My Account, records exactly what happens during the
post-login redirect sequence, and downloads the most recent bill.

## Why this exists

Community Fibre moved billing into My Account in March 2026 ("Important update
– how you receive your bills is changing", 6 Mar 2026). Before that, invoices
arrived as PDF attachments on the monthly email. Since then the email only
carries the amount and a link, so the bill itself is reachable only by logging
in — which is where the redirect loop bites.

## Requirements

    pip install playwright
    playwright install chromium

## Usage

Credentials are read from the environment. Do not put them in a file.

    export CF_EMAIL='you@example.com'
    read -rs CF_PASSWORD && export CF_PASSWORD    # typed, not echoed, not in history
    python3 cf_bill.py

Flags:

| Flag | Effect |
| --- | --- |
| `--headed` | watch the browser, useful if the login form is not found |
| `--entry URL` | start at a different portal URL |
| `--fresh` | ignore the saved session and log in from scratch |
| `--timeout MS` | per-operation timeout (default 45000) |

`CF_CHROMIUM=/path/to/chrome` pins a specific Chromium build if Playwright's
managed one does not match.

## Output (`out/`, gitignored)

- `diagnosis.json` — every navigation hop with status and `Location`, plus the
  cookie diff described below
- `final_page.png` — full-page screenshot of wherever it ended up
- `<bill>.pdf` — the downloaded bill
- `session_state.json` — saved cookies so re-runs skip login. **This is a live
  credential. Delete it when you are done** (`--fresh` removes it).

## How it diagnoses the loop

The script compares the cookies the server *tried* to set (`Set-Cookie`
response headers) against the cookies the browser *actually kept*. A cookie the
browser silently drops looks like a successful login to the login page and like
an anonymous visitor to every page after it — which is exactly a bounce between
the two. Common causes it names: `SameSite=None` without `Secure`, a `Domain`
that does not match the host, and `Max-Age=0`.

Any URL seen 4+ times is reported as a loop.

## Status

The detection and download logic are tested against local fixtures that
reproduce both a cookie-dropped redirect loop and a successful login with a PDF
download. It has **not** been run against the real portal — see the note in the
commit message.
