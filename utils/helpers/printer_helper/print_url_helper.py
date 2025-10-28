from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from datetime import datetime, timezone
from data.api_constants import URLAnalysis as ua, Response as r

console = Console()

def _ts_to_human(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"


def print_url_details(data, json_output=False, show_headers=False, show_engines=False):
    if json_output:
        console.print_json(data)
        return

    # Handle API error
    if not isinstance(data, dict):
        console.print("[bold red]✗ Invalid data: expected JSON object[/bold red]")
        return
    if r.ERROR in data:
        err = data[r.ERROR]
        console.print(f"[bold red]✗ Error:[/] {err.get(r.ERROR_MESSAGE, err)}")
        return

    # Extract main data
    d = data.get(ua.DATA, {})
    if not isinstance(d, dict):
        console.print_json(data)
        return

    attrs = d.get(ua.ATTR, {})

    # URL / Meta info
    original_url = attrs.get(ua.ATTR_URL, d.get(ua.ID, "N/A"))
    final_url = attrs.get(ua.ATTR_FINAL_URL, "N/A")
    title = attrs.get(ua.ATTR_TITLE, "N/A")

    # Timestamps
    last_analysis_date = _ts_to_human(attrs.get(ua.ATTR_LAST_ANALYSIS_DATE))
    first_submission_date = _ts_to_human(attrs.get(ua.ATTR_FIRST_SUBMISSION_DATE))
    last_submission_date = _ts_to_human(attrs.get(ua.ATTR_LAST_SUBMISSION_DATE))
    last_modification_date = _ts_to_human(attrs.get(ua.ATTR_LAST_MODIFICATION_DATE))
    times_submitted = attrs.get(ua.ATTR_TIMES_SUBMITTED, "N/A")

    # Stats
    stats = attrs.get(ua.ATTR_LAST_STATS, {}) or attrs.get(ua.ATTR_STATS, {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    timeout = int(stats.get("timeout", 0))
    total_engines = sum(stats.values()) if stats else None

    # Reputation / Votes
    reputation = attrs.get(ua.ATTR_REPUTATION, "N/A")
    votes = attrs.get(ua.ATTR_VOTES, {})
    votes_h = votes.get("harmless", 0)
    votes_m = votes.get("malicious", 0)

    # Verdict color logic
    if malicious > 0:
        verdict_label = "[bold red]REQUIRES INVESTIGATION[/bold red]"
    elif suspicious > 0 or (votes_m + votes_h > 0 and votes_m / max(1, votes_m + votes_h) > 0.2):
        verdict_label = "[bold yellow]SUSPICIOUS[/bold yellow]"
    else:
        verdict_label = "[bold green]LIKELY CLEAN[/bold green]"

    # HTTP info
    http_code = attrs.get(ua.ATTR_HTTP_CODE, "N/A")
    content_len = attrs.get(ua.ATTR_HTTP_CONTENT_LEN, "N/A")
    content_sha256 = attrs.get(ua.ATTR_HTTP_CONTENT_SHA256, "N/A")
    cookies = attrs.get(ua.ATTR_HTTP_COOKIES, {}) or {}
    headers = attrs.get(ua.ATTR_HTTP_HEADERS, {}) or {}
    redir_chain = attrs.get(ua.ATTR_REDIRECTION_CHAIN, []) or []

    # Tags / trackers / categories
    tags = attrs.get(ua.ATTR_TAGS, []) or []
    trackers = attrs.get(ua.ATTR_TRACKERS, {}) or {}
    categories = attrs.get(ua.ATTR_CATEGORIES, {}) or {}

    # Per-engine results
    results = attrs.get(ua.ATTR_LAST_RESULTS, {}) or attrs.get(ua.ATTR_RESULTS, {})
    highlighted = [
        (engine, info) for engine, info in results.items()
        if info.get(ua.ATTR_RESULTS_AVDETECT_CATEGORY, "").lower() in ("malicious", "suspicious")
    ]

    # Crowd context
    crowds = attrs.get(ua.ATTR_CROWD_CONTEXT, []) or []

    # === Top Summary ===
    verdict_line = (
        f"{verdict_label}  "
        f"[bold]Detections:[/] {malicious}/{total_engines or '?'}  "
        f"[bold]Reputation:[/] {reputation}  "
        f"[bold]Votes:[/] harmless {votes_h} / malicious {votes_m}"
    )

    summary_text = (
        f"[cyan]URL:[/] {original_url}\n"
        f"[cyan]Final URL:[/] {final_url}\n"
        f"[cyan]Title:[/] {title}\n\n"
        f"{verdict_line}\n\n"
        f"[cyan]Last analysis:[/] {last_analysis_date}   [cyan]Times submitted:[/] {times_submitted}\n"
        f"[cyan]First seen:[/] {first_submission_date}   [cyan]Last submission:[/] {last_submission_date}"
    )
    console.print(Panel(summary_text, title="URL Summary", expand=False))

    # === Redirection chain ===
    if redir_chain:
        console.print(Panel("  →  ".join(redir_chain), title="Redirection Chain", expand=False))

    # === HTTP Summary ===
    http_panel = (
        f"[bold]HTTP code:[/] {http_code}   [bold]Content length:[/] {content_len}\n"
        f"[bold]Content SHA256:[/] {content_sha256}\n"
        f"[bold]Cookies:[/] " + (", ".join(f"{k}={v}" for k, v in cookies.items()) if cookies else "None")
    )
    console.print(Panel(http_panel, title="HTTP Response", expand=False))

    # === Tags & Trackers ===
    trackers_summary = ", ".join(trackers.keys()) if trackers else "None"
    console.print(
        Panel(
            f"[bold]Tags:[/] {', '.join(tags) if tags else 'None'}\n"
            f"[bold]Top trackers:[/] {trackers_summary}",
            title="Tags & Trackers",
            expand=False
        )
    )

    # === Vendor categories ===
    if categories:
        cat_map = {}
        for vendor, cat in categories.items():
            cat_map.setdefault(cat, []).append(vendor)
        cat_lines = [
            f"[bold]{cat}[/bold]: {', '.join(v[:6]) + ('...' if len(v) > 6 else '')} ({len(v)})"
            for cat, v in sorted(cat_map.items(), key=lambda x: (-len(x[1]), x[0]))
        ]
        console.print(Panel("\n".join(cat_lines), title="Vendor Categories", expand=False))

    # === Scan Stats ===
    stat_table = Table(title="Scan Stats")
    stat_table.add_column("Type", justify="left")
    stat_table.add_column("Count", justify="center")
    for t, c in [("Malicious", malicious), ("Suspicious", suspicious), ("Harmless", harmless),
                 ("Undetected", undetected), ("Timeout", timeout)]:
        stat_table.add_row(t, str(c))
    console.print(stat_table)

    # === Per-engine highlights ===
    if highlighted:
        av_table = Table(title=f"Per-Engine Highlights ({len(highlighted)})")
        av_table.add_column("Engine", justify="left")
        av_table.add_column("Category", justify="center")
        av_table.add_column("Method", justify="left")
        av_table.add_column("Result", justify="left")

        for engine, info in sorted(highlighted, key=lambda x: x[0].lower()):
            cat = info.get(ua.ATTR_RESULTS_AVDETECT_CATEGORY, "N/A")
            method = info.get(ua.ATTR_RESULTS_AVMETHOD, "N/A")
            result = info.get(ua.ATTR_RESULTS_AVRESULT, "N/A")
            color = "red" if cat == "malicious" else "yellow"
            av_table.add_row(engine, f"[{color}]{cat}[/{color}]", method, result)
        console.print(av_table)
    else:
        console.print(Panel("No suspicious/malicious detections.", title="Per-Engine Highlights", expand=False))

    # === Full engine list (optional) ===
    if show_engines and results:
        all_table = Table(title="All Per-Antivirus Results")
        all_table.add_column("Engine", justify="left")
        all_table.add_column("Category", justify="center")
        all_table.add_column("Method", justify="left")
        all_table.add_column("Result", justify="left")
        for engine, info in sorted(results.items()):
            cat = info.get(ua.ATTR_RESULTS_AVDETECT_CATEGORY, "N/A")
            method = info.get(ua.ATTR_RESULTS_AVMETHOD, "N/A")
            result = info.get(ua.ATTR_RESULTS_AVRESULT, "N/A")
            color = (
                "red" if cat == "malicious" else
                "yellow" if cat == "suspicious" else
                "green" if cat == "harmless" else
                "cyan" if cat == "undetected" else "grey50"
            )
            all_table.add_row(engine, f"[{color}]{cat}[/{color}]", method, result)
        console.print(all_table)

    # === Headers (optional) ===
    if show_headers:
        if headers:
            h_table = Table(title="HTTP Response Headers")
            h_table.add_column("Header", justify="left")
            h_table.add_column("Value", justify="left")
            for k, v in headers.items():
                h_table.add_row(k, str(v))
            console.print(h_table)
        else:
            console.print(Panel("No headers available.", title="HTTP Headers", expand=False))

    # === Crowdsourced context ===
    if crowds:
        c_table = Table(title="Crowdsourced Context")
        c_table.add_column("Source", justify="left")
        c_table.add_column("Timestamp", justify="center")
        c_table.add_column("Severity", justify="center")
        c_table.add_column("Summary", justify="left")
        for item in crowds:
            src = item.get("source", "N/A")
            ts = _ts_to_human(item.get("timestamp"))
            sev = item.get("severity", "N/A")
            detail = item.get("details", item.get("title", ""))[:200]
            c_table.add_row(src, ts, sev, detail)
        console.print(c_table)

    # === Actions & IOCs ===
    iocs = []
    if content_sha256 and content_sha256 != "N/A":
        iocs.append(f"content_sha256={content_sha256}")
    if final_url and final_url != "N/A":
        iocs.append(f"final_url={final_url}")
    iocs.append(f"original_url={original_url}")

    suggestions = (
        "[bold]Suggested commands:[/bold]\n"
        "  --more-headers : show full HTTP response headers\n"
        "  --engines      : show all per-engine results\n"
        "  --export-iocs  : export IOCs (URL + content hash)\n\n"
        + ("[bold]IOCs:[/] " + ", ".join(iocs))
    )
    console.print(Panel(Align.left(suggestions), title="Actions & IOCs", expand=False))
