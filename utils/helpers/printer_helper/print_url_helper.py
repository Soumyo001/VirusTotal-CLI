from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from datetime import datetime, timezone
from data.api_constants import URLAnalysis as ua, Response as r
import json

console = Console()

def _ts_to_human(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"


def print_url_details(data, json_output=False, show_headers=False, show_engines=False):
    if json_output:
        console.print_json(json.dumps(data))
        return

    # Handle API error
    if not isinstance(data, dict):
        console.print("[bold red]✗ Invalid data: expected JSON object[/bold red]")
        return
    if r.ERROR in data:
        err = data[r.ERROR]
        console.print(f"[bold red]✗ Error:[/bold red] {err.get(r.ERROR_CODE, 'Unknown error')}")
        if r.ERROR_MESSAGE in err:
            console.print(f"[yellow]{err.get(r.ERROR_MESSAGE, 'Unknown error message')}[/yellow]")
        return

    # Extract main data
    d = data.get(ua.DATA, {})
    if not isinstance(d, dict):
        console.print_json(data)
        return

    # Detect manual scan JSON: /analyses response with results under attributes
    is_manual_scan = d.get("type") == "analysis" and isinstance(d.get("attributes"), dict) and "results" in d.get("attributes", {})

    # Handle "analysis submitted" case for built-in flow
    if not is_manual_scan and d.get(ua.TYPE) == "analysis" and ua.ATTR not in d:
        console.print("[yellow]🕓 File successfully submitted for analysis.[/yellow]")
        console.print(f"[cyan]Analysis ID:[/] {d.get(ua.ID, 'N/A')}")
        console.print("Run the following command to check the report:")
        console.print(f"  [bold]vt analysis url {d.get(ua.ID, '')}[/bold]")
        return

    # Populate fields depending on JSON shape
    if is_manual_scan:
        attrs = d.get(ua.ATTR, {})
        original_url = data.get(ua.META, {}).get(ua.URL_INFO, {}).get(ua.URL_INFO_URL, "N/A")
        final_url = original_url
        title = "N/A"
        results = attrs.get(ua.ATTR_RESULTS, {}) or {}
        stats = attrs.get(ua.ATTR_STATS, {}) or {}
        content_sha256 = data.get(ua.META, {}).get(ua.FILE_INFO, {}).get(ua.FILE_INFO_SHA256, "N/A")
        headers = attrs.get(ua.ATTR_HTTP_HEADERS, {}) or {}
        cookies = attrs.get(ua.ATTR_HTTP_COOKIES, {}) or {}
        redir_chain = attrs.get(ua.ATTR_REDIRECTION_CHAIN, []) or []
        tags = attrs.get(ua.ATTR_TAGS, []) or []
        trackers = attrs.get(ua.ATTR_TRACKERS, {}) or {}
        categories = attrs.get(ua.ATTR_CATEGORIES, {}) or {}
        reputation = "N/A"
        votes = {}
        votes_h = 0
        votes_m = 0
        crowds = []
        last_analysis_date = _ts_to_human(attrs.get("date"))
        first_submission_date = last_submission_date = last_modification_date = times_submitted = "N/A"
    else:
        attrs = d.get(ua.ATTR, {}) or {}
        original_url = attrs.get(ua.ATTR_URL, d.get(ua.ID, "N/A"))
        final_url = attrs.get(ua.ATTR_FINAL_URL, original_url)
        title = attrs.get(ua.ATTR_TITLE, "N/A")
        results = attrs.get(ua.ATTR_LAST_RESULTS, {}) or attrs.get(ua.ATTR_RESULTS, {}) or {}
        stats = attrs.get(ua.ATTR_LAST_STATS, {}) or attrs.get(ua.ATTR_STATS, {}) or {}
        content_sha256 = attrs.get(ua.ATTR_HTTP_CONTENT_SHA256, "N/A")
        headers = attrs.get(ua.ATTR_HTTP_HEADERS, {}) or {}
        cookies = attrs.get(ua.ATTR_HTTP_COOKIES, {}) or {}
        redir_chain = attrs.get(ua.ATTR_REDIRECTION_CHAIN, []) or []
        tags = attrs.get(ua.ATTR_TAGS, []) or []
        trackers = attrs.get(ua.ATTR_TRACKERS, {}) or {}
        categories = attrs.get(ua.ATTR_CATEGORIES, {}) or {}
        reputation = attrs.get(ua.ATTR_REPUTATION, "N/A")
        votes = attrs.get(ua.ATTR_VOTES, {}) or {}
        votes_h = votes.get("harmless", 0)
        votes_m = votes.get("malicious", 0)
        crowds = attrs.get(ua.ATTR_CROWD_CONTEXT, []) or []
        last_analysis_date = _ts_to_human(attrs.get(ua.ATTR_LAST_ANALYSIS_DATE))
        first_submission_date = _ts_to_human(attrs.get(ua.ATTR_FIRST_SUBMISSION_DATE))
        last_submission_date = _ts_to_human(attrs.get(ua.ATTR_LAST_SUBMISSION_DATE))
        last_modification_date = _ts_to_human(attrs.get(ua.ATTR_LAST_MODIFICATION_DATE))
        times_submitted = attrs.get(ua.ATTR_TIMES_SUBMITTED, "N/A")

    # Stats counts
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    timeout = int(stats.get("timeout", 0))
    total_engines = sum(stats.values()) if stats else None

    # Verdict color logic
    if malicious > 0:
        verdict_label = "[bold red]REQUIRES INVESTIGATION[/bold red]"
    elif suspicious > 0 or (votes_m + votes_h > 0 and votes_m / max(1, votes_m + votes_h) > 0.2):
        verdict_label = "[bold yellow]SUSPICIOUS[/bold yellow]"
    else:
        verdict_label = "[bold green]LIKELY CLEAN[/bold green]"

    # Prepare highlighted engines 
    highlighted = [
        (engine, info) for engine, info in results.items()
        if info.get(ua.ATTR_RESULTS_AVDETECT_CATEGORY, "").lower() in ("malicious", "suspicious")
    ]

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
        f"[bold]HTTP code:[/] {attrs.get(ua.ATTR_HTTP_CODE, 'N/A') if not is_manual_scan else 'N/A'}   [bold]Content length:[/] {attrs.get(ua.ATTR_HTTP_CONTENT_LEN, content_sha256)}\n"
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

        # Display threat names if available
        threat_names = attrs.get("threat_names", []) or []
        if threat_names:
            threat_panel = Panel(
                "\n".join(threat_names),
                title=f"Threat Names ({len(threat_names)})",
                expand=False,
                style="red"
            )
            console.print(threat_panel)
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
        if headers and isinstance(headers, dict):
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
        "  --headers : show full HTTP response headers\n"
        "  --engines      : show all per-engine results\n"
        + ("[bold]IOCs:[/] " + ", ".join(iocs))
    )
    console.print(Panel(Align.left(suggestions), title="Actions & IOCs", expand=False))
