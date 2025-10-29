from rich.console import Console
from rich.table import Table
from datetime import datetime, timezone
from data.api_constants import DomainAnalysis as da, Response as r

console = Console()

def fmt_time(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"

def print_domain_details(domain_data, json_output=False):

    if json_output:
        import json
        console.print_json(json.dumps(domain_data))
        return
    
    data = domain_data.get(da.DATA, {})
    attrs = data.get(da.ATTRIBUTES, {})
    domain_id = data.get(da.ID, "N/A")

    if r.ERROR in data:
        err = data[r.ERROR]
        console.print(f"[bold red]✗ Error:[/bold red] {err.get(r.ERROR_CODE, 'Unknown error')}")
        if r.ERROR_MESSAGE in err:
            console.print(f"[yellow]{err.get(r.ERROR_MESSAGE, 'Unknown error message')}[/yellow]")
        return
    
    if data.get(da.TYPE) == "analysis" and da.ATTRIBUTES not in data:
        console.print("[yellow]🕓 File successfully submitted for analysis.[/yellow]")
        console.print(f"[cyan]Analysis ID:[/] {data.get(da.ID, 'N/A')}")
        console.print("Run the following command to check the report:")
        console.print(f"  [bold]vt analysis url {data.get(da.ID, '')}[/bold]")
        return

    console.rule(f"[bold cyan]Domain Analysis Report: {domain_id}")

    # --- Basic Info ---
    info_table = Table(title="Basic Information")
    info_table.add_column("Field", justify="left")
    info_table.add_column("Value", justify="left")

    info_table.add_row("Category", attrs.get(da.ATTR_CATEGORY, "N/A"))
    info_table.add_row("Reputation", str(attrs.get(da.ATTR_REPUTATION, "N/A")))
    info_table.add_row("Creation Date", fmt_time(attrs.get(da.ATTR_CREATION_DATE)))
    info_table.add_row("Last Analysis", fmt_time(attrs.get(da.ATTR_LAST_ANALYSIS_DATE)))
    info_table.add_row("Last Modification", fmt_time(attrs.get(da.ATTR_LAST_MOD_DATE)))

    console.print(info_table)

    # --- Categories by Service ---
    categories = attrs.get(da.ATTR_CATEGORIES, {})
    if categories:
        cat_table = Table(title="Categorization Services")
        cat_table.add_column("Service", justify="left")
        cat_table.add_column("Category", justify="left")
        for svc, cat in categories.items():
            cat_table.add_row(svc, cat)
        console.print(cat_table)

    # --- Last Analysis Stats ---
    stats = attrs.get(da.ATTR_LAST_STATS, {}) or attrs.get(da.ATTR_STATS, {})
    if stats:
        stat_table = Table(title="Last Analysis Statistics")
        stat_table.add_column("Status", justify="left")
        stat_table.add_column("Count", justify="center")
        for k, v in stats.items():
            stat_table.add_row(k.capitalize(), str(v))
        console.print(stat_table)

    # --- Last Analysis Results ---
    results = attrs.get(da.ATTR_LAST_RESULTS, {}) or attrs.get(da.ATTR_RESULTS, {})
    if results:
        res_table = Table(title="Per-Engine Results")
        res_table.add_column("Engine", justify="left")
        res_table.add_column("Category", justify="center")
        res_table.add_column("Result", justify="left")
        res_table.add_column("Method", justify="right")

        for engine, details in results.items():
            cat = details.get(da.ATTR_RESULTS_DETECT_CATEGORY, "N/A")
            color = (
                "red" if cat == "malicious" else
                "yellow" if cat == "suspicious" else
                "green" if cat == "harmless" else
                "cyan" if cat == "undetected" else "grey50"
            )
            res_table.add_row(
                details.get(da.ATTR_RESULTS_ENGINE_NAME, engine),
                f"[{color}]{cat}[/{color}]",
                details.get(da.ATTR_RESULTS_RESULT, "N/A"),
                details.get(da.ATTR_RESULTS_METHOD, "N/A"),
            )
        console.print(res_table)

    # --- Popularity Ranks ---
    ranks = attrs.get(da.ATTR_POPULARITY_RANKS, {})
    if ranks:
        rank_table = Table(title="Popularity Ranks")
        rank_table.add_column("Service", justify="left")
        rank_table.add_column("Rank", justify="center")
        rank_table.add_column("Timestamp", justify="left")
        for name, rinfo in ranks.items():
            rank_table.add_row(name, str(rinfo.get("rank", "N/A")), fmt_time(rinfo.get("timestamp")))
        console.print(rank_table)

    # --- DNS Records ---
    dns_records = attrs.get(da.ATTR_DNS_RECORDS, [])
    if dns_records:
        dns_table = Table(title="Last DNS Records (Summary)")
        dns_table.add_column("Type", justify="center")
        dns_table.add_column("Value", justify="left")
        dns_table.add_column("TTL", justify="right")
        for rec in dns_records:  # limit to 10 for brevity
            dns_table.add_row(
                rec.get("type", "N/A"),
                rec.get("value", "N/A"),
                str(rec.get("ttl", "N/A")),
            )
        console.print(dns_table)

    # --- Whois Info ---
    registrar = attrs.get(da.ATTR_REGISTRAR, "N/A")
    whois_info = attrs.get(da.ATTR_WHOIS, "N/A")
    whois_date = fmt_time(attrs.get(da.ATTR_WHOIS_DATE))
    if registrar or whois_info:
        whois_table = Table(title="Whois Information")
        whois_table.add_column("Field", justify="left")
        whois_table.add_column("Value", justify="left")
        whois_table.add_row("Registrar", registrar)
        whois_table.add_row("Last Whois Update", whois_date)
        whois_table.add_row("Whois Raw", whois_info[:300] + "..." if len(whois_info) > 300 else whois_info)
        console.print(whois_table)

    # --- Tags ---
    tags = attrs.get(da.ATTR_TAGS, [])
    if tags:
        console.print(f"[bold]Tags:[/] {', '.join(tags)}")

    console.rule("[bold green]End of Domain Report")
