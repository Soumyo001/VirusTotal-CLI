from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from data.api_constants import FileAnalysis as fa, Response as r
import json

console = Console()

def print_file_details(data, json_output=False):
    # If user wants raw JSON output
    if json_output:
        console.print_json(json.dumps(data))
        return

    # Handle API error responses
    if r.ERROR in data:
        error = data[r.ERROR]
        console.print(f"[bold red]✗ Error:[/bold red] {error.get(r.ERROR_CODE, 'Unknown error')}")
        if r.ERROR_MESSAGE in error:
            console.print(f"[yellow]{error.get(r.ERROR_MESSAGE, 'Unknown error message')}[/yellow]")
        return

    # If response contains 'data'
    if fa.DATA in data and isinstance(data[fa.DATA], dict):
        d = data[fa.DATA]

        # Case 1: File submission (no attributes yet)
        if d.get(fa.TYPE) == "analysis" and fa.ATTRIBUTES not in d:
            console.print("[yellow]🕓 File successfully submitted for analysis.[/yellow]")
            console.print(f"[cyan]Analysis ID:[/] {d.get(fa.ID, 'N/A')}")
            console.print("Run the following command to check the report:")
            console.print(f"  [bold]vt analysis file {d.get(fa.ID, '')}[/bold]")
            return

        # Case 2: Completed analysis (has attributes/stats)
        attrs = d.get(fa.ATTRIBUTES, {})
        stats = attrs.get(fa.ATTRIBUTES_STATS) or attrs.get(fa.ATTRIBUTES_LAST_STATS, {})

        # File metadata from meta section if available
        meta = data.get(fa.FILE_META, {}).get(fa.FILE_META_INFO, {})
        metadata_panel = Panel(
            f"[cyan]SHA256:[/] {meta.get('sha256', 'N/A')}\n"
            f"[cyan]MD5:[/] {meta.get('md5', 'N/A')}\n"
            f"[cyan]SHA1:[/] {meta.get('sha1', 'N/A')}\n"
            f"[cyan]Size:[/] {meta.get('size', 'N/A')} bytes",
            title="File Metadata",
            expand=False
        )
        console.print(metadata_panel)

         # Analysis stats table
        if stats:
            table = Table(title="VirusTotal Scan Summary")
            table.add_column("Status", justify="right")
            table.add_column("Count", justify="center")
            for status, color in [
                ("malicious", "red"),
                ("suspicious", "yellow"),
                ("harmless", "green"),
                ("undetected", "cyan"),
                ("timeout", "magenta"),
                ("type-unsupported", "grey50"),
                ("failure", "white")
            ]:
                if status in stats:
                    table.add_row(status.capitalize(), f"[{color}]{stats.get(status,0)}[/{color}]")
            console.print(table)

        # Per-antivirus results table
        results = attrs.get(fa.ATTRIBUTES_RESULTS, {}) or attrs.get(fa.ATTRIBUTES_LAST_RESULTS, {})
        if results:
            av_table = Table(title="Per-Antivirus Results")
            av_table.add_column("Engine", justify="left")
            av_table.add_column("Category", justify="center")
            av_table.add_column("Method", justify="left")
            av_table.add_column("Result", justify="left")

            for engine, info in sorted(results.items()):
                category = info.get(fa.ATTRIBUTES_RESULTS_AVDETECT_CATEGORY, "N/A")
                result = info.get(fa.ATTRIBUTES_RESULTS, "N/A")
                method = info.get(fa.ATTRIBUTES_RESULTS_AVMETHOD, "N/A")
                color = "red" if category == "malicious" else \
                        "yellow" if category == "suspicious" else \
                        "green" if category == "harmless" else \
                        "cyan" if category == "undetected" else "grey50"
                av_table.add_row(engine, f"[{color}]{category}[/{color}]", method, result)
            console.print(av_table)

        # show permalink if available
        permalink = attrs.get("permalink") or d.get(fa.LINKS, {}).get(fa.LINKS_ITEM)
        if permalink:
            console.print(f"[cyan]Permalink:[/] {permalink}")
        return

    # Fallback for unknown responses
    console.print_json(json.dumps(data))
