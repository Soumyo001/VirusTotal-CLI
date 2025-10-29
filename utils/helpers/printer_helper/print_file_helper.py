from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import json

console = Console()

def print_file_details(data, json_output=False):
    try:
        if json_output:
            console.print_json(json.dumps(data))
            return

        # === Error Handling ===
        if "error" in data:
            error = data["error"]
            console.print(f"[bold red]✗ Error:[/bold red] {error.get('code', 'Unknown error')}")
            if "message" in error:
                console.print(f"[yellow]{error['message']}[/yellow]")
            return

        # === Has 'data' section ===
        if "data" in data and isinstance(data["data"], dict):
            d = data["data"]

            # --- Case 1: Freshly submitted file ---
            if d.get("type") == "analysis" and "attributes" not in d:
                console.print("[yellow]🕓 File successfully submitted for analysis.[/yellow]")
                console.print(f"[cyan]Analysis ID:[/] {d.get('id', 'N/A')}")
                console.print("Run the following command to check the report:")
                console.print(f"  [bold]vt analysis file {d.get('id', '')}[/bold]")
                return

            # --- Case 2: Completed analysis or hash lookup ---
            attrs = d.get("attributes", {})
            if not attrs:
                console.print_json(json.dumps(data))
                return

            # --- File Metadata ---
            overview = Table(title="File Overview", show_header=False)
            overview.add_row("Meaningful Name", attrs.get("meaningful_name", "N/A"))
            overview.add_row("Size", f"{attrs.get('size', 0)/1024:.2f} KB")
            overview.add_row("Type", attrs.get("type_description", "N/A"))
            overview.add_row("Tags", ", ".join(attrs.get("tags", [])) or "N/A")
            overview.add_row("SHA256", attrs.get("sha256", "N/A"))
            overview.add_row("MD5", attrs.get("md5", "N/A"))
            overview.add_row("SHA1", attrs.get("sha1", "N/A"))
            overview.add_row("Reputation", str(attrs.get("reputation", 0)))
            console.print(overview)
            console.print()

            # --- PowerShell Info ---
            ps_info = attrs.get("powershell_info")
            if ps_info:
                ps_table = Table(title="PowerShell Information")
                ps_table.add_column("Cmdlets", justify="left")
                ps_table.add_column("Functions", justify="left")
                cmdlets = ", ".join(ps_info.get("cmdlets", []))
                functions = ", ".join(ps_info.get("functions", []))
                ps_table.add_row(cmdlets or "—", functions or "—")
                console.print(ps_table)
                console.print()

            # --- Analysis Statistics ---
            stats = attrs.get("last_analysis_stats", {})
            if stats:
                stats_table = Table(title="Analysis Statistics")
                stats_table.add_column("Status", justify="left")
                stats_table.add_column("Count", justify="right")
                for k, v in stats.items():
                    color = (
                        "red" if "malicious" in k else
                        "yellow" if "suspicious" in k else
                        "green" if "harmless" in k else
                        "cyan" if "undetected" in k else
                        "magenta" if "timeout" in k else
                        "grey50"
                    )
                    stats_table.add_row(k.capitalize(), f"[{color}]{v}[/{color}]")
                console.print(stats_table)
                console.print()

            # --- Per-Antivirus Results ---
            results = attrs.get("last_analysis_results", {})
            if results:
                av_table = Table(title="Per-Antivirus Results")
                av_table.add_column("Engine", justify="left")
                av_table.add_column("Category", justify="center")
                av_table.add_column("Method", justify="center")
                av_table.add_column("Result", justify="left")

                for engine, r in sorted(results.items()):
                    cat = r.get("category", "N/A")
                    method = r.get("method", "N/A")
                    result = r.get("result", "—") or "—"
                    color = (
                        "red" if cat == "malicious" else
                        "yellow" if cat == "suspicious" else
                        "green" if cat == "harmless" else
                        "cyan" if cat == "undetected" else
                        "grey50"
                    )
                    av_table.add_row(engine, f"[{color}]{cat}[/{color}]", method, result)
                console.print(av_table)
                console.print()

            # --- Crowdsourced AI Results ---
            ai_results = attrs.get("crowdsourced_ai_results", [])
            if ai_results:
                for ai in ai_results:
                    verdict_color = "red" if ai.get("verdict") == "malicious" else "green"
                    analysis_preview = ai.get("analysis", "").strip()
                    panel_text = (
                        f"[bold]{ai.get('source', 'Unknown').upper()}[/bold] ({ai.get('category')})\n"
                        f"[{verdict_color}]Verdict: {ai.get('verdict', 'N/A')}[/{verdict_color}]\n\n"
                        f"{analysis_preview}"
                    )
                    console.print(Panel(panel_text, title="Crowdsourced AI Analysis", expand=False))
                    console.print()

            # --- Community Votes ---
            votes = attrs.get("total_votes", {})
            if votes:
                vt = Table(title="Community Votes")
                vt.add_column("Harmless", justify="center")
                vt.add_column("Malicious", justify="center")
                vt.add_row(str(votes.get("harmless", 0)), str(votes.get("malicious", 0)))
                console.print(vt)
                console.print()

            # --- Permalink ---
            permalink = attrs.get("permalink") or d.get("links", {}).get("self")
            if permalink:
                console.print(f"[cyan]Permalink:[/] {permalink}")

            return

        # === Fallback ===
        console.print_json(json.dumps(data))

    except Exception as e:
        console.print(f"[red]Error displaying response:[/red] {e}")
        console.print_json(json.dumps(data))
