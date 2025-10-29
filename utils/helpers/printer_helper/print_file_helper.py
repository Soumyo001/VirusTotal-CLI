from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import json
from data.api_constants import FileAnalysis as fa

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
        if fa.DATA in data and isinstance(data[fa.DATA], dict):
            d = data[fa.DATA]

            # --- Case 1: Freshly submitted file ---
            if d.get(fa.TYPE) == "analysis" and fa.ATTRIBUTES not in d:
                console.print("[yellow]🕓 File successfully submitted for analysis.[/yellow]")
                console.print(f"[cyan]Analysis ID:[/] {d.get(fa.ID, 'N/A')}")
                console.print("Run the following command to check the report:")
                console.print(f"  [bold]vt analysis file {d.get(fa.ID, '')}[/bold]")
                return

            # --- Case 2: Completed analysis or hash lookup ---
            attrs = d.get(fa.ATTRIBUTES, {})
            if not attrs:
                console.print_json(json.dumps(data))
                return

            # --- File Metadata ---
            overview = Table(title="File Overview", show_header=False)
            overview.add_row("Meaningful Name", attrs.get(fa.ATTRIBUTES_MEANINGFUL_NAME, "N/A"))
            overview.add_row("Size", f"{attrs.get(fa.SIZE, data.get(fa.FILE_META, {}).get(fa.FILE_META_INFO, {}).get(fa.SIZE, "N/A"))/1024:.2f} KB")
            overview.add_row("Type", attrs.get(fa.ATTRIBUTES_TYPE_DESC, "N/A"))
            overview.add_row("Tags", ", ".join(attrs.get(fa.ATTRIBUTES_TAGS, [])) or "N/A")
            overview.add_row("SHA256", attrs.get(fa.SHA256, data.get(fa.FILE_META, {}).get(fa.FILE_META_INFO, {}).get(fa.SHA256, "N/A")))
            overview.add_row("MD5", attrs.get(fa.MD5, data.get(fa.FILE_META, {}).get(fa.FILE_META_INFO, {}).get(fa.MD5, "N/A")))
            overview.add_row("SHA1", attrs.get(fa.SHA1, data.get(fa.FILE_META, {}).get(fa.FILE_META_INFO, {}).get(fa.SHA1, "N/A")))
            overview.add_row("Reputation", str(attrs.get(fa.ATTRIBUTES_REPUTATION, 0)))
            console.print(overview)
            console.print()

            # --- PowerShell Info ---
            ps_info = attrs.get(fa.ATTRIBUTES_PWSH_INFO)
            if ps_info:
                ps_table = Table(title="PowerShell Information")
                ps_table.add_column("Cmdlets", justify="left")
                ps_table.add_column("Functions", justify="left")
                cmdlets = ", ".join(ps_info.get(fa.ATTRIBUTES_PWSH_INFO_CMDLETS, []))
                functions = ", ".join(ps_info.get(fa.ATTRIBUTES_PWSH_INFO_FUNCTIONS, []))
                ps_table.add_row(cmdlets or "—", functions or "—")
                console.print(ps_table)
                console.print()

            # --- Scan Summary ---
            stats = attrs.get(fa.ATTRIBUTES_LAST_STATS, {}) or attrs.get(fa.ATTRIBUTES_STATS, {})
            if stats:
                stats_table = Table(title="VirusTotal Scan Summary")
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
            results = attrs.get(fa.ATTRIBUTES_LAST_RESULTS, {}) or attrs.get(fa.ATTRIBUTES_RESULTS, {})
            if results:
                av_table = Table(title="Per-Antivirus Results")
                av_table.add_column("Engine", justify="left")
                av_table.add_column("Category", justify="center")
                av_table.add_column("Method", justify="center")
                av_table.add_column("Result", justify="left")

                for engine, r in sorted(results.items()):
                    cat = r.get(fa.ATTRIBUTES_RESULTS_AVDETECT_CATEGORY, "N/A")
                    method = r.get(fa.ATTRIBUTES_RESULTS_AVMETHOD, "N/A")
                    result = r.get(fa.ATTRIBUTES_RESULTS_AVRESULT, "N/A")
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
            ai_results = attrs.get(fa.CRWD_AI_RESULTS, [])
            if ai_results:
                for ai in ai_results:
                    verdict_color = "red" if ai.get(fa.CRWD_AI_VERDICT) == "malicious" else "green"
                    analysis_preview = ai.get(fa.CRWD_AI_ANALYSIS, "").strip().replace('`', '"')
                    panel_text = (
                        f"[bold]{ai.get(fa.CRWD_AI_SOURCE, 'Unknown').upper()}[/bold] "
                        f"({ai.get(fa.CRWD_AI_CAT)})\n"
                        f"[{verdict_color}]Verdict: {ai.get(fa.CRWD_AI_VERDICT, 'N/A')}[/{verdict_color}]\n\n"
                        f"{analysis_preview}"
                    )
                    console.print(Panel(panel_text, title="Crowdsourced AI Analysis", expand=False))
                    console.print()

            # --- Votes ---
            votes = attrs.get(fa.ATTRIBUTES_VOTES, {})
            if votes:
                vt = Table(title="Community Votes")
                vt.add_column("Harmless", justify="center")
                vt.add_column("Malicious", justify="center")
                vt.add_row(str(votes.get("harmless", 0)), str(votes.get("malicious", 0)))
                console.print(vt)
                console.print()

            # --- Permalink ---
            permalink = d.get(fa.LINKS, {}).get(fa.LINKS_ITEM) or d.get(fa.LINKS, {}).get(fa.LINKS_SELF)
            if permalink:
                console.print(f"[cyan]Permalink:[/] {permalink}")

            return

        # === Fallback ===
        console.print_json(json.dumps(data))

    except Exception as e:
        console.print(f"[red]Error displaying response:[/red] {e}")
        console.print_json(json.dumps(data))
