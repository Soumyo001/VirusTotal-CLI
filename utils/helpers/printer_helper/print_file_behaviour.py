from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import json
from collections import Counter, defaultdict

console = Console()

def _slice_list(lst, max_items):
    total = len(lst) if lst is not None else 0
    if total <= max_items:
        return lst, 0
    return lst[:max_items], total - max_items

def print_file_behaviour(data: dict, json_output: bool = False, show_all: bool = False, max_items: int = 25):
    try:
        if json_output:
            console.print_json(json.dumps(data))
            return

        # Validate data structure
        if "data" not in data or not isinstance(data["data"], dict):
            console.print("[yellow]No behaviour data found.[/yellow]")
            console.print_json(json.dumps(data))
            return

        d = data["data"]

        # Top-level summary (verdicts / tags / confidence / text highlights)
        top_left = []
        verdicts = d.get("verdicts", [])
        if verdicts:
            top_left.append(("Verdicts", ", ".join(verdicts)))
        vc = d.get("verdict_confidence")
        if vc is not None:
            top_left.append(("Verdict Confidence", str(vc)))
        tags = d.get("tags", [])
        if tags:
            top_left.append(("Tags", ", ".join(tags)))
        text_highlighted = d.get("text_highlighted", [])
        if text_highlighted:
            # show first non-empty highlight
            first_hl = next((t for t in text_highlighted if t and t.strip()), "")
            if first_hl:
                top_left.append(("Highlighted Text", first_hl if len(first_hl) < 400 else first_hl[:400] + "..."))

        if top_left:
            overview = Table(show_header=False, title="Behaviour Overview")
            for k, v in top_left:
                overview.add_row(k, v)
            console.print(overview)
            console.print()

        # ----------------- Signature Matches -----------------
        sigs = d.get("signature_matches", [])
        if sigs:
            sig_table = Table(show_lines=True, expand=True, title=f"Signature Matches (showing up to {max_items if not show_all else 'ALL'})")
            sig_table.add_column("ID", justify="right", style="bold")
            sig_table.add_column("Description", justify="left")
            sig_table.add_column("Severity", justify="center")
            sig_table.add_column("Match Data", justify="left")

            # if many duplicates, group identical signatures and count occurrences
            grouped = defaultdict(list)
            print(str(len(sigs)))
            for s in sigs:
                key = (s.get("id"), s.get("description"))
                grouped[key].append(s)

            rows = []
            for (sid, desc), sig_group in sorted(grouped.items(), key=lambda kv: (kv[0][0] or 0)):
                severity = sig_group[0].get("severity", "N/A")
                match_data = []
                for g in sig_group:
                    match_data_list = []
                    # match_data.extend(g.get("match_data", []))
                    for data in g.get("match_data", []):
                        parsed_data = None
                        try:
                            parsed_data = json.loads(data)
                        except: parsed_data = data

                        if isinstance(parsed_data, dict):
                            match_data_dict = []
                            for key, value in parsed_data.items(): match_data_dict.append(f"{key}: {value}")
                            match_data_list.append("\n".join(match_data_dict))
                        else: match_data_list.append(str(parsed_data))

                    match_data.extend(match_data_list)

                rows.append(
                    (sid or "N/A", 
                    desc or "N/A", 
                    severity, 
                    "\n".join(list(set(match_data))))
                )

            if not show_all and len(rows) > max_items:
                rows_to_show = rows[:max_items]
                remaining = len(rows) - max_items
            else:
                rows_to_show = rows
                remaining = 0

            for r in rows_to_show:
                sig_table.add_row(str(r[0]), r[1], r[2], r[3])
            console.print(sig_table)
            if remaining:
                console.print(f"[grey50]... {remaining} more signatures (use '--all' to view all)[/grey50]")
            console.print()

        # ----------------- MITRE ATT&CK Techniques -----------------
        mitre = d.get("mitre_attack_techniques", []) or d.get("attack_techniques", {})
        if isinstance(mitre, list) and mitre:
            mitre_table = Table(title="MITRE ATT&CK (list)")
            mitre_table.add_column("Technique ID", justify="center")
            mitre_table.add_column("Severity", justify="center")
            mitre_table.add_column("Description", justify="left")
            for m in mitre[: max_items if not show_all else None]:
                mitre_table.add_row(
                    m.get("id", "N/A"),
                    m.get("severity", "N/A"),
                    m.get("signature_description", m.get("description", "N/A"))
                )
            console.print(mitre_table)
            if not show_all and len(mitre) > max_items:
                console.print(f"[grey50]... {len(mitre)-max_items} more MITRE entries[/grey50]")
            console.print()
        elif isinstance(mitre, dict) and mitre:
            mitre_table = Table(title="MITRE ATT&CK (by technique)")
            mitre_table.add_column("Technique ID", justify="center")
            mitre_table.add_column("Instances", justify="center")
            mitre_table.add_column("Sample Description", justify="left")
            for tid, entries in mitre.items():
                sample_desc = entries[0].get("description", "") if isinstance(entries, list) and entries else ""
                mitre_table.add_row(tid, str(len(entries)), sample_desc[:200] + ("..." if len(sample_desc) > 200 else ""))
            console.print(mitre_table)
            console.print()

        # ----------------- Files Dropped / Written / Deleted / Opened -----------------
        def _print_file_list(title, lst, key_fields=None):
            if not lst:
                return
            if isinstance(lst, list) and lst and isinstance(lst[0], dict):
                # list of dicts (files_dropped)
                table = Table(title=f"{title} (showing up to {max_items if not show_all else 'ALL'})")
                cols = key_fields or ["path", "sha256", "type"]
                for c in cols:
                    table.add_column(c.capitalize(), justify="left")
                if not show_all and len(lst) > max_items:
                    to_show = lst[:max_items]
                    remaining = len(lst) - max_items
                else:
                    to_show = lst
                    remaining = 0
                for item in to_show:
                    row = [str(item.get(k, "")) for k in cols]
                    table.add_row(*row)
                console.print(table)
                if remaining:
                    console.print(f"[grey50]... {remaining} more items (use '--all' to see all)[/grey50]")
                console.print()
            else:
                # plain list of strings (files_written, files_deleted, files_opened)
                if not lst:
                    return
                if not show_all and len(lst) > max_items:
                    sample, remaining = _slice_list(lst, max_items)
                else:
                    sample, remaining = (lst, 0)
                panel_text = "\n".join(sample)
                panel = Panel(panel_text, title=f"{title} (showing {len(sample)})", expand=False)
                console.print(panel)
                if remaining:
                    console.print(f"[grey50]... {remaining} more items (use '--all' to see all)[/grey50]")
                console.print()

        _print_file_list("Files Dropped", d.get("files_dropped", []), key_fields=["path", "sha256", "type"])
        _print_file_list("Files Written", d.get("files_written", []))
        _print_file_list("Files Deleted", d.get("files_deleted", []))
        _print_file_list("Files Opened", d.get("files_opened", []))
        _print_file_list("Files Attributes Changed", d.get("files_attribute_changed", []))

        # ----------------- IP Traffic -----------------
        ip_traffic = d.get("ip_traffic", [])
        if ip_traffic:
            ip_counter = Counter()
            ip_ports = defaultdict(set)
            for entry in ip_traffic:
                dst_ip = entry.get("destination_ip", "N/A")
                ip_counter[dst_ip] += 1
                port = entry.get("destination_port")
                if port is not None:
                    ip_ports[dst_ip].add(str(port))
            net_table = Table(title="Network Destinations (unique)")
            net_table.add_column("Destination IP", justify="left")
            net_table.add_column("Count", justify="center")
            net_table.add_column("Ports Observed", justify="left")
            for ip, cnt in ip_counter.most_common()[: (max_items if not show_all else None)]:
                ports = ", ".join(sorted(ip_ports[ip]))
                net_table.add_row(ip, str(cnt), ports)
            console.print(net_table)
            if not show_all and len(ip_counter) > max_items:
                console.print(f"[grey50]... {len(ip_counter) - max_items} more IPs[/grey50]")
            console.print()

        # ----------------- Processes Tree -----------------
        processes = d.get("processes_tree", [])
        if processes:
            proc_table = Table(title="Processes (tree / sample)")
            proc_table.add_column("PID", justify="center")
            proc_table.add_column("Name", justify="left")
            for p in processes[: (max_items if not show_all else None)]:
                proc_table.add_row(str(p.get("process_id", p.get("pid", "N/A"))), str(p.get("name", "N/A")))
            console.print(proc_table)
            console.print()

        # ----------------- Command Executions -----------------
        cmds = d.get("command_executions", [])
        if cmds:
            if not show_all and len(cmds) > max_items:
                sample_cmds, remaining = _slice_list(cmds, max_items)
            else:
                sample_cmds, remaining = cmds, 0
            cmd_panel = Panel("\n".join(sample_cmds), title=f"Command Executions (showing {len(sample_cmds)})", expand=False)
            console.print(cmd_panel)
            if remaining:
                console.print(f"[grey50]... {remaining} more commands (use '--all')[/grey50]")
            console.print()

        # ----------------- Services Stopped -----------------
        services = d.get("services_stopped", [])
        if services:
            svc_panel = Panel("\n".join(services[: (max_items if not show_all else None)]), title="Services Stopped", expand=False)
            console.print(svc_panel)
            console.print()

        # ----------------- Attack techniques (map -> table) -----------------
        attack_map = d.get("attack_techniques", {})
        if isinstance(attack_map, dict) and attack_map:
            atk_table = Table(title="Attack Techniques (mapped)", show_lines=True)
            atk_table.add_column("Technique ID", justify="center")
            atk_table.add_column("Instances", justify="center")
            atk_table.add_column("Severity/Description", justify="left")
            for tid, entries in attack_map.items():
                if not isinstance(entries, list) or not entries: 
                    atk_table.add_row(tid, str(len(entries)), "N/A")
                    continue
                entry_list = []
                for index, entry in enumerate(entries, start=1):
                    severity = entry.get("severity", "N/A")
                    desc = entry.get("description", "N/A")
                    entry_list.append(
                        f"[bold]{index}.[/bold] Severity: {severity}\n"
                        f"   Description: {desc}"
                    )
                
                tid_entries = "\n\n".join(entry_list)
                atk_table.add_row(tid, str(len(entries)), tid_entries)

            console.print(atk_table)
            console.print()

        # ----------------- Final quick counts summary -----------------
        counts = {
            "files_dropped": len(d.get("files_dropped", [])),
            "files_written": len(d.get("files_written", [])),
            "files_opened": len(d.get("files_opened", [])),
            "signature_matches": len(d.get("signature_matches", [])),
            "ip_traffic_entries": len(d.get("ip_traffic", [])),
            "command_executions": len(d.get("command_executions", [])),
        }
        summary = Table(title="Quick Counts Summary")
        summary.add_column("Metric", justify="left")
        summary.add_column("Count", justify="center")
        for k, v in counts.items():
            summary.add_row(k.replace("_", " ").title(), str(v))
        console.print(summary)
        console.print()

    except Exception as exc:
        console.print(f"[red]Error rendering behaviour report:[/red] {exc}")
        console.print(f"[green]Use '--json' to get the full JSON output[/green]")
