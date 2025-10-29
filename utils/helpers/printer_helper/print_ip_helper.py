from rich.console import Console
from rich.table import Table
from datetime import datetime, timezone
from data.api_constants import IPAnalysis as ia, Response as r

console = Console()

def fmt_time(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"


def print_ip_details(ip_data, json_output=False):
    if json_output:
        import json
        console.print_json(json.dumps(ip_data))
        return

    data = ip_data.get(ia.DATA, {})
    attrs = data.get(ia.ATTRIBUTES, {})
    ip_addr = data.get(ia.ID, "N/A")

    if r.ERROR in data:
        err = data[r.ERROR]
        console.print(f"[bold red]✗ Error:[/bold red] {err.get(r.ERROR_CODE, 'Unknown error')}")
        if r.ERROR_MESSAGE in err:
            console.print(f"[yellow]{err.get(r.ERROR_MESSAGE, 'Unknown error message')}[/yellow]")
        return
    
    if data.get(ia.TYPE) == "analysis" and ia.ATTRIBUTES not in data:
        console.print("[yellow]🕓 File successfully submitted for analysis.[/yellow]")
        console.print(f"[cyan]Analysis ID:[/] {data.get(ia.ID, 'N/A')}")
        console.print("Run the following command to check the report:")
        console.print(f"  [bold]vt analysis domain {data.get(ia.ID, '')}[/bold]")
        return

    console.rule(f"[bold cyan]IP Analysis Report: [white]{ip_addr}[/white]")

    # --- Basic Info ---
    info_table = Table(title="[bold cyan]Basic Information")
    info_table.add_column("Field", justify="left")
    info_table.add_column("Value", justify="left")

    info_table.add_row("Owner (AS)", str(attrs.get(ia.ATTR_AS_OWNER, "N/A")))
    info_table.add_row("ASN", str(attrs.get(ia.ATTR_ASN, "N/A")))
    info_table.add_row("Network Range", attrs.get(ia.ATTR_NETWORK, "N/A"))
    info_table.add_row("RIR", attrs.get(ia.ATTR_REGIONAL_INTERNET_REGISTRY, "N/A"))
    info_table.add_row("Continent", attrs.get(ia.ATTR_CONTINENT, "N/A"))
    info_table.add_row("Country", attrs.get(ia.ATTR_COUNTRY, "N/A"))
    info_table.add_row("Reputation", f"[magenta]{str(attrs.get(ia.ATTR_REPUTATION, 'N/A'))}[/magenta]")
    info_table.add_row("Last Modification", f"[dim]{fmt_time(attrs.get(ia.ATTR_LAST_MOD_DATE))}[/dim]")
    info_table.add_row("Last Analysis", f"[dim]{fmt_time(attrs.get(ia.ATTR_LAST_ANALYSIS_DATE))}[/dim]")

    console.print(info_table)

    # --- Last Analysis Stats ---
    stats = attrs.get(ia.ATTR_LAST_STATS, {}) or attrs.get(ia.ATTR_STATS, {})
    if stats:
        stat_table = Table(title="Last Analysis Statistics")
        stat_table.add_column("Status", justify="left")
        stat_table.add_column("Count", justify="center")
        for k, v in stats.items():
            _k_low = k.lower() if isinstance(k, str) else ""
            _col = "green" if _k_low == "harmless" else ("red" if _k_low == "malicious" else ("yellow" if _k_low == "suspicious" else "grey70"))
            stat_table.add_row(f"[{_col}]{k.capitalize()}[/{_col}]", f"[{_col}]{str(v)}[/{_col}]")
        console.print(stat_table)

    # --- Last Analysis Results ---
    results = attrs.get(ia.ATTR_LAST_RESULTS, {}) or attrs.get(ia.ATTR_RESULTS, {})
    if results:
        res_table = Table(title="Per-Engine Results")
        res_table.add_column("Engine", justify="left")
        res_table.add_column("Category", justify="center")
        res_table.add_column("Result", justify="left")
        res_table.add_column("Method", justify="right")

        for engine, details in results.items():
            cat = details.get(ia.ATTR_RESULTS_DETECT_CATEGORY, "N/A")
            color = (
                "red" if cat == "malicious" else
                "yellow" if cat == "suspicious" else
                "green" if cat == "harmless" else
                "cyan" if cat == "undetected" else "grey50"
            )
            res_table.add_row(
                details.get(ia.ATTR_RESULTS_ENGINE_NAME, engine),
                f"[{color}]{cat}[/{color}]",
                details.get(ia.ATTR_RESULTS_RESULT, "N/A"),
                details.get(ia.ATTR_RESULTS_METHOD, "N/A"),
            )
        console.print(res_table)

    # --- Votes ---
    votes = attrs.get(ia.ATTR_TOTAL_VOTES, {})
    if votes:
        vt = Table(title="Community Votes")
        vt.add_column("[green]Harmless[/green]", justify="center")
        vt.add_column("[red]Malicious[/red]", justify="center")
        vt.add_row(str(votes.get("harmless", 0)), str(votes.get("malicious", 0)))
        console.print(vt)
        console.print()

    # --- Tags ---
    tags = attrs.get(ia.ATTR_TAGS, [])
    if tags:
        console.print(f"[bold]Tags:[/] [cyan]{', '.join(tags)}[/cyan]")

    # --- JARM Fingerprint ---
    jarm = attrs.get(ia.ATTR_JARM, None)
    if jarm:
        console.print(f"[bold cyan]JARM Fingerprint:[/] [magenta]{jarm}[/magenta]")

    # --- Whois Info ---
    whois_info = attrs.get(ia.ATTR_WHOIS, "N/A")
    whois_date = fmt_time(attrs.get(ia.ATTR_WHOIS_DATE))
    if whois_info:
        whois_table = Table(title="Whois Information")
        whois_table.add_column("Field", justify="left")
        whois_table.add_column("Value", justify="left")
        whois_table.add_row("Whois Raw", whois_info)
        whois_table.add_row("Last Whois Update", f"[dim]{whois_date}[/dim]")
        console.print(whois_table)

    # --- Last HTTPS Certificate Info ---
    last_https = attrs.get(ia.ATTR_LAST_HTTPS_CERT, {}) or {}
    if last_https:
        ssl_table = Table(title="Last HTTPS Certificate Info")
        ssl_table.add_column("Field", justify="left")
        ssl_table.add_column("Value", justify="left")

        # Subject CN (prefer CN field, else stringify)
        subject = last_https.get(ia.LAST_HTTPS_SUBJECT, {})
        subject_cn = subject.get(ia.LAST_HTTPS_CN) if isinstance(subject, dict) else None
        subject_display = subject_cn or (str(subject) if subject else "N/A")
        ssl_table.add_row("Subject CN", subject_display)

        # Issuer CN
        issuer = last_https.get(ia.LAST_HTTPS_ISSUER, {})
        issuer_cn = issuer.get(ia.LAST_HTTPS_CN) if isinstance(issuer, dict) else None
        issuer_display = issuer_cn or (str(issuer) if issuer else "N/A")
        ssl_table.add_row("Issuer CN", issuer_display)

        # Validity (these are usually human-readable strings in VT JSON)
        validity = last_https.get(ia.LAST_HTTPS_VALIDITY, {}) or {}
        not_before = validity.get("not_before") or last_https.get("validity_not_before") or "N/A"
        not_after = validity.get("not_after") or last_https.get("validity_not_after") or "N/A"
        ssl_table.add_row("Validity (Not Before)", str(not_before))
        ssl_table.add_row("Validity (Not After)", str(not_after))

        # Thumbprints / serial / size
        ssl_table.add_row("Thumbprint (SHA256)", last_https.get(ia.LAST_HTTPS_THMB_SHA256, "N/A"))
        ssl_table.add_row("Thumbprint", last_https.get(ia.LAST_HTTPS_THMB, "N/A"))
        ssl_table.add_row("Serial Number", last_https.get(ia.LAST_HTTPS_SN, "N/A"))
        ssl_table.add_row("Certificate Size (bytes)", str(last_https.get(ia.LAST_HTTPS_CERT_SIZE, "N/A")))

        # Public key info (algorithm, curve, pub value truncated)
        pubkey = last_https.get(ia.LAST_HTTPS_PK, {}) or {}
        pub_alg = pubkey.get(ia.LAST_HTTPS_PK_ALGO) or ""
        pub_ec = pubkey.get(ia.LAST_HTTPS_PK_EC) or {}
        pub_curve = pub_ec.get(ia.LAST_HTTPS_EC_OID) or ""
        pub_raw = pub_ec.get(ia.LAST_HTTPS_EC_PUB) or ""
        ssl_table.add_row("Public Key Algorithm", pub_alg or "N/A")
        if pub_curve:
            ssl_table.add_row("Public Key Curve (OID)", pub_curve)
        ssl_table.add_row("Public Key (truncated)", pub_raw or "N/A")

        # Signature info
        cert_sig = last_https.get(ia.LAST_HTTPS_CERT_SIG, {}) or {}
        sig_alg = cert_sig.get(ia.LAST_HTTPS_CERT_SIG_ALGO) or "N/A"
        ssl_table.add_row("Signature Algorithm", sig_alg)

        # Common extensions (SANs, EKU, CA flag)
        extensions = last_https.get(ia.LAST_HTTPS_EXT, {}) or {}
        san = extensions.get(ia.LAST_HTTPS_EXT_SAN) or []
        eku = extensions.get(ia.LAST_HTTPS_EXT_EKU) or []
        ca_flag = extensions.get(ia.LAST_HTTPS_EXT_CA, None)
        san_str = ", ".join(san) if isinstance(san, (list, tuple)) and san else (str(san) if san else "N/A")
        eku_str = ", ".join(eku) if isinstance(eku, (list, tuple)) and eku else (str(eku) if eku else "N/A")
        ca_str = str(ca_flag) if ca_flag is not None else "N/A"

        ssl_table.add_row("Subject Alternative Names", san_str)
        ssl_table.add_row("Extended Key Usage", eku_str)
        ssl_table.add_row("Is CA?", ca_str)
        ca_info = extensions.get(ia.LAST_HTTPS_EXT_CA_INFO, {}) or {}
        if ca_info:
            for key, val in ca_info.items():
                ssl_table.add_row(f"CA Info ({key})", val)

        console.print(ssl_table)

    console.rule("[bold green]End of IP Report")
