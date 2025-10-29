from rich.console import Console
from rich.table import Table
from datetime import datetime, timezone
from data.api_constants import DomainAnalysis as da, Response as r

console = Console()

def _fmt_time(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"
    
def _flatten_domain_entities(entities, parent_roles=None):
    flat_list = []
    for e in entities:
        roles = e.get("roles", [])
        if parent_roles:
            roles = parent_roles + roles
        roles_str = ", ".join(roles) if roles else "N/A"

        # Extract multiple values from vcard_array
        fn_list, email_list, tel_list, org_list, adr_list = [], [], [], [], []
        for v in e.get("vcard_array", []):
            name = v.get("name")
            values = v.get("values", [])
            if not values:
                continue
            if name == "fn":
                fn_list.extend(values)
            elif name == "email":
                email_list.extend(values)
            elif name == "tel":
                tel_list.extend(values)
            elif name == "org":
                org_list.extend(values)
            elif name == "adr":
                adr_label = v.get("parameters", {}).get("label")
                if adr_label:
                    adr_list.extend(adr_label)
                else:
                    adr_list.append(", ".join(v if v!="" else "?" for v in values))

        flat_list.append({
            "roles": roles_str,
            "fn": ", ".join(fn_list) if fn_list else "N/A",
            "org": ", ".join(org_list) if org_list else "N/A",
            "email": ", ".join(email_list) if email_list else "N/A",
            "tel": ", ".join(tel_list) if tel_list else "N/A",
            "adr": "; ".join(adr_list) if adr_list else "N/A"
        })

        # recursively process nested entities
        nested = e.get("entities", [])
        if nested:
            flat_list.extend(_flatten_domain_entities(nested, roles))

    return flat_list

def print_domain_details(domain_data, json_output=False):
    if json_output:
        import json
        console.print_json(json.dumps(domain_data))
        return
    
    data = domain_data.get(da.DATA, {})
    attrs = data.get(da.ATTRIBUTES, {})
    domain_id = data.get(da.ID, "N/A")
    rdap_entities = attrs.get("rdap", {}).get("entities", [])

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
        console.print(f"  [bold]vt analysis domain {data.get(da.ID, '')}[/bold]")
        return

    console.rule(f"[bold cyan]Domain Analysis Report: [white]{domain_id}[/white]")

    # --- Basic Info ---
    info_table = Table(title="[bold cyan]Basic Information")
    info_table.add_column("Field", justify="left")
    info_table.add_column("Value", justify="left")

    # reputation colored magenta for visibility
    info_table.add_row("Reputation", f"[magenta]{str(attrs.get(da.ATTR_REPUTATION, 'N/A'))}[/magenta]")
    info_table.add_row("Creation Date", f"[dim]{_fmt_time(attrs.get(da.ATTR_CREATION_DATE))}[/dim]")
    info_table.add_row("Last Analysis", f"[dim]{_fmt_time(attrs.get(da.ATTR_LAST_ANALYSIS_DATE))}[/dim]")
    info_table.add_row("Last Modification", f"[dim]{_fmt_time(attrs.get(da.ATTR_LAST_MOD_DATE))}[/dim]")

    console.print(info_table)

    # --- Categories by Service ---
    categories = attrs.get(da.ATTR_CATEGORIES, {})
    if categories:
        cat_table = Table(title="Categorization Services")
        cat_table.add_column("Service", justify="left")
        cat_table.add_column("Category", justify="left")
        for svc, cat in categories.items():
            cat_table.add_row(svc, f"[bold magenta]{cat}[/bold magenta]")
        console.print(cat_table)

    # --- Last Analysis Stats ---
    stats = attrs.get(da.ATTR_LAST_STATS, {}) or attrs.get(da.ATTR_STATS, {})
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
            rank_table.add_row(name, str(rinfo.get("rank", "N/A")), _fmt_time(rinfo.get("timestamp")))
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
    whois_date = _fmt_time(attrs.get(da.ATTR_WHOIS_DATE))
    if registrar or whois_info:
        whois_table = Table(title="Whois Information")
        whois_table.add_column("Field", justify="left")
        whois_table.add_column("Value", justify="left")
        whois_table.add_row("Registrar", f"[bold]{registrar}[/bold]")
        whois_table.add_row("Last Whois Update", f"[dim]{whois_date}[/dim]")
        whois_table.add_row("Whois Raw", whois_info)
        console.print(whois_table)

    # --- Whois Extended Info (if any split fields exist) ---
    whois_details = attrs.get(da.ATTR_WHOIS_DETAILS, {})
    if whois_details:
        whois_ext_table = Table(title="Extended Whois Details")
        whois_ext_table.add_column("Field", justify="left")
        whois_ext_table.add_column("Value", justify="left")

        for k, v in whois_details.items():
            whois_ext_table.add_row(k, str(v))
        console.print(whois_ext_table)

    if rdap_entities:
        flat_entities = _flatten_domain_entities(rdap_entities)
        if flat_entities:
            ent_table = Table(title="RDAP Domain Entities / Contacts")
            ent_table.add_column("Roles", justify="center")
            ent_table.add_column("Name / Org", justify="left")
            ent_table.add_column("Email", justify="left")
            ent_table.add_column("Phone", justify="left")
            ent_table.add_column("Address", justify="left")

            for ent in flat_entities:
                ent_table.add_row(
                    ent["roles"],
                    f'{ent["fn"]} / {ent["org"]}',
                    ent["email"],
                    ent["tel"],
                    ent["adr"]
                )

            console.print(ent_table)

    # --- Votes ---
    votes = attrs.get(da.ATTR_VOTES, {})
    if votes:
        vt = Table(title="Community Votes")
        vt.add_column("[green]Harmless[/green]", justify="center")
        vt.add_column("[red]Malicious[/red]", justify="center")
        vt.add_row(str(votes.get("harmless", 0)), str(votes.get("malicious", 0)))
        console.print(vt)
        console.print()

    # --- Tags ---
    tags = attrs.get(da.ATTR_TAGS, [])
    if tags:
        console.print(f"[bold]Tags:[/] [cyan]{', '.join(tags)}[/cyan]")

    subdomains = attrs.get(da.ATTR_SUBDOMAINS, [])
    if subdomains:
        sub_table = Table(title="Known Subdomains")
        sub_table.add_column("Subdomain", justify="left")
        for sd in subdomains[:10]:  # limit to 10
            sub_table.add_row(sd)
        console.print(sub_table)

    # --- Resolutions (Domain → IP) ---
    resolutions = attrs.get(da.ATTR_RESOLUTIONS, [])
    if resolutions:
        res_table = Table(title="Domain Resolutions (Recent)")
        res_table.add_column("IP Address", justify="left")
        res_table.add_column("Last Resolved", justify="left")
        for res in resolutions[:10]:
            res_table.add_row(
                res.get("ip_address", "N/A"),
                _fmt_time(res.get("date"))
            )
        console.print(res_table)

    # --- JARM Fingerprint (TLS) ---
    jarm = attrs.get(da.ATTR_JARM, None)
    if jarm:
        console.print(f"[bold cyan]JARM Fingerprint:[/] [magenta]{jarm}[/magenta]")

    # --- SSL/TLS Certificate Chain Info ---
    last_https = attrs.get(da.ATTR_LAST_HTTPS_CERT, {}) or {}
    if last_https:
        ssl_table = Table(title="Last HTTPS Certificate Info")
        ssl_table.add_column("Field", justify="left")
        ssl_table.add_column("Value", justify="left")

        # Subject CN (prefer CN field, else stringify)
        subject = last_https.get(da.LAST_HTTPS_SUBJECT, {})
        subject_cn = subject.get(da.LAST_HTTPS_CN) if isinstance(subject, dict) else None
        subject_display = subject_cn or (str(subject) if subject else "N/A")
        ssl_table.add_row("Subject CN", subject_display)

        # Issuer CN
        issuer = last_https.get(da.LAST_HTTPS_ISSUER, {})
        issuer_cn = issuer.get(da.LAST_HTTPS_CN) if isinstance(issuer, dict) else None
        issuer_display = issuer_cn or (str(issuer) if issuer else "N/A")
        ssl_table.add_row("Issuer CN", issuer_display)

        # Validity (these are usually human-readable strings in VT JSON)
        validity = last_https.get(da.LAST_HTTPS_VALIDITY, {}) or {}
        not_before = validity.get("not_before") or last_https.get("validity_not_before") or "N/A"
        not_after = validity.get("not_after") or last_https.get("validity_not_after") or "N/A"
        ssl_table.add_row("Validity (Not Before)", str(not_before))
        ssl_table.add_row("Validity (Not After)", str(not_after))

        # Thumbprints / serial / size
        ssl_table.add_row("Thumbprint (SHA256)", last_https.get(da.LAST_HTTPS_THMB_SHA256, "N/A"))
        ssl_table.add_row("Thumbprint", last_https.get(da.LAST_HTTPS_THMB, "N/A"))
        ssl_table.add_row("Serial Number", last_https.get(da.LAST_HTTPS_SN, "N/A"))
        ssl_table.add_row("Certificate Size (bytes)", str(last_https.get(da.LAST_HTTPS_CERT_SIZE, "N/A")))

        # Public key info (algorithm, curve, pub value truncated)
        pubkey = last_https.get(da.LAST_HTTPS_PK, {}) or {}
        pub_alg = pubkey.get(da.LAST_HTTPS_PK_ALGO) or ""
        pub_ec = pubkey.get(da.LAST_HTTPS_PK_EC) or {}
        pub_curve = pub_ec.get(da.LAST_HTTPS_EC_OID) or ""
        pub_raw = pub_ec.get(da.LAST_HTTPS_EC_PUB) or ""
        ssl_table.add_row("Public Key Algorithm", pub_alg or "N/A")
        if pub_curve:
            ssl_table.add_row("Public Key Curve (OID)", pub_curve)
        ssl_table.add_row("Public Key (truncated)", pub_raw or "N/A")

        # Signature info
        cert_sig = last_https.get(da.LAST_HTTPS_CERT_SIG, {}) or {}
        sig_alg = cert_sig.get(da.LAST_HTTPS_CERT_SIG_ALGO) or "N/A"
        ssl_table.add_row("Signature Algorithm", sig_alg)

        # Common extensions (SANs, EKU, CA flag)
        extensions = last_https.get(da.LAST_HTTPS_EXT, {}) or {}
        san = extensions.get(da.LAST_HTTPS_EXT_SAN) or []
        eku = extensions.get(da.LAST_HTTPS_EXT_EKU) or []
        ca_flag = extensions.get(da.LAST_HTTPS_EXT_CA, None)
        san_str = ", ".join(san) if isinstance(san, (list, tuple)) and san else (str(san) if san else "N/A")
        eku_str = ", ".join(eku) if isinstance(eku, (list, tuple)) and eku else (str(eku) if eku else "N/A")
        ca_str = str(ca_flag) if ca_flag is not None else "N/A"

        ssl_table.add_row("Subject Alternative Names", san_str)
        ssl_table.add_row("Extended Key Usage", eku_str)
        ssl_table.add_row("Is CA?", ca_str)
        ca_info = extensions.get(da.LAST_HTTPS_EXT_CA_INFO, {}) or {}
        if ca_info:
            for key, val in ca_info.items():
                ssl_table.add_row(f"CA Info ({key})", val)

        console.print(ssl_table)

    # --- Last HTTPS Chain SHA256 (if exists) ---
    cert_sha256 = attrs.get(da.ATTR_LAST_HTTPS_CERT_SHA256, None)
    if cert_sha256:
        console.print(f"[bold]Certificate SHA256:[/] [dim]{cert_sha256}[/dim]")

    console.rule("[bold green]End of Domain Report")
