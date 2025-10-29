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

def print_user_details(user_data, json_output=False):
    if json_output:
        import json
        console.print_json(json.dumps(user_data))
        return

    data = user_data.get("data", {})
    attrs = data.get("attributes", {})

    user_id = data.get("id", "N/A")
    console.rule(f"[bold cyan]User Profile: [white]{user_id}[/white]")

    # --- Basic Information ---
    basic = Table(title="[bold cyan]Basic Information")
    basic.add_column("Field", justify="left")
    basic.add_column("Value", justify="left")

    first_name = attrs.get("first_name", "")
    last_name = attrs.get("last_name", "")
    full_name = f"{first_name} {last_name}".strip() or "N/A"
    email = attrs.get("email", "N/A")
    status = attrs.get("status", "N/A")
    identity = attrs.get("identity_provider", "N/A")
    certified = "Yes" if attrs.get("certified") else "No"
    private = "Yes" if attrs.get("private") else "No"

    basic.add_row("Full Name", full_name)
    basic.add_row("Email", f"[cyan]{email}[/cyan]")
    basic.add_row("Identity Provider", identity)
    basic.add_row("Status", status.capitalize())
    basic.add_row("Certified", certified)
    basic.add_row("Private Account", private)
    basic.add_row("Reputation", f"[magenta]{attrs.get('reputation', 'N/A')}[/magenta]")
    basic.add_row("User Since", _fmt_time(attrs.get("user_since")))
    basic.add_row("Last Login", _fmt_time(attrs.get("last_login")))

    console.print(basic)

    # --- Account Security ---
    security = Table(title="[bold cyan]Account Security")
    security.add_column("Setting", justify="left")
    security.add_column("Value", justify="left")

    has_2fa = "Enabled" if attrs.get("has_2fa") else "Disabled"
    sso = "Enforced" if attrs.get("sso_enforced") else "Not Enforced"
    api_key = attrs.get("apikey", "")
    masked_key = api_key[:4] + "*" * (len(api_key) - 8) + api_key[-4:] if api_key else "N/A"

    security.add_row("Two-Factor Auth", has_2fa)
    security.add_row("SSO", sso)
    security.add_row("API Key", f"[dim]{masked_key}[/dim]")

    console.print(security)

    # --- Preferences / Activity ---
    prefs = attrs.get("preferences", {})
    ui_last_read = _fmt_time(
        prefs.get("ui", {}).get("last_read_notification_date")
    )
    graph_last_visit = _fmt_time(
        prefs.get("graph", {}).get("last_visit")
    )

    pref_table = Table(title="[bold cyan]Recent Activity & Preferences")
    pref_table.add_column("Field", justify="left")
    pref_table.add_column("Value", justify="left")

    pref_table.add_row("Last Notification Read", ui_last_read)
    pref_table.add_row("Last Graph Visit", graph_last_visit)

    console.print(pref_table)

    # --- Quotas ---
    quotas = attrs.get("quotas", {})
    if quotas:
        quota_table = Table(title="[bold cyan]Quota Usage")
        quota_table.add_column("Type", justify="left")
        quota_table.add_column("Used", justify="center")
        quota_table.add_column("Allowed", justify="center")

        # Define a few important quotas to display
        key_map = {
            "api_requests_hourly": "API Requests (Hourly)",
            "api_requests_daily": "API Requests (Daily)",
            "api_requests_monthly": "API Requests (Monthly)",
            "collections_creation_monthly": "Collections (Monthly)",
            "private_scans_monthly": "Private Scans (Monthly)",
            "private_urlscans_monthly": "Private URL Scans (Monthly)",
        }

        for key, label in key_map.items():
            q = quotas.get(key, {})
            used, allowed = q.get("used", 0), q.get("allowed", 0)
            if used or allowed:  # show only relevant quotas
                quota_table.add_row(label, str(used), str(allowed))

        console.print(quota_table)

    # --- Privileges ---
    privileges = attrs.get("privileges", {})
    granted = [k for k, v in privileges.items() if v.get("granted")]
    priv_table = Table(title="[bold cyan]Privileges")
    priv_table.add_column("Granted Privileges", justify="left")

    if granted:
        for p in granted:
            priv_table.add_row(f"[green]{p}[/green]")
    else:
        priv_table.add_row("[dim]No special privileges granted[/dim]")

    console.print(priv_table)

    # --- Internal IDs ---
    mand_uuid = attrs.get("mandiant_uuid", "N/A")
    collections_count = attrs.get("collections_count", 0)
    if mand_uuid or collections_count:
        misc_table = Table(title="[bold cyan]Miscellaneous")
        misc_table.add_column("Field", justify="left")
        misc_table.add_column("Value", justify="left")
        misc_table.add_row("Mandiant UUID", mand_uuid)
        misc_table.add_row("Collections Count", str(collections_count))
        console.print(misc_table)

    console.rule("[bold green]End of User Profile")
