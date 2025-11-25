import os, shutil, platform
from data.api_constants import Paths
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

class UninstallHandler:
    def __init__(self):
        self._config_path = os.path.dirname(Paths.CONFIG_PATH)
        self._shim_path = Paths.SHIM_PATH
        self._venv_dir = Paths.VENV_DIR
        self._failures = []

    def uninstall(self):
        print("[*] Uninstalling VirusTotal-CLI...")
        if os.path.exists(self._config_path):
            try:
                shutil.rmtree(self._config_path, ignore_errors=False)
                print(f"[+] Removed config: {self._config_path}")
            except Exception as e: 
                self._failures.append(("Config Directory", self._config_path, str(e)))
        else:
            print("[-] Couldn't remove config Path. Did you setup your API key ?")

        if os.path.exists(self._shim_path):
            try:
                os.remove(self._shim_path)
                print(f"[+] Removed {platform.system()} global command: vt")
            except Exception as e: 
                self._failures.append(("Global command File", self._shim_path, str(e)))

        if os.path.exists(self._venv_dir):
            try:
                shutil.rmtree(self._venv_dir, ignore_errors=False)
                print(f"[+] Removed {platform.system()} venv: {self._venv_dir}")
            except Exception as e:
                self._failures.append(("Venv Directory", self._venv_dir, str(e)))
        
        self._print_summary()

    def _print_summary(self):
        print("\n==============================")
        print("   UNINSTALL SUMMARY")
        print("==============================")

        if not self._failures:
            console.print(
                Panel.fit(
                    "[bold green]Uninstallation COMPLETED successfully![/bold green]",
                    title="[bold green]Success[/bold green]",
                    border_style="green",
                )
            )
            return

        console.print(
            Panel.fit(
                "[bold red]Some components could not be removed[/bold red]",
                title="[bold red]Uninstall Summary[/bold red]",
                border_style="red",
            )
        )

        table = Table(
            title="Failed Removals",
            show_header=True,
            header_style="bold red",
            border_style="bright_red",
        )

        table.add_column("Component", style="yellow", no_wrap=True)
        table.add_column("Path", style="cyan")
        table.add_column("Error", style="red")

        for name, path, error in self._failures:
            table.add_row(
                f"[bold yellow]{name}[/bold yellow]",
                f"[cyan]{path}[/cyan]",
                f"[red]{error}[/red]",
            )

        console.print(table)

        # Manual instructions panel
        instructions = Text()
        instructions.append("Please delete the files/directories manually.\n\n", style="bold white")

        instructions.append("• Close all terminals or apps using those files.\n", style="bright_white")
        instructions.append("• On Windows: run the uninstall as Administrator.\n", style="bright_white")
        instructions.append("• If deletion still fails: restart your system.\n", style="bright_white")

        console.print(
            Panel(
                instructions,
                title="[bold yellow]Manual Removal Instructions[/bold yellow]",
                border_style="yellow",
            )
        )

        console.print("[bold red][!] Uninstallation was NOT fully completed.[/bold red]\n")