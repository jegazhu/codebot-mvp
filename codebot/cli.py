import typer
from rich.console import Console
from codebot.auditor import run_full_audit

app = typer.Typer(help="CodeBot CLI Auditor")
console = Console()

@app.command()
def scan(
    target: str = typer.Argument(..., help="URL del repositorio público o ruta local"),
    min_confidence: float = typer.Option(0.60, help="Nivel de confianza mínimo (0.0 a 1.0)")
):
    console.print(f"[bold cyan]🛡️ Escaneando:[/] {target}")
    findings = run_full_audit(target, min_confidence=min_confidence)
    if not findings:
        console.print("[bold green]✅ SEGURO:[/] No se detectaron amenazas ni scripts sospechosos.")
        return
    for f in findings:
        console.print(f"[bold red]• [{f.severity}] {f.title}[/] ({f.location})")
        console.print(f"  → {f.recommendation}")

if __name__ == "__main__":
    app()
