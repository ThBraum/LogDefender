from pathlib import Path

import typer

from logdefender.analyze import run_analysis

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    pass


@app.command("analyze")
def analyze(
    input_path: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(Path("out"), "--out", "-o"),
):
    result = run_analysis(input_path=input_path, out_dir=out)
    print(f"Events: {len(result.events)}")
    print(f"Alerts: {len(result.alerts)}")
    print(f"Wrote: {result.alerts_path}")
    print(f"Wrote: {result.report_path}")
