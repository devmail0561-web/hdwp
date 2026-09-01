# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(
    name="hdwp",
    help="HDWP Engine -- Hypothesis-Driven Web Pentesting Engine",
    invoke_without_command=True,
)
console = Console()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        from hdwp.tui.app import HDWPApp

        HDWPApp().run()


@app.command()
def run(
    context: Annotated[
        Path | None,
        typer.Option(
            "--context",
            "-c",
            help="Fichier hdwp-context.yaml (optionnel si --target fourni)",
        ),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            "-t",
            help="URL cible directe (cree un contexte minimal automatiquement)",
        ),
    ] = None,
    db_url: Annotated[
        str | None,
        typer.Option("--db", help="Evidence store URL"),
    ] = None,
    no_tui: Annotated[
        bool,
        typer.Option("--no-tui", hidden=True, help="Run without TUI (CI/debug mode)"),
    ] = False,
) -> None:
    """Lancer le moteur HDWP (TUI interactif).

    Usages :

      hdwp run --target https://example.com        (zero config)
      hdwp run --context mon-pentest.yaml           (config complete)
    """
    if target and not context:
        context = _create_minimal_context(target)

    if no_tui:
        if context is None:
            console.print("[red]--context ou --target requis[/red]")
            raise typer.Exit(1)
        import hdwp as _hdwp
        from hdwp.core.engine import HDWPEngine

        console.print(
            f"[bold]HDWP Engine v{_hdwp.__version__}[/bold]  context={context}"
        )

        async def _run_headless() -> None:
            async with await HDWPEngine.create(context, db_url=db_url) as engine:
                findings = await engine.run()
            if not findings:
                console.print("[green]Aucun finding confirme.[/green]")
                return
            table = Table(title=f"Findings ({len(findings)})")
            table.add_column("ID", style="cyan")
            table.add_column("Sev.")
            table.add_column("OWASP")
            table.add_column("Conf.")
            for f in findings:
                table.add_row(
                    f.id, f.severity, f.owasp_category, f"{f.confidence:.0%}"
                )
            console.print(table)

        asyncio.run(_run_headless())
        return

    # Default: TUI interactif avec auto_start si --target
    from hdwp.tui.app import HDWPApp

    HDWPApp(
        context_path=context,
        db_url=db_url,
        auto_start_url=target,
    ).run()


def _create_minimal_context(target_url: str) -> Path:
    """Cree un hdwp-context.yaml minimal depuis une URL cible."""
    from hdwp.core.paths import build_context_from_url

    path = build_context_from_url(target_url)
    console.print(f"[dim]Contexte minimal cree : {path}[/dim]")
    return path


@app.command()
def model(
    context: Annotated[
        Path, typer.Option("--context", "-c", help="Path to hdwp-context.yaml")
    ],
    export: Annotated[
        Path, typer.Option("--export", "-e", help="Export model to JSON file")
    ],
) -> None:
    """Crawler la cible et exporter le modele applicatif en JSON."""
    from hdwp.core.bus.event_bus import AsyncEventBus
    from hdwp.core.context.loader import ContextLoader
    from hdwp.core.context.scope_guard import ScopeGuard
    from hdwp.core.model.application_model import ApplicationModel
    from hdwp.core.observation.engine import ObservationEngine

    async def _export() -> None:
        ctx = ContextLoader.load(context)
        bus = AsyncEventBus()
        app_model = ApplicationModel(bus)
        scope_guard = ScopeGuard(ctx)
        obs_engine = ObservationEngine(bus, ctx, scope_guard)
        console.print(f"Crawl de {ctx.base_url}...")
        await obs_engine.start()
        await bus.drain()
        snapshot = app_model.snapshot()
        export.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
        console.print(
            f"[green]Modele exporte : {len(snapshot.endpoints)} endpoints, "
            f"{len(snapshot.parameters)} parametres -> {export}[/green]"
        )

    asyncio.run(_export())


@app.command()
def report(
    db: Annotated[str, typer.Option("--db", help="Evidence store URL")],
    format: Annotated[
        str, typer.Option("--format", "-f", help="md | json | har")
    ] = "md",
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Output path")
    ] = Path("report"),
) -> None:
    """Generer un rapport depuis l'evidence store."""
    from hdwp.core.bus.event_bus import AsyncEventBus
    from hdwp.core.report.engine import ReportEngine
    from hdwp.store.database import init_db
    from hdwp.store.repository import Repository

    async def _report() -> None:
        engine_db = await init_db(db)
        repository = Repository(engine_db)
        bus = AsyncEventBus()
        report_engine = ReportEngine(bus, repository)

        match format:
            case "md":
                out = output.with_suffix(".md")
                await report_engine.generate_markdown(out)
                console.print(f"[green]Rapport Markdown : {out}[/green]")
            case "json":
                summary = await report_engine.generate_json(output)
                console.print(
                    f"[green]Rapport JSON : {output}/ "
                    f"({summary['total']} finding(s))[/green]"
                )
            case "har":
                har_dir = output / "har"
                await report_engine.generate_har(har_dir)
                console.print(f"[green]Fichiers HAR : {har_dir}/[/green]")
            case _:
                console.print(
                    f"[red]Format inconnu : {format}. Utiliser : md, json, har[/red]"
                )
                raise typer.Exit(1)

    asyncio.run(_report())


@app.command()
def replay(
    experiment: Annotated[
        str, typer.Option("--experiment", "-e", help="Experiment ID to replay")
    ],
    db: Annotated[
        str, typer.Option("--db", help="Evidence store URL")
    ] = "sqlite+aiosqlite:///evidence_store.db",
) -> None:
    """Afficher les details d'une experience depuis l'evidence store."""
    from hdwp.store.database import init_db
    from hdwp.store.repository import Repository

    async def _replay() -> None:
        engine_db = await init_db(db)
        repo = Repository(engine_db)
        findings = await repo.list_findings()
        found = None
        for f in findings:
            if experiment in f.proof.get("experiments", []):
                found = f
                break

        if found is None:
            console.print(
                f"[red]Experience {experiment} introuvable dans les findings.[/red]"
            )
            raise typer.Exit(1)

        steps = "\n".join(found.proof.get("reproduction_steps", ["---"]))
        console.print(
            Panel(
                f"[bold]Experience[/bold] : {experiment}\n"
                f"[bold]Finding[/bold]   : {found.id} ({found.severity})\n"
                f"[bold]OWASP[/bold]     : {found.owasp_category} / {found.cwe_id}\n"
                f"[bold]Confiance[/bold] : {found.confidence:.0%}\n\n"
                f"{steps}",
                title="Replay",
            )
        )

    asyncio.run(_replay())


@app.command()
def plugin(
    action: Annotated[str, typer.Argument(help="list | enable | disable")],
    target: Annotated[str | None, typer.Argument(help="Plugin ID")] = None,
) -> None:
    """Gerer les plugins HDWP."""
    from hdwp.plugins.registry import PluginRegistry

    registry = PluginRegistry()
    registry.discover()

    match action:
        case "list":
            plugins = registry.list_all()
            if not plugins:
                console.print("[yellow]Aucun plugin decouvert.[/yellow]")
                return
            table = Table(title=f"Plugins ({len(plugins)})")
            table.add_column("ID", style="cyan")
            table.add_column("Nom")
            table.add_column("Categorie")
            table.add_column("OWASP")
            table.add_column("Version")
            for p in plugins:
                table.add_row(
                    p.id,
                    p.name,
                    p.category,
                    ", ".join(p.owasp_mapping),
                    p.version,
                )
            console.print(table)

        case "enable":
            if target is None:
                console.print("[red]Usage : hdwp plugin enable <plugin-id>[/red]")
                raise typer.Exit(1)
            ok = registry.enable(target)
            if ok:
                console.print(f"[green]{target} active[/green]")
            else:
                console.print(f"[red]{target} introuvable[/red]")
                raise typer.Exit(1)

        case "disable":
            if target is None:
                console.print("[red]Usage : hdwp plugin disable <plugin-id>[/red]")
                raise typer.Exit(1)
            registry.disable(target)
            console.print(f"[yellow]{target} désactivé[/yellow]")

        case _:
            console.print(
                f"[red]Action inconnue : {action}. Utiliser : list, enable, disable[/red]"
            )
            raise typer.Exit(1)


@app.command()
def knowledge(
    action: Annotated[str, typer.Argument(help="stats | reset")],
    db: Annotated[
        str | None, typer.Option("--db", help="Chemin vers knowledge.db")
    ] = None,
) -> None:
    """Consulter ou reinitialiser la base de connaissances adaptative."""
    from hdwp.core.knowledge.base import DEFAULT_KB_PATH, KnowledgeBase

    async def _run() -> None:
        kb = KnowledgeBase(db_path=db or DEFAULT_KB_PATH)

        match action:
            case "stats":
                stats = await kb.get_stats()
                sessions = await kb.get_session_count()
                console.print(
                    f"[bold]Base de connaissances[/bold] -- "
                    f"{sessions} session(s) enregistree(s)"
                )
                if not stats:
                    console.print(
                        "[yellow]Aucun pattern appris. "
                        "Lancez des pentests pour alimenter la base.[/yellow]"
                    )
                else:
                    table = Table(title="Patterns appris")
                    table.add_column("Propriete", style="cyan")
                    table.add_column("Mutation")
                    table.add_column("Confirmes", style="green")
                    table.add_column("Refutes", style="red")
                    table.add_column("Taux", style="bold")
                    table.add_column("Conf. moy.")
                    for s in stats:
                        rate = f"{s['confirmed_rate'] * 100:.0f}%"
                        table.add_row(
                            s["property_type"],
                            s["mutation_type"],
                            str(s["confirmed"]),
                            str(s["refuted"]),
                            rate,
                            f"{s['avg_confidence']:.2f}",
                        )
                    console.print(table)

            case "reset":
                await kb.reset()
                console.print(
                    "[green]Base de connaissances reinitialisee "
                    "(session_meta conserve).[/green]"
                )

            case _:
                console.print(
                    f"[red]Action inconnue : {action}. Utiliser : stats, reset[/red]"
                )
                raise typer.Exit(1)

        await kb.close()

    asyncio.run(_run())
