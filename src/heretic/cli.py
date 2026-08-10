"""HERETIC CLI — `heretic scan -u TARGET --roe roe.yaml --accounts accounts.yaml`.

This is the operator-facing entrypoint. It loads + validates config (which
enforces the authorization gate), then hands off to the orchestrator.

Skeleton status: wires up commands and the live view; phase logic is stubbed
in core/ modules with TODOs. Run `heretic --help`.
"""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from . import __version__

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,          # bare `heretic` launches the interactive menu
    help="HERETIC — find business-logic bugs your scanner can't.",
)
console = Console()

CLASSES = [
    "bola", "bfla", "excessive_data_exposure", "price_tamper", "workflow_bypass",
    "mass_assignment", "coupon_abuse", "race_condition", "auth_flow",
]


def _load_dotenv(path: str = ".env") -> None:
    """Load KEY=VALUE lines from ./.env into the environment (does not overwrite
    already-set vars). So pasted API keys 'just work' without manual export."""
    import os

    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


@app.callback(invoke_without_command=True)
def _main(ctx: typer.Context) -> None:
    """HERETIC — find business-logic bugs your scanner can't."""
    _load_dotenv()          # runs before every command
    if ctx.invoked_subcommand is None:      # bare `heretic` → interactive menu
        from .ui import run_menu
        run_menu(console)
        raise typer.Exit()


@app.command()
def menu() -> None:
    """Launch the interactive menu (logo + guided actions)."""
    from .ui import run_menu
    run_menu(console)


@app.command()
def version() -> None:
    """Print version."""
    console.print(f"HERETIC v{__version__}")


@app.command()
def connect() -> None:
    """Guided setup: point HERETIC at your app — enter two users, it auto-detects the login
    (handles OTP/MFA via a pasted token), writes the profile, and scans. The easy on-ramp."""
    from .ui import run_connect
    run_connect(console)


_ROE_TEMPLATE = """\
engagement:    "my lab engagement"
authorized_by: "you@example.com"
signed:        true
scope:
  allow:   ["*.local", "127.0.0.1", "10.0.0.0/8"]
  exclude: ["*/admin/delete*"]
mode:          dry-run
max_rate_rps:  5
max_parallel:  3
destructive_allowed: []
classes: [bola]
# Objects to harvest ids from + test for BOLA:
objects:
  - name:      order
    list_url:  "/api/orders"          # role fetches its OWN orders (harvest ids)
    item_url:  "/api/orders/{id}"     # cross-role BOLA test
    id_field:  "id"
    # list_path: "data"               # uncomment if the array is nested
"""

_ACCOUNTS_TEMPLATE = """\
login:
  url:         "/api/auth/login"
  method:      "POST"
  token_field: "token"                       # or "cookie:session", or dotted "data.token"
  auth_header: "Authorization: Bearer {token}"
roles:
  - { name: guest, creds: null }
  - { name: userA, creds: { email: "userA@test.local", password: "TestPass123!" } }
  - { name: userB, creds: { email: "userB@test.local", password: "TestPass123!" } }
  - { name: admin, creds: { email: "admin@test.local", password: "AdminPass123!" } }
"""


@app.command()
def init() -> None:
    """Scaffold roe.yaml + accounts.yaml in the current directory."""
    for name, content in (("roe.yaml", _ROE_TEMPLATE), ("accounts.yaml", _ACCOUNTS_TEMPLATE)):
        p = Path(name)
        if p.exists():
            console.print(f"[yellow]skip[/] {name} (already exists)")
            continue
        p.write_text(content)
        console.print(f"[green]wrote[/] {name}")
    console.print("Edit both, then: [bold]heretic scan -u <target> --roe roe.yaml --accounts accounts.yaml[/]")


@app.command()
def auto(
    url: str | None = typer.Option(None, "-u", "--url", help="Target base URL (you'll be prompted if omitted)."),
    profile: Path | None = typer.Option(None, "--profile", help="Profile dir with roe.yaml + accounts.yaml (prompted if omitted)."),
    model: str = typer.Option("auto-detect", "--model", help="Backend id; default auto-detects the best available."),
    report: Path = typer.Option(Path("heretic-report.html"), "--report", help="HTML report path."),
) -> None:
    """One command, fully guided: preflight → scan (every class + chains) → HTML report.

    The zero-friction path for operators: point it at a target profile and it runs the
    whole assessment end to end, no other flags needed."""
    from .ui import run_auto
    run_auto(console, url=url, profile=profile, model=model, report=report)


@app.command()
def scan(
    url: str = typer.Option(..., "-u", "--url", help="Target base URL."),
    roe: Path = typer.Option(..., "--roe", help="Rules-of-engagement YAML (required)."),
    accounts: Path = typer.Option(..., "--accounts", help="Test-account YAML."),
    model: str = typer.Option(
        "auto-detect", "--model",
        help="Backend id. Default auto-detect picks the best available (hosted key or local Ollama). "
             "Explicit: nemotron-super | nemotron-nano | ollama:<model> | gemini-flash | groq | "
             "openrouter-r1 | auto (per-phase routing) | fake."),
    classes: str | None = typer.Option(
        None, "--classes", help=f"Comma list; default all. Options: {','.join(CLASSES)}"
    ),
    mode: str | None = typer.Option(None, "--mode", help="dry-run | live (overrides RoE)."),
    chain: bool = typer.Option(False, "--chain", help="Compose confirmed primitives into higher-impact chains."),
    log: Path | None = typer.Option(None, "--log", help="Append an engagement trace (JSONL) for audit + distillation."),
    memory: Path | None = typer.Option(None, "--memory", help="Pattern-memory JSONL: learn from + improve across runs."),
    save: Path | None = typer.Option(None, "--save", help="Checkpoint engagement to a SQLite file so it survives an interrupt and can be resumed."),
    iterate: int = typer.Option(0, "-i", "--iterate", help="Feedback loop: on a failed logic test, mutate the input and retry up to N times (0 = off)."),
    discover: bool | None = typer.Option(None, "--discover/--no-discover", help="Autonomously discover endpoints + infer BOLA targets (default: on when roe has no objects)."),
    brute: bool = typer.Option(False, "--brute", help="Also brute-force a path wordlist during discovery (noisy; needs --discover)."),
    browser: bool = typer.Option(False, "--browser", help="Headless-browser XHR capture during discovery (catches runtime-built URLs; needs playwright)."),
    report: Path | None = typer.Option(None, "--report", help="Write HTML report here."),
    output: str = typer.Option("table", "-o", "--output", help="table | json | md"),
) -> None:
    """Run a business-logic assessment against TARGET."""
    from .config import load_config  # local import keeps --help fast
    from .core.engagement import EngagementStore
    from .core.memory import PatternMemory
    from .core.orchestrator import Orchestrator
    from .core.trace import TraceStore
    from .llm.select import resolve as resolve_model

    model = resolve_model(model)     # auto-detect the best available backend
    # load_config enforces the authorization gate — raises + exits if RoE invalid/out-of-scope.
    cfg = load_config(roe=roe, accounts=accounts, url=url, model=model,
                      classes=classes.split(",") if classes else None, mode=mode,
                      chain=(True if chain else None), discover=discover)
    cfg.iterate = iterate
    if brute:
        cfg.discovery.enabled = True
        cfg.discovery.wordlist = True
    if browser:
        cfg.discovery.enabled = True
        cfg.discovery.browser = True

    console.print(Panel.fit(
        f"[bold]HERETIC v{__version__}[/]\n"
        f"target [cyan]{cfg.url}[/]  ·  mode [magenta]{cfg.mode}[/]  ·  model [green]{cfg.model}[/]\n"
        f"classes: {', '.join(cfg.classes)}",
        title="engagement", border_style="red",
    ))

    trace = TraceStore(log) if log else None
    mem = PatternMemory.load(memory) if memory else None
    eng = None
    if save:
        eng = EngagementStore(save)
        eng.start(cfg, roe=roe, accounts=accounts)
    orch = Orchestrator(cfg, console=console, trace=trace, memory=mem, engagement=eng)
    findings = orch.run()                    # drives phases 1..7 (see core/orchestrator.py)
    if eng:
        eng.close()
        console.print(f"  [dim]engagement saved → {save}  ·  resume: heretic resume --engagement {save}[/]")

    from .report.render import render
    render(findings, fmt=output, html_path=report, console=console)


@app.command()
def bench(
    threshold: float = typer.Option(0.10, "--threshold", help="Max allowed false-positive rate."),
) -> None:
    """Run the built-in offline benchmark (no network / no API key) and score
    precision / recall / FP. Exits non-zero if the FP-rate gate fails — wire it
    into CI to run every build."""
    from .benchmark import run_builtin
    from .core.benchmark import score, scoreboard

    findings, ground_truth = run_builtin(console=console)
    metrics = score(findings, ground_truth)
    console.print(scoreboard(metrics, threshold=threshold))
    if metrics.fps:
        console.print(f"[red]false positives:[/] {', '.join(metrics.fps)}")
    if metrics.missed:
        console.print(f"[yellow]missed:[/] {', '.join(g['match'] for g in metrics.missed)}")
    if metrics.fp_rate >= threshold:
        raise typer.Exit(code=1)


@app.command()
def doctor(
    model: str = typer.Option("auto-detect", "--model", help="Backend id; default auto-detects the best available."),
    url: str | None = typer.Option(None, "-u", "--url", help="Target base URL to reachability-check."),
) -> None:
    """Preflight: are the model key(s) set and the target reachable? Run before a live scan."""
    import httpx

    from .core.doctor import preflight
    from .llm.select import resolve as resolve_model

    model = resolve_model(model)

    def probe(u: str) -> int:
        return httpx.get(u, timeout=5.0, follow_redirects=True).status_code

    checks = preflight(model, url, probe=probe if url else None)
    for c in checks:
        mark = "[green]✓[/]" if c["ok"] else "[red]✗[/]"
        console.print(f"{mark} {c['name']} — {c['detail']}")
    if all(c["ok"] for c in checks):
        console.print("[green]ready.[/] run: heretic livecheck --profile <dir> -u <url> --model " + model)
    else:
        raise typer.Exit(code=1)


@app.command()
def livecheck(
    profile: Path = typer.Option(..., "--profile", help="Target profile dir (roe.yaml + accounts.yaml + ground_truth.yaml)."),
    url: str = typer.Option(..., "-u", "--url", help="Target base URL."),
    model: str = typer.Option("auto-detect", "--model", help="Backend id; default auto-detects the best available."),
    max_fp: float = typer.Option(0.10, "--max-fp", help="Fail if false-positive rate >= this."),
    min_recall: float = typer.Option(0.5, "--min-recall", help="Fail if recall < this."),
    report: Path | None = typer.Option(None, "--report", help="Write HTML report here."),
) -> None:
    """Run a target profile against a REAL target and score precision/recall/FP vs
    ground truth. This is the number that decides whether HERETIC actually works."""
    from .core.benchmark import scoreboard
    from .core.livecheck import run_profile
    from .llm.select import resolve as resolve_model
    from .report.render import render

    findings, m = run_profile(profile, url, resolve_model(model), console=console)
    console.print(scoreboard(m, threshold=max_fp))
    if m.fps:
        console.print(f"[red]false positives:[/] {', '.join(m.fps)}")
    if m.missed:
        console.print(f"[yellow]missed:[/] {', '.join(g['match'] for g in m.missed)}")
    if report:
        render(findings, fmt="table", html_path=report, console=console)
    if m.fp_rate >= max_fp or m.recall < min_recall:
        raise typer.Exit(code=1)


@app.command()
def export(
    trace: Path = typer.Option(..., "--trace", help="Engagement trace JSONL (from scan --log)."),
    out: Path = typer.Option(..., "--out", help="Output dataset JSONL."),
    fmt: str = typer.Option("alpaca", "--format", help="alpaca | chat"),
) -> None:
    """Turn CONFIRMED attack traces into a fine-tune dataset for distilling a
    private specialist model (see docs/04-LLM-BACKENDS.md)."""
    import json as _json

    from .core.dataset import build_finetune_examples, to_chat, to_jsonl
    from .core.trace import TraceStore

    ts = TraceStore.load(trace)
    examples = build_finetune_examples(ts.records)
    if fmt == "chat":
        out.write_text("\n".join(_json.dumps(c) for c in to_chat(examples)))
    else:
        out.write_text(to_jsonl(examples))
    console.print(f"[green]wrote[/] {len(examples)} fine-tune examples ({fmt}) -> {out}")


@app.command()
def resume(
    engagement: Path = typer.Option(..., "--engagement", help="Engagement .db to resume (from `scan --save`)."),
    report: Path | None = typer.Option(None, "--report", help="Write HTML report here."),
    output: str = typer.Option("table", "-o", "--output", help="table | json | md"),
) -> None:
    """Resume a saved engagement: reload confirmed findings, re-run any classes that
    hadn't finished, then re-chain over the merged set and report."""
    from .config import load_config
    from .core.chain import Chainer
    from .core.engagement import EngagementStore
    from .core.orchestrator import Orchestrator
    from .report.render import render

    if not engagement.exists():
        console.print(f"[red]no engagement file:[/] {engagement}")
        raise typer.Exit(code=2)

    store = EngagementStore(engagement)
    meta, saved, done = store.load()
    remaining = [c for c in meta["classes"] if c not in done]
    console.print(Panel.fit(
        f"[bold]resume[/] {engagement.name}\n"
        f"target [cyan]{meta['url']}[/]  ·  saved findings [green]{len(saved)}[/]  ·  "
        f"done: {', '.join(sorted(done)) or 'none'}\n"
        f"remaining classes: {', '.join(remaining) or 'none (engagement complete)'}",
        title="engagement", border_style="red",
    ))

    if remaining and not meta["completed"]:
        cfg = load_config(roe=Path(meta["roe"]), accounts=Path(meta["accounts"]),
                          url=meta["url"], model=meta["model"], classes=remaining,
                          mode=meta["mode"], chain=False)   # chain once at the end, over the merged set
        Orchestrator(cfg, console=console, engagement=store).run()   # saves new primitives + marks done

    # reload everything (saved + newly confirmed), then chain over the full primitive set
    _meta, findings, _done = store.load()
    if meta["chain"]:
        chains = Chainer(None).chain(findings, None)
        if chains:
            console.print(f"  [magenta]chained[/] {len(chains)} higher-impact finding(s) over {len(findings)} primitives")
        findings = findings + chains
    store.mark_complete()
    store.close()
    render(findings, fmt=output, html_path=report, console=console)


if __name__ == "__main__":
    app()
