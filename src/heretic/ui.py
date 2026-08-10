"""Interactive menu-driven UI for HERETIC — logo, colors, guided actions.

Launched by bare `heretic` (or `heretic menu`). Every action is wrapped so the
menu never crashes; it dispatches into the same core the CLI uses.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from . import __version__

# HERETIC in block glyphs
_LOGO = r"""
 ██   ██ ███████ ██████  ███████ ████████ ██  ██████
 ██   ██ ██      ██   ██ ██         ██    ██ ██
 ███████ █████   ██████  █████      ██    ██ ██
 ██   ██ ██      ██   ██ ██         ██    ██ ██
 ██   ██ ███████ ██   ██ ███████    ██    ██  ██████
"""

# "HERETIC" in ASCII binary
_BINARY = "01001000 01000101 01010010 01000101 01010100 01001001 01000011"

_MENU = [
    ("1", "Connect", "point HERETIC at your app — enter 2 users, it auto-detects login + scans (start here)"),
    ("2", "Auto", "guided one-shot on an existing profile: scan + chains → HTML report"),
    ("3", "Doctor", "preflight — API key(s) + target reachable?"),
    ("4", "Scan", "run a business-logic assessment on a target"),
    ("5", "Live-check", "run a profile + score precision/recall/FP vs ground truth"),
    ("6", "Benchmark", "offline self-test (no key, no target)"),
    ("7", "Export", "confirmed traces → fine-tune dataset (distil a private model)"),
    ("8", "Model", "pick / pull the AI model — hosted or local Ollama (auto-detected by default)"),
    ("9", "Keys", "configure API keys (.env, gitignored)"),
    ("0", "Quit", "stay heretical"),
]


def banner(console: Console) -> None:
    logo = Text(_LOGO, style="bold red")
    sub = Text()
    sub.append(_BINARY + "\n", style="dim red")
    sub.append("Business-Logic Vulnerability Agent", style="bold white")
    sub.append(f"   v{__version__}\n", style="dim")
    sub.append("author ", style="red")
    sub.append("SYCO7", style="bold white")
    sub.append("   ·   ", style="dim")
    sub.append("github ", style="red")
    sub.append("github.com/SYCO7", style="bold cyan")
    console.print(Panel(Group(Align.center(logo), Align.center(sub)),
                        border_style="red", padding=(1, 2)))


def _menu_panel(console: Console) -> None:
    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column(justify="right", style="bold red", no_wrap=True)
    t.add_column(style="bold white", no_wrap=True)
    t.add_column(style="dim")
    for key, name, desc in _MENU:
        t.add_row(key, name, desc)
    console.print(Panel(t, title="[bold red]menu[/]", border_style="red", padding=(0, 1)))


def run_menu(console: Console | None = None) -> None:
    console = console or Console()
    banner(console)
    try:
        from .llm.select import resolve
        console.print(f"  [dim]active model:[/] [green]{resolve(None)}[/] "
                      f"[dim](auto-detected · menu 7 to change/pull)[/]\n")
    except Exception:
        pass
    actions = {"1": _connect, "2": _auto, "3": _doctor, "4": _scan, "5": _livecheck,
               "6": _bench, "7": _export, "8": _models, "9": _keys}
    while True:
        _menu_panel(console)
        choice = Prompt.ask("[bold red]heretic[/]", choices=[k for k, _, _ in _MENU], default="1")
        if choice == "0":
            console.print("[red]stay heretical.[/] 🔥")
            return
        try:
            actions[choice](console)
        except SystemExit:
            console.print("[red]refused[/] — scope/authorization gate blocked this (check RoE).")
        except KeyboardInterrupt:
            console.print("\n[dim]cancelled[/]")
        except Exception as e:
            console.print(f"[red]error:[/] {type(e).__name__}: {e}")
        console.print()


# ---- connect wizard: point HERETIC at any app in a couple of prompts ----

def run_connect(console: Console, *, run_after: bool = True) -> Path | None:
    """Guided onboarding: enter target + 2 users → auto-detect the login → write a ready
    profile. Handles OTP/MFA/SSO by letting the user paste a token instead of credentials."""
    from urllib.parse import urlparse

    from .core.login_detect import detect_login

    console.print(Panel("[bold]Connect HERETIC to your web app / API[/]\n"
                        "[dim]You'll need TWO accounts on the target (register them first). HERETIC logs in "
                        "as both and looks for bugs where one user reaches the other's data.[/]",
                        border_style="red"))
    url = Prompt.ask("[bold red]target URL[/] (e.g. https://app.example.com)").rstrip("/")
    host = urlparse(url).hostname or url
    profile = Path(Prompt.ask("save profile to", default=f"targets/{host.split('.')[0] or 'myapp'}"))

    idA = Prompt.ask("[bold]userA[/] email / username / phone")
    pwA = Prompt.ask("userA password", password=True)
    idB = Prompt.ask("[bold]userB[/] email / username / phone")
    pwB = Prompt.ask("userB password", password=True)

    console.print("[dim]detecting the login endpoint …[/]")
    spec = detect_login(url, idA, pwA)
    roles_yaml: list[str] = ["  - { name: guest, creds: null }"]
    login_yaml = ""

    if spec and not spec["otp_hint"]:
        idfield = next((f for f in spec["cred_fields"] if f != "password"), "email")
        console.print(f"[green]✓ login detected[/] {spec['method']} {spec['url']} "
                      f"· token at [cyan]{spec['token_field']}[/] · id field [cyan]{idfield}[/]")
        login_yaml = (f"login:\n  url:         \"{spec['url']}\"\n  method:      \"{spec['method']}\"\n"
                      f"  token_field: \"{spec['token_field']}\"\n"
                      f"  auth_header: \"Authorization: Bearer {{token}}\"\n\n")
        roles_yaml += [f'  - {{ name: userA, creds: {{ {idfield}: "{idA}", password: "{pwA}" }} }}',
                       f'  - {{ name: userB, creds: {{ {idfield}: "{idB}", password: "{pwB}" }} }}']
    else:
        console.print("[yellow]auto-login didn't return a token[/] (OTP / MFA / SSO apps work this way). "
                      "Log in to each account in your browser → DevTools → Network → any authed request → "
                      "copy the [bold]Authorization: Bearer <token>[/] value and paste it here.")
        tA = Prompt.ask("userA bearer token", password=True)
        tB = Prompt.ask("userB bearer token", password=True)
        roles_yaml += [f'  - {{ name: userA, token: "{tA}" }}',
                       f'  - {{ name: userB, token: "{tB}" }}']

    profile.mkdir(parents=True, exist_ok=True)
    (profile / "accounts.yaml").write_text(login_yaml + "roles:\n" + "\n".join(roles_yaml) + "\n")
    allow = sorted({host, "127.0.0.1", "localhost"})
    (profile / "roe.yaml").write_text(
        f'engagement:    "{host} assessment"\nauthorized_by: "you@example.com"\nsigned:        true\n\n'
        f"scope:\n  allow:   {allow}\n  exclude: []\n\n"
        "mode:         dry-run\nmax_rate_rps: 20\nmax_parallel: 5\nchain: true\n"
        "classes: [bola, excessive_data_exposure]\n")
    console.print(f"[green]profile written → {profile}[/] (accounts.yaml is gitignored)")

    if run_after and Confirm.ask("run the scan now?", default=True):
        run_auto(console, url=url, profile=profile)
    return profile


# ---- shared auto flow (used by `heretic auto` and menu option 1) ------

def run_auto(console: Console, *, url: str | None = None, profile=None,
             model: str = "auto-detect", report=None) -> None:
    """Preflight → full scan (every RoE class + chains) → HTML report, checkpointed."""
    import httpx

    from .config import load_config
    from .core.doctor import preflight
    from .core.engagement import EngagementStore
    from .core.orchestrator import Orchestrator
    from .llm.select import resolve as resolve_model
    from .report.render import render

    model = resolve_model(model)
    console.print(f"[dim]model:[/] [green]{model}[/] [dim](auto-detected — change in the Models menu)[/]")
    url = url or Prompt.ask("[bold red]target URL[/]", default="http://localhost:8888")
    profile = Path(profile or Prompt.ask("[bold red]profile dir[/] (roe.yaml + accounts.yaml)", default="targets/crapi"))
    report = Path(report or "heretic-report.html")
    roe, accounts = profile / "roe.yaml", profile / "accounts.yaml"
    if not accounts.exists() and (profile / "accounts.yaml.example").exists():
        console.print(f"[yellow]no {accounts}[/] — copy {profile/'accounts.yaml.example'} → accounts.yaml, fill real creds, retry.")
        return

    console.rule("[bold]preflight[/]")

    def probe(u: str) -> int:
        return httpx.get(u, timeout=5.0, follow_redirects=True).status_code

    for chk in preflight(model, url, probe=probe):
        console.print(f"{'[green]✓[/]' if chk['ok'] else '[yellow]○[/]'} {chk['name']} — {chk['detail']}")

    cfg = load_config(roe=roe, accounts=accounts, url=url, model=model, chain=True, discover=True)
    console.print(Panel(
        f"[bold]target[/] {cfg.url}   [bold]mode[/] {cfg.mode}   [bold]model[/] {cfg.model}\n"
        f"[bold]classes[/] {', '.join(cfg.classes)}",
        title="[bold red]engagement[/]", border_style="red"))
    eng = EngagementStore(profile / "engagement.db")
    eng.start(cfg, roe=roe, accounts=accounts)
    findings = Orchestrator(cfg, console=console, engagement=eng).run()
    eng.close()
    render(findings, fmt="table", html_path=report, console=console)
    console.print(f"\n[bold green]done.[/] {len(findings)} finding(s) · report → [cyan]{report}[/] · "
                  f"resume → heretic resume --engagement {profile/'engagement.db'}")


# ---- actions ----------------------------------------------------------

def _connect(console: Console) -> None:
    run_connect(console)


def _auto(console: Console) -> None:
    run_auto(console)


def _doctor(console: Console) -> None:
    import httpx

    from .core.doctor import preflight
    from .llm.select import resolve

    model = resolve(None)
    console.print(f"[dim]model:[/] [green]{model}[/]")
    url = Prompt.ask("target URL (blank to skip)", default="")

    def probe(u: str) -> int:
        return httpx.get(u, timeout=5.0, follow_redirects=True).status_code

    for c in preflight(model, url or None, probe=probe if url else None):
        mark = "[green]✓[/]" if c["ok"] else "[red]✗[/]"
        console.print(f"{mark} {c['name']} — {c['detail']}")


def _scan(console: Console) -> None:
    from .config import load_config
    from .core.orchestrator import Orchestrator
    from .llm.select import resolve
    from .report.render import render
    url = Prompt.ask("target URL")
    roe = Prompt.ask("RoE yaml", default="targets/crapi/roe.yaml")
    accounts = Prompt.ask("accounts yaml", default="targets/crapi/accounts.yaml")
    model = resolve(None)
    console.print(f"[dim]model:[/] [green]{model}[/]")
    chain = Confirm.ask("compose chains?", default=True)

    cfg = load_config(roe=Path(roe), accounts=Path(accounts), url=url, model=model,
                      chain=(True if chain else None))
    findings = Orchestrator(cfg, console=console).run()
    render(findings, fmt="table", console=console)
    if findings and Confirm.ask("write HTML report?", default=True):
        out = Prompt.ask("report path", default="report.html")
        render(findings, fmt="table", html_path=Path(out), console=console)


def _livecheck(console: Console) -> None:
    from .core.benchmark import scoreboard
    from .core.livecheck import run_profile
    from .llm.select import resolve
    profile = Prompt.ask("profile dir", default="targets/crapi")
    url = Prompt.ask("target URL", default="http://localhost:8888")
    model = resolve(None)
    console.print(f"[dim]model:[/] [green]{model}[/]")
    _findings, m = run_profile(profile, url, model, console=console)
    console.print(scoreboard(m))
    if m.fps:
        console.print(f"[red]false positives:[/] {', '.join(m.fps)}")
    if m.missed:
        console.print(f"[yellow]missed:[/] {', '.join(g['match'] for g in m.missed)}")


def _bench(console: Console) -> None:
    from .benchmark import run_builtin
    from .core.benchmark import score, scoreboard

    findings, gt = run_builtin(console=console)
    console.print(scoreboard(score(findings, gt)))


def _export(console: Console) -> None:
    from .core.dataset import build_finetune_examples, to_chat, to_jsonl
    from .core.trace import TraceStore

    trace = Prompt.ask("trace jsonl (from scan --log)", default="run.jsonl")
    out = Prompt.ask("output dataset", default="data.jsonl")
    fmt = Prompt.ask("format", choices=["alpaca", "chat"], default="chat")
    ex = build_finetune_examples(TraceStore.load(trace).records)
    Path(out).write_text("\n".join(json.dumps(c) for c in to_chat(ex)) if fmt == "chat" else to_jsonl(ex))
    console.print(f"[green]wrote {len(ex)} fine-tune examples[/] → {out}")


def _save_env_var(key: str, value: str) -> None:
    """Upsert a single KEY=value into ./.env (gitignored) and the live environment."""
    p = Path(".env")
    kv: dict[str, str] = {}
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()
    kv[key] = value
    p.write_text("# HERETIC config — gitignored, DO NOT COMMIT. Rotate keys if exposed.\n"
                 + "\n".join(f"{k}={v}" for k, v in kv.items()) + "\n")
    os.environ[key] = value


def _models(console: Console) -> None:
    from .llm.select import available, best_available, ollama_pull, ollama_running

    rows = available()
    active = os.environ.get("HERETIC_MODEL") or best_available()
    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column(justify="right", style="bold red")
    t.add_column(style="bold white")
    t.add_column(style="dim")
    pick: dict[str, str] = {}
    for i, row in enumerate(rows, 1):
        pick[str(i)] = row["id"]
        mark = "[green]✓[/]" if row["ready"] else "[dim]○[/]"
        star = " [green](active)[/]" if row["id"] == active else ""
        note = f"  [dim]{row['note']}[/]" if row["note"] else ""
        t.add_row(str(i), f"{mark} {row['label']}{star}", note)
    console.print(Panel(t, title="[bold red]models[/]  ·  auto-detected best is used unless you pick one",
                        border_style="red", padding=(0, 1)))
    console.print("[dim]P[/] pull a local Ollama model (e.g. a bigger one)   ·   [dim]Enter[/] keep auto")

    choice = Prompt.ask("[bold red]pick #[/] (or P to pull)", default="").strip().lower()
    if choice == "p":
        if not ollama_running():
            console.print("[yellow]Ollama isn't running.[/] Start it: [bold]ollama serve[/]")
            return
        name = Prompt.ask("model to pull (bigger = better for logic)",
                          default="qwen2.5:7b")
        console.print(f"[dim]pulling {name} … (this can take a while)[/]")
        console.print("[green]pulled.[/]" if ollama_pull(name) else "[red]pull failed[/] — check the name / `ollama` CLI")
        return
    if choice in pick:
        chosen = pick[choice]
        _save_env_var("HERETIC_MODEL", chosen)
        console.print(f"[green]default model set → {chosen}[/]  (saved to .env)")


def _keys(console: Console) -> None:
    console.print("[dim]enter keys (blank = keep/skip). saved to .env, gitignored.[/]")
    p = Path(".env")
    kv: dict[str, str] = {}
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()
    for key in ("NVIDIA_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY"):
        have = "  [green](set)[/]" if kv.get(key) else ""
        val = Prompt.ask(f"{key}{have}", default="", password=True)
        if val:
            kv[key] = val
    p.write_text("# HERETIC secrets — gitignored, DO NOT COMMIT. Rotate if exposed.\n"
                 + "\n".join(f"{k}={v}" for k, v in kv.items()) + "\n")
    for k, v in kv.items():
        os.environ[k] = v
    console.print("[green].env saved + loaded.[/] rotate keys after use if they were shared.")
