"""Orchestrator — the deterministic phase state machine.

The LLM PROPOSES actions; this code enforces scope/mode/rate gates the model
cannot override (prompt-injection defense, see docs/07-GUARDRAILS.md).

M1: BOLA/IDOR (mechanical, read-only, no LLM).
M2: LLM intent model + price/mass/workflow via Oracle 1 & 3.
M3: hardened Oracle (refuter panel, rerun, confidence) + benchmark.
M4: race/TOCTOU (parallel-fire), chain composition, RAG-lite knowledge.
State-changing classes are gated behind live mode + RoE authorization.
"""
from __future__ import annotations

from typing import Any

import httpx
from rich.console import Console

from ..config import Config
from ..llm.base import LLM
from ..llm.router import DEFAULT_PROFILE, LLMRouter
from .bola import build_bola_hypotheses
from .chain import Chainer
from .hypothesis import LLM_CLASSES, HypothesisEngine
from .intent_model import IntentModeler
from .knowledge import KnowledgeBase
from .models import Finding
from .oracle import Oracle
from .race import build_race_hypotheses
from .session_mgr import SessionManager

STATE_CHANGING = {"price_tamper", "workflow_bypass", "mass_assignment", "coupon_abuse", "race_condition"}


def _may_fire(cfg: Config, bug_class: str) -> bool:
    if bug_class not in STATE_CHANGING:
        return True                              # read-only (e.g. BOLA) — always safe
    if cfg.mode != "live":
        return False
    return "*" in cfg.destructive_allowed or bug_class in cfg.destructive_allowed


class Orchestrator:
    def __init__(
        self,
        cfg: Config,
        console: Console,
        transport: httpx.BaseTransport | None = None,
        llm: LLM | None = None,
        trace: Any | None = None,
        memory: Any | None = None,
        engagement: Any | None = None,
    ) -> None:
        self.cfg = cfg
        self.console = console
        self.transport = transport
        self.sessions = SessionManager(cfg, transport=transport)
        self.router = LLMRouter.single(llm) if llm is not None else self._build_router()
        self.oracle = Oracle(judge_llm=self.router.for_role("judge"),
                             refute_llm=self.router.for_role("refute"))
        self.kb = KnowledgeBase.load()
        self.trace = trace                            # optional TraceStore (audit + distil data)
        self.memory = memory                          # optional PatternMemory (self-improvement)
        self.engagement = engagement                  # optional EngagementStore (resumable checkpoint)

    def _skip_hint(self) -> str:
        """Explain WHY state-changing tests were skipped, based on the actual gate that blocked them."""
        if self.cfg.mode != "live":
            return "run with --mode live + RoE destructive_allowed to fire them"
        return 'add them to RoE destructive_allowed (e.g. ["*"]) to fire them — mode is already live'

    def _build_router(self) -> LLMRouter:
        # `--model auto` -> per-phase routing (Super/Nano/R1); else one model for all phases.
        if self.cfg.model == "auto":
            router = LLMRouter.from_profile({**DEFAULT_PROFILE, **(self.cfg.models or {})})
            if not router.any():
                self.console.print("[yellow]no LLM backends available[/] (auto profile); mechanical checks only.")
            return router
        from ..llm import get_backend
        try:
            return LLMRouter.single(get_backend(self.cfg.model))
        except Exception as e:
            self.console.print(f"[yellow]LLM backend unavailable[/] ({e}); running mechanical checks only.")
            return LLMRouter.empty()

    def _run_hyps(self, hyps: list[Finding], label: str) -> tuple[list[Finding], int, int]:
        """Gate + execute + verify a batch. Returns (confirmed, dropped, skipped)."""
        confirmed: list[Finding] = []
        dropped = skipped = 0
        for hyp in hyps:
            if not _may_fire(self.cfg, hyp.bug_class):
                skipped += 1
                continue
            for step in hyp.request_sequence:
                self.cfg.assert_in_scope(self.sessions.abs(step["url"]))
            v = self.oracle.verify(hyp, self.sessions.execute(hyp), reexec=self.sessions.execute)
            if self.trace is not None:
                self.trace.record_verdict(hyp, v)     # audit + distillation data
            if not (v.confirmed and v.finding) and self.cfg.iterate and hyp.bug_class in LLM_CLASSES:
                v = self._iterate(hyp, v)             # feedback loop: mutate the input + retry
            if v.confirmed and v.finding:
                confirmed.append(v.finding)
                if self.engagement is not None:
                    self.engagement.save_finding(v.finding)   # checkpoint immediately (survives Ctrl-C)
                self.console.print(f"  [red]CONFIRM[/] {v.finding.title}")
            else:
                dropped += 1
        return confirmed, dropped, skipped

    def _iterate(self, hyp: Finding, first: Any) -> Any:
        """On a failed logic test, mutate the input and retry up to cfg.iterate times.
        Returns the first confirming Verdict, else the original failed verdict."""
        from .mutate import mutations
        for variant in mutations(hyp, self.cfg.iterate):
            for step in variant.request_sequence:
                self.cfg.assert_in_scope(self.sessions.abs(step["url"]))   # scope-gate every retry
            v = self.oracle.verify(variant, self.sessions.execute(variant), reexec=self.sessions.execute)
            if self.trace is not None:
                self.trace.record_verdict(variant, v)
            if v.confirmed and v.finding:
                self.console.print(f"  [yellow]↻ mutated[/] input confirmed on retry: {variant.description}")
                return v
        return first

    def _mark_done(self, *classes: str) -> None:
        if self.engagement is not None:
            for cls in classes:
                self.engagement.mark_done(cls)

    def run(self) -> list[Finding]:
        c, cfg = self.console, self.cfg
        findings: list[Finding] = []
        dropped = 0
        model = None

        # Phase 1 — recon
        c.rule("[bold]Phase 1[/] recon — multi-role login + harvest + observe")
        self.sessions.login_all()
        for role, err in self.sessions.login_errors:
            c.print(f"  [yellow]login failed[/] {role}: {err}")
        if self.sessions.login_errors:
            c.print("  [dim]→ register these users in the target, or fix credentials in accounts.yaml[/]")
        c.print(f"  identities: {', '.join(self.sessions.roles())}")

        # Phase 1b — autonomous discovery (read-only): find endpoints + infer BOLA targets
        disc_endpoints: list[dict] = []
        if cfg.discovery.enabled:
            from .discovery import Discoverer
            c.rule("[bold]Phase 1b[/] discovery — endpoints + object inference")
            disc = Discoverer(self.sessions, cfg, console=c).discover()
            existing = {(o.list_url, o.item_url) for o in cfg.objects}
            new_objs = [o for o in disc.objects if (o.list_url, o.item_url) not in existing]
            cfg.objects = [*cfg.objects, *new_objs]
            disc_endpoints = disc.endpoints
            c.print(f"  {len(disc.spec_paths)} spec(s) · {disc.js_assets} JS · {disc.browser_reqs} XHR · "
                    f"crawled {disc.crawled} · probed {disc.probes} · {len(disc.endpoints)} endpoints · "
                    f"inferred {len(new_objs)} object(s): {', '.join(o.name for o in new_objs) or 'none'}")

        owned, observation = self.sessions.recon(cfg.objects)
        # login-response id harvest: owned ids the app hands the user at login (e.g. basket bid)
        if cfg.login_objects:
            from ..config import ObjectSpec
            login_owned = self.sessions.harvest_login_ids(cfg.login_objects)
            for spec in cfg.login_objects:
                owned[spec.name] = login_owned.get(spec.name, {})
                cfg.objects = [*cfg.objects, ObjectSpec(       # give BOLA the item_url to attack
                    name=spec.name, list_url=spec.item_url, item_url=spec.item_url, id_field="id")]
        for name, per_role in owned.items():
            summary = ", ".join(f"{r}={len(ids)}" for r, ids in per_role.items()) or "none"
            c.print(f"  harvested {name}: {summary}")
        # feed discovered endpoints the recon didn't sample into the intent model
        for ep in disc_endpoints:
            observation.endpoints.append({"method": ep["method"], "path": ep["path"],
                                          "role": "discovery", "status": None, "sample": ""})

        # Phase 3a — BOLA (mechanical, read-only)
        if "bola" in cfg.classes:
            c.rule("[bold]Phase 3a[/] hypotheses — BOLA/IDOR (mechanical)")
            bola_hyps = build_bola_hypotheses(cfg, owned)
            c.print(f"  queued {len(bola_hyps)} cross-session tests")
            conf, drop, _ = self._run_hyps(bola_hyps, "bola")
            findings += conf
            dropped += drop
            self._mark_done("bola")

        # Phase 3d — excessive data exposure (mechanical, read-only)
        if "excessive_data_exposure" in cfg.classes and cfg.objects:
            from .exposure import build_exposure_hypotheses
            c.rule("[bold]Phase 3d[/] hypotheses — excessive data exposure (mechanical)")
            ede_hyps = build_exposure_hypotheses(cfg)
            c.print(f"  queued {len(ede_hyps)} list-exposure checks")
            conf, drop, _ = self._run_hyps(ede_hyps, "exposure")
            findings += conf
            dropped += drop
            self._mark_done("excessive_data_exposure")

        # Phase 3e — broken function-level authorization (mechanical, read-only)
        if "bfla" in cfg.classes:
            from .bfla import build_bfla_hypotheses
            c.rule("[bold]Phase 3e[/] hypotheses — broken function-level auth (mechanical)")
            bfla_hyps = build_bfla_hypotheses(cfg, disc_endpoints)
            c.print(f"  queued {len(bfla_hyps)} admin-function checks")
            conf, drop, _ = self._run_hyps(bfla_hyps, "bfla")
            findings += conf
            dropped += drop
            self._mark_done("bfla")

        # Phase 2/3b — LLM classes (intent model -> hypotheses -> oracle)
        llm_classes = [k for k in cfg.classes if k in LLM_CLASSES]
        if self.router.any() and llm_classes:
            c.print(f"  [dim]models: {self.router.describe()}[/]")
            c.rule("[bold]Phase 2[/] intent model (LLM)")
            model = IntentModeler(self.router.for_role("intent")).build(observation)
            c.print(f"  {len(model.invariants)} invariants extracted")
            c.rule("[bold]Phase 3b[/] hypotheses — logic classes (LLM + knowledge)")
            hyps = HypothesisEngine(self.router.for_role("hypothesis"), self.kb, self.memory).generate(model, observation, llm_classes)
            c.print(f"  queued {len(hyps)} tests: {', '.join(sorted({h.bug_class for h in hyps})) or 'none'}")
            c.rule("[bold]Phase 4-5[/] execute + Oracle (assertion / state-delta)")
            conf, drop, skipped = self._run_hyps(hyps, "logic")
            findings += conf
            dropped += drop
            if skipped:
                c.print(f"  [yellow]skipped {skipped}[/] state-changing tests — {self._skip_hint()}")
            self._mark_done(*llm_classes)

        # Phase 3c — race / TOCTOU (mechanical, parallel-fire)
        if cfg.races and "race_condition" in cfg.classes:
            c.rule("[bold]Phase 3c[/] hypotheses — race / TOCTOU (parallel-fire)")
            race_hyps = build_race_hypotheses(cfg)
            c.print(f"  queued {len(race_hyps)} race tests")
            conf, drop, skipped = self._run_hyps(race_hyps, "race")
            findings += conf
            dropped += drop
            if skipped:
                c.print(f"  [yellow]skipped {skipped}[/] race tests — {self._skip_hint()}")
            self._mark_done("race_condition")

        # Phase 6 — chain confirmed primitives into higher impact
        if cfg.chain and findings:
            c.rule("[bold]Phase 6[/] chaining — compose primitives")
            chains = Chainer(self.router.for_role("chain")).chain(findings, model)
            for ch in chains:
                findings.append(ch)
                c.print(f"  [magenta]CHAIN[/] {ch.title} ({ch.severity.value})")

        # M5 — remember what worked so the next run starts smarter
        if self.memory is not None:
            added = self.memory.learn(findings)
            if added:
                c.print(f"  [cyan]learned {added} new patterns[/] for future engagements")

        if self.engagement is not None:
            self.engagement.mark_complete()

        c.rule(f"[bold green]{len(findings)} confirmed[/] · {dropped} dropped (false positives)")
        self.sessions.close()
        return findings
