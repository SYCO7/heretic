"""Core engine: orchestrator + the phase components.

Phase map (see docs/02-WORKFLOWS.md):
  1 recon        -> session_mgr
  2 intent model -> intent_model
  3 hypotheses   -> hypothesis
  4 execute      -> session_mgr (replay)
  5 verify       -> oracle          (THE MOAT)
  6 chain        -> chain
  7 report       -> ../report
"""
