# Flow Context Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow Core Engine flow rules to consume FlowTracker output directly.

**Architecture:** FlowTracker retains its bidirectional accounting fields and additionally emits a small matcher-facing `flow_context`. Core Engine treats that embedded object as its default while preserving the explicit `flow_context` argument for compatibility.

**Tech Stack:** Python 3.10+, existing standard-library data structures and current verifier scripts.

**Spec:** `docs/superpowers/specs/2026-11-02-flow-context-integration-design.md`

## Global Constraints

- Preserve BT1-BT2 output fields and behavior.
- Keep implementation and permanent regression test in separate commits.
- Add no dependency.

## Review Focus

- Normal TCP handshake must classify initiator packets as `to_server`.
- Reverse packets must classify as `to_client`.
- Midstream TCP and UDP must retain a deterministic first-sender fallback.
- Explicit Core Engine context must continue to override embedded context.
- Skipped or malformed events must not gain a misleading flow context.

---

### Task 1: Produce and consume normalized flow context

**Files:**
- Modify: `src/flow_tracker.py`
- Modify: `src/core_engine/core_engine.py`
- Test temporarily before implementation; commit the permanent regression test as Task 2.

**Interfaces:**
- Consumes: tracked normalized events and `CoreEngine.process_event(event, flow_context=None, application_data=None)`.
- Produces: `event["flow_context"]` containing `direction`, `state`, and `flow_id`.

- [x] Write and run a temporary failing integration test using a real three-packet handshake.
- [x] Track client/server roles without changing endpoint A/B accounting.
- [x] Attach normalized flow context after each state update.
- [x] Default Core Engine evaluation to the embedded context.
- [x] Run the temporary test, BT2 flow tests, all BT3 verifiers, lint, and syntax checks.
- [ ] Commit the implementation as one atomic change.
