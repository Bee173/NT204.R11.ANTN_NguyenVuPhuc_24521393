# Flow Context Integration Design

## Intent

Make BT3 consume flow direction and state produced by BT2 without requiring callers to translate `forward`/`backward` into `to_server`/`to_client` manually.

## Scope

- Preserve the existing BT2 `direction` field and all endpoint/statistics behavior.
- Record client/server roles from the TCP initiator; use the first sender as the fallback for midstream TCP and UDP flows.
- Attach a normalized `flow_context` object to every tracked event.
- Let `CoreEngine.process_event()` use `event["flow_context"]` when no explicit context is supplied.

## Non-goals

- Do not change Snort rule parsing or matching semantics.
- Do not add the permanent regression test in this commit; that is the next independently committed task.
- Do not replace the existing endpoint A/B or forward/backward accounting model.

## Approaches

1. Infer server solely from port numbers. Rejected because non-standard application ports are supported and port heuristics can reverse roles.
2. Translate `forward` directly to `to_server`. Rejected because endpoint A is lexicographically sorted and is not necessarily the client.
3. Track the flow initiator and expose a dedicated matcher context. Selected because it preserves existing output while giving BT3 an explicit contract.
