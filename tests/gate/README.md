Test-only keys for the unlock-gate VM tests. They protect nothing and MUST
NOT be used outside tests.

- `approver`, `approver.pub`: plain ed25519 approver key (the tests set
  `requireSecurityKey = false`).
- `agent.key`, `agent.pub`: the client's Ed25519 agent seed and public key.
