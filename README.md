# abacus

An attribute-based access control runtime for agents.

## Goal

Abacus should provide:
- a configurable rules-based engine for agent guardrails
- auditable allow/escalate/deny decisions for evaluated actions
- a fast and portable runtime

## Why

Agents have permission control requirements similar to users, but with extra guardrails needed to avoid coerced behavior.

While using agents, you may want to provide access to:
- Tools (reproducible, pre-coded workflows/tools)
- Skills (re-used prompts that structure agent behavior)
- Filesystem
- Networks
- Secrets

In each case, agents shouldn't be allowed to use them without oversight.
Even in sandboxes, accessing secrets or executing code should safe and transparent.

Abacus aims to provide the configurable control plane for agents at these critical access junctures.
