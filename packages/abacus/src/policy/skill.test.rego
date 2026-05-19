package abacus.skill

import rego.v1

test_skill_candidates_match_skill_scope_only if {
  config := {
    "meta": {
      "schemaVersion": 1,
      "policyVersion": "skill-tests",
      "permissionModeEffect": "deny",
    },
    "rules": [
      {
        "id": "skill-research",
        "agent": "*",
        "scope": "skill",
        "verb": "use",
        "effect": "allow",
        "source": "agent_rule_exact",
        "priority": 600,
        "specificity": 2,
        "match": {
          "pattern": "research",
        },
      },
      {
        "id": "fs-ignore",
        "agent": "*",
        "scope": "fs",
        "verb": "read",
        "effect": "allow",
        "source": "global_default",
        "priority": 400,
        "specificity": 2,
        "match": {
          "pattern": "/workspace/*",
        },
      },
    ],
  }

  req := {
    "config": config,
    "request": {
      "scope": "skill",
      "verb": "use",
      "match": {
        "pattern": "research",
      },
    },
  }

  candidates := skill_candidates with input as req
  count(candidates) == 1
}
