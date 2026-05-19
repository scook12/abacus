package abacus.secret

import rego.v1

test_secret_candidates_match_secret_scope_only if {
  config := {
    "meta": {
      "schemaVersion": 1,
      "policyVersion": "secret-tests",
      "permissionModeEffect": "deny",
    },
    "rules": [
      {
        "id": "secret-git",
        "agent": "*",
        "scope": "secret",
        "verb": "use",
        "effect": "allow",
        "reason": "allow_git_secret",
        "source": "agent_rule_exact",
        "priority": 600,
        "specificity": 2,
        "match": {
          "pattern": "git",
        },
      },
      {
        "id": "skill-ignore",
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
    ],
  }

  req := {
    "config": config,
    "request": {
      "scope": "secret",
      "verb": "use",
      "match": {
        "pattern": "git",
      },
    },
  }

  candidates := secret_candidates with input as req
  count(candidates) == 1
}
