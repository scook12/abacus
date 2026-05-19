package abacus.tool

import rego.v1

test_tool_candidates_match_tool_scope_only if {
  config := {
    "meta": {
      "schemaVersion": 1,
      "policyVersion": "tool-tests",
      "permissionModeEffect": "deny",
    },
    "rules": [
      {
        "id": "tool-1",
        "agent": "*",
        "scope": "tool",
        "verb": "use",
        "effect": "allow",
        "source": "override_exact",
        "priority": 700,
        "specificity": 2,
        "match": {
          "tool": "bash",
          "argv0": "git",
        },
      },
      {
        "id": "net-1",
        "agent": "*",
        "scope": "net",
        "verb": "get",
        "effect": "deny",
        "source": "override_exact",
        "priority": 700,
        "specificity": 2,
        "match": {
          "host": "*",
        },
      },
    ],
  }

  req := {
    "config": config,
    "request": {
      "agent": "build",
      "scope": "tool",
      "verb": "use",
      "match": {
        "tool": "bash",
        "argv0": "git",
      },
    },
  }

  candidates := tool_candidates with input as req
  count(candidates) == 1
}

test_tool_candidates_capture_tool_reason if {
  config := {
    "meta": {
      "schemaVersion": 1,
      "policyVersion": "tool-tests",
      "permissionModeEffect": "deny",
    },
    "rules": [
      {
        "id": "tool-allow-git",
        "agent": "*",
        "scope": "tool",
        "verb": "use",
        "effect": "allow",
        "reason": "allow_git",
        "source": "override_exact",
        "priority": 700,
        "specificity": 3,
        "match": {
          "tool": "bash",
          "argv0": "git",
          "argv": ["status"],
        },
      },
    ],
  }

  req := {
    "config": config,
    "request": {
      "scope": "tool",
      "verb": "use",
      "match": {
        "tool": "bash",
        "argv0": "git",
        "argv": ["status"],
      },
    },
  }

  some c in tool_candidates with input as req
  object.get(c.rule, "reason", "") == "allow_git"
}
