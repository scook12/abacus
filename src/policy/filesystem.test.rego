package abacus.filesystem

import rego.v1

test_filesystem_candidates_match_fs_scope_only if {
  config := {
    "meta": {
      "schemaVersion": 1,
      "policyVersion": "filesystem-tests",
      "permissionModeEffect": "deny",
    },
    "rules": [
      {
        "id": "fs-read",
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
      {
        "id": "net-ignore",
        "agent": "*",
        "scope": "net",
        "verb": "*",
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
      "scope": "fs",
      "verb": "read",
      "match": {
        "pattern": "/workspace/file.txt",
      },
    },
  }

  candidates := filesystem_candidates with input as req
  count(candidates) == 1
}
