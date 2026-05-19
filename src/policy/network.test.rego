package abacus.network

import rego.v1

test_network_candidates_match_net_scope_only if {
  config := {
    "meta": {
      "schemaVersion": 1,
      "policyVersion": "network-tests",
      "permissionModeEffect": "deny",
    },
    "rules": [
      {
        "id": "net-allow",
        "agent": "*",
        "scope": "net",
        "verb": "get",
        "effect": "allow",
        "source": "override_exact",
        "priority": 700,
        "specificity": 3,
        "match": {
          "host": "*.example.com",
          "path": "/api/*",
        },
      },
      {
        "id": "tool-ignore",
        "agent": "*",
        "scope": "tool",
        "verb": "use",
        "effect": "deny",
        "source": "override_exact",
        "priority": 700,
        "specificity": 2,
        "match": {
          "tool": "webfetch",
        },
      },
    ],
  }

  req := {
    "config": config,
    "request": {
      "scope": "net",
      "verb": "get",
      "match": {
        "host": "docs.example.com",
        "path": "/api/v1/items",
      },
    },
  }

  candidates := network_candidates with input as req
  count(candidates) == 1
}

test_network_candidates_preserve_rule_reason if {
  config := {
    "meta": {
      "schemaVersion": 1,
      "policyVersion": "network-tests",
      "permissionModeEffect": "deny",
    },
    "rules": [
      {
        "id": "net-allow",
        "agent": "*",
        "scope": "net",
        "verb": "get",
        "effect": "allow",
        "reason": "allow_example_api",
        "source": "override_exact",
        "priority": 700,
        "specificity": 3,
        "match": {
          "host": "*.example.com",
          "path": "/api/*",
        },
      },
    ],
  }

  req := {
    "config": config,
    "request": {
      "scope": "net",
      "verb": "get",
      "match": {
        "host": "docs.example.com",
        "path": "/api/v1/items",
      },
    },
  }

  some c in network_candidates with input as req
  object.get(c.rule, "reason", "") == "allow_example_api"
}
