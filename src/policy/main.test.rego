package abacus

import rego.v1

base_config := {
  "meta": {
    "version": 1,
    "permissionModeEffect": "deny",
  },
  "rules": [],
}

test_falls_back_to_permission_mode_if_no_match if {
  test_input := {
    "config": base_config,
    "request": {
      "agent": "build",
      "scope": "tool",
      "verb": "use",
      "match": {
        "tool": "bash",
      },
    },
  }

  d := decision with input as test_input
  d.effect == "deny"
  d.source == "permission_mode"
}

test_override_beats_agent_rule if {
  config := {
    "meta": base_config.meta,
    "rules": [
      {
        "id": "r_agent_allow",
        "agent": "build",
        "scope": "tool",
        "verb": "use",
        "effect": "allow",
        "source": "agent_rule_exact",
        "priority": 600,
        "specificity": 2,
        "match": {"tool": "webfetch"},
      },
      {
        "id": "r_override_deny",
        "agent": "*",
        "scope": "tool",
        "verb": "use",
        "effect": "deny",
        "source": "override_exact",
        "priority": 700,
        "specificity": 2,
        "match": {"tool": "webfetch"},
      },
    ],
  }

  test_input := {
    "config": config,
    "request": {
      "agent": "build",
      "scope": "tool",
      "verb": "use",
      "match": {
        "tool": "webfetch",
      },
    },
  }

  d := decision with input as test_input
  d.effect == "deny"
  d.source == "override_exact"
  d.rule_id == "r_override_deny"
}

test_exact_beats_wildcard if {
  config := {
    "meta": base_config.meta,
    "rules": [
      {
        "id": "r_wildcard",
        "agent": "*",
        "scope": "tool",
        "verb": "use",
        "effect": "ask",
        "source": "override_wildcard",
        "priority": 650,
        "specificity": 1,
        "match": {"tool": "*"},
      },
      {
        "id": "r_exact",
        "agent": "*",
        "scope": "tool",
        "verb": "use",
        "effect": "allow",
        "source": "override_exact",
        "priority": 700,
        "specificity": 2,
        "match": {"tool": "webfetch"},
      },
    ],
  }

  test_input := {
    "config": config,
    "request": {
      "scope": "tool",
      "verb": "use",
      "match": {
        "tool": "webfetch",
      },
    },
  }

  d := decision with input as test_input
  d.effect == "allow"
  d.rule_id == "r_exact"
}

test_effect_tiebreak_prefers_deny if {
  config := {
    "meta": base_config.meta,
    "rules": [
      {
        "id": "r_allow",
        "agent": "*",
        "scope": "tool",
        "verb": "use",
        "effect": "allow",
        "source": "override_exact",
        "priority": 700,
        "specificity": 2,
        "match": {"tool": "webfetch"},
      },
      {
        "id": "r_deny",
        "agent": "*",
        "scope": "tool",
        "verb": "use",
        "effect": "deny",
        "source": "override_exact",
        "priority": 700,
        "specificity": 2,
        "match": {"tool": "webfetch"},
      },
    ],
  }

  test_input := {
    "config": config,
    "request": {
      "scope": "tool",
      "verb": "use",
      "match": {
        "tool": "webfetch",
      },
    },
  }

  d := decision with input as test_input
  d.effect == "deny"
  d.rule_id == "r_deny"
}

test_case_insensitive_glob if {
  config := {
    "meta": base_config.meta,
    "rules": [
      {
        "id": "r_case",
        "agent": "*",
        "scope": "tool",
        "verb": "use",
        "effect": "deny",
        "source": "override_exact",
        "priority": 700,
        "specificity": 2,
        "match": {"tool": "WEBFETCH"},
      },
    ],
  }

  test_input := {
    "config": config,
    "request": {
      "scope": "tool",
      "verb": "use",
      "match": {
        "tool": "webfetch",
      },
    },
  }

  d := decision with input as test_input
  d.effect == "deny"
}

test_argv_subsequence_matches_ordered_tokens if {
  config := {
    "meta": base_config.meta,
    "rules": [
      {
        "id": "r_push_force",
        "agent": "*",
        "scope": "tool",
        "verb": "use",
        "effect": "deny",
        "source": "override_exact",
        "priority": 700,
        "specificity": 3,
        "match": {
          "tool": "bash",
          "argv0": "git",
          "argv": ["push", "--force"],
        },
      },
    ],
  }

  test_input := {
    "config": config,
    "request": {
      "scope": "tool",
      "verb": "use",
      "match": {
        "tool": "bash",
        "argv0": "git",
        "argv": ["push", "--force", "origin", "main"],
      },
    },
  }

  d := decision with input as test_input
  d.effect == "deny"
}

test_net_match_checks_host_path_and_verb if {
  config := {
    "meta": base_config.meta,
    "rules": [
      {
        "id": "r_net_allow",
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
    ],
  }

  input_allow := {
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

  d_allow := decision with input as input_allow
  d_allow.effect == "allow"

  input_deny := {
    "config": config,
    "request": {
      "scope": "net",
      "verb": "post",
      "match": {
        "host": "docs.example.com",
        "path": "/api/v1/items",
      },
    },
  }

  d_deny := decision with input as input_deny
  d_deny.effect == "deny"
  d_deny.source == "permission_mode"
}
