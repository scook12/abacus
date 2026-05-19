package abacus.network

import rego.v1

network_rules contains rule if {
  some idx
  rules := object.get(object.get(input, "config", {}), "rules", [])
  rule := rules[idx]
  object.get(rule, "scope", "") == "net"
}

network_candidates contains candidate if {
  some rule in network_rules
  data.abacus.rule_matches(rule)
  candidate := {
    "rule": rule,
    "priority": object.get(rule, "priority", 0),
    "specificity": object.get(rule, "specificity", 0),
    "agent_rank": data.abacus.rank_agent(object.get(rule, "agent", "*")),
    "effect_rank": data.abacus.rank_effect(object.get(rule, "effect", "allow")),
    "id": object.get(rule, "id", ""),
  }
}
