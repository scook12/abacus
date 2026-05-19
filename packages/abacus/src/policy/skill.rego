package abacus.skill

import rego.v1

skill_rules contains rule if {
  some idx
  rules := object.get(object.get(input, "config", {}), "rules", [])
  rule := rules[idx]
  object.get(rule, "scope", "") == "skill"
}

skill_candidates contains candidate if {
  some rule in skill_rules
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
