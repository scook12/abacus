package abacus

import rego.v1

meta := object.get(object.get(input, "config", {}), "meta", {})

permission_mode_effect := object.get(meta, "permissionModeEffect", "deny")

policy_version := object.get(meta, "policyVersion", object.get(meta, "schemaVersion", 1))

default decision := {
  "effect": "deny",
  "source": "permission_mode",
  "reason": "permission_mode_default",
  "rule_id": "",
  "policy_version": 1,
}

decision := {
  "effect": permission_mode_effect,
  "source": "permission_mode",
  "reason": "permission_mode_default",
  "rule_id": "",
  "policy_version": policy_version,
} if {
  not best_candidate_exists
}

decision := {
  "effect": c.rule.effect,
  "source": c.rule.source,
  "reason": object.get(c.rule, "reason", "matched_rule"),
  "rule_id": c.rule.id,
  "policy_version": policy_version,
} if {
  c := best_candidate
}

rules := object.get(object.get(input, "config", {}), "rules", [])

candidates contains candidate if {
  some candidate in data.abacus.tool.tool_candidates
}

candidates contains candidate if {
  some candidate in data.abacus.network.network_candidates
}

candidates contains candidate if {
  some candidate in data.abacus.filesystem.filesystem_candidates
}

candidates contains candidate if {
  some candidate in data.abacus.secret.secret_candidates
}

candidates contains candidate if {
  some candidate in data.abacus.skill.skill_candidates
}

candidates contains candidate if {
  some idx
  rule := rules[idx]
  scope := object.get(rule, "scope", "")
  scope != "tool"
  scope != "net"
  scope != "fs"
  scope != "secret"
  scope != "skill"
  rule_matches(rule)
  candidate := {
    "rule": rule,
    "priority": object.get(rule, "priority", 0),
    "specificity": object.get(rule, "specificity", 0),
    "agent_rank": rank_agent(object.get(rule, "agent", "*")),
    "effect_rank": rank_effect(object.get(rule, "effect", "allow")),
    "id": object.get(rule, "id", ""),
  }
}

best_candidate := c if {
  some c in candidates
  not candidate_has_better_peer(c)
}

best_candidate_exists if {
  _ := best_candidate
}

candidate_has_better_peer(c) if {
  some other in candidates
  better_candidate(other, c)
}

better_candidate(a, b) if {
  a.priority > b.priority
}

better_candidate(a, b) if {
  a.priority == b.priority
  a.specificity > b.specificity
}

better_candidate(a, b) if {
  a.priority == b.priority
  a.specificity == b.specificity
  a.agent_rank > b.agent_rank
}

better_candidate(a, b) if {
  a.priority == b.priority
  a.specificity == b.specificity
  a.agent_rank == b.agent_rank
  a.effect_rank > b.effect_rank
}

better_candidate(a, b) if {
  a.priority == b.priority
  a.specificity == b.specificity
  a.agent_rank == b.agent_rank
  a.effect_rank == b.effect_rank
  a.id < b.id
}

rule_matches(rule) if {
  request := object.get(input, "request", {})
  request_match := object.get(request, "match", {})
  rule_match := object.get(rule, "match", {})

  object.get(rule, "scope", "") == object.get(request, "scope", "")

  rule_verb := object.get(rule, "verb", "*")
  request_verb := object.get(request, "verb", "")
  verb_matches(rule_verb, request_verb)

  rule_agent := object.get(rule, "agent", "*")
  request_agent := object.get(request, "agent", "")
  agent_matches(rule_agent, request_agent)

  field_matches(object.get(rule_match, "pattern", ""), object.get(request_match, "pattern", ""))
  field_matches(object.get(rule_match, "tool", ""), object.get(request_match, "tool", ""))
  field_matches(object.get(rule_match, "argv0", ""), object.get(request_match, "argv0", ""))
  field_matches(object.get(rule_match, "scheme", ""), object.get(request_match, "scheme", ""))
  field_matches(object.get(rule_match, "host", ""), object.get(request_match, "host", ""))
  field_matches(object.get(rule_match, "path", ""), object.get(request_match, "path", ""))
  field_matches(object.get(rule_match, "port", ""), object.get(request_match, "port", ""))

  argv_subsequence(
    object.get(rule_match, "argv", []),
    object.get(request_match, "argv", []),
  )
}

field_matches(pattern, _) if {
  pattern == ""
}

field_matches(pattern, value) if {
  pattern != ""
  value != ""
  glob_ci(pattern, value)
}

glob_ci(pattern, value) if {
  p := lower(pattern)
  v := lower(value)
  glob.match(p, [], v)
}

glob_ci(pattern, value) if {
  p := lower(pattern)
  v := lower(value)
  glob.match(p, ["/"], v)
}

glob_ci(pattern, value) if {
  p := lower(pattern)
  v := lower(value)
  glob.match(p, ["."], v)
}

argv_subsequence(rule_argv, request_argv) if {
  count(rule_argv) == 0
}

argv_subsequence(rule_argv, request_argv) if {
  count(rule_argv) > 0
  count(request_argv) > 0

  lowered_rule := [lower(token) | token := rule_argv[_]]
  lowered_request := [lower(token) | token := request_argv[_]]

  pattern := sprintf("*%s*", [concat("*", lowered_rule)])
  value := concat(" ", lowered_request)

  glob.match(pattern, [], value)
}

rank_effect("deny") := 3
rank_effect("ask") := 2
rank_effect("allow") := 1

rank_agent("*") := 0
rank_agent(agent) := 1 if {
  agent != "*"
}

verb_matches("*", _)

verb_matches(rule_verb, request_verb) if {
  rule_verb == request_verb
}

agent_matches("*", _)

agent_matches(rule_agent, request_agent) if {
  rule_agent == request_agent
}
