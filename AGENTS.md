# OSINT Monitor -- Project Directive

## Purpose

This is a predictive intelligence system. Not a news aggregator. Not a dashboard that shows what happened. The point is to figure out **what is going to happen next** based on what is observable right now.

The system collects signals from 40+ open sources across multiple intelligence disciplines -- news, military transponders, sanctions lists, seismic sensors, trade flows, internet censorship, displacement data, nuclear safeguards, vulnerability databases. It extracts structured claims, entities, and relationships. It clusters events, tracks narrative propagation, and detects coordination.

All of that is infrastructure. The actual product is **deduction**: a chain of reasoning from observed facts to predicted outcomes.

## Analytical Philosophy

### Show evidence, not scores

Do not generate fake precision. No "53.1% probability of escalation." No composite severity scores built from made-up weights. These numbers create an illusion of rigor where none exists.

Instead: show what was observed, who reported it, whether sources agree or disagree, and what it means. Let the evidence speak. The analyst -- human or AI -- reasons from the evidence, not from a number.

### Reason like a game theorist

Every actor in a geopolitical situation is making strategic decisions under constraints. To predict what happens next, you must:

1. **Identify the actors** and their interests. Who benefits, who loses, who is constrained.
2. **Map the decision space.** What can each actor actually do? Not what they say -- what their capabilities and constraints permit.
3. **Trace the incentive structure.** Given what Actor A did, what is Actor B's best response? Given B's likely response, what does A anticipate and prepare for?
4. **Find the equilibria.** Where do the incentive chains converge? What outcomes are stable? What outcomes are unstable and likely to shift?
5. **Identify the pivots.** What single variable, if it changed, would shift the equilibrium? That's your leading indicator.

### Chain deductions from truth

Every prediction must trace back to observable facts through a clear logical chain:

```
OBSERVED: Iran has allowed selective tanker transits through Hormuz under apparent coordination (source: @TheIntelFrog, MarineTraffic data)
OBSERVED: EU leaders rejected military involvement in Hormuz (source: Al Jazeera, BBC)
OBSERVED: Trump asking ~7 countries for help reopening Hormuz (source: Defense News)
DEDUCTION: Iran is using selective access as leverage -- allowing allies' ships while blocking others. This is a negotiating position, not a total blockade.
DEDUCTION: EU refusal to participate militarily means the US cannot assemble a coalition for forced reopening without significant unilateral risk.
DEDUCTION: Trump seeking 7 countries' help and being refused means diplomatic pressure is failing.
PREDICTION: The Hormuz situation will persist as a managed crisis rather than resolve quickly. Iran will continue selective access to prevent a unified military response while maintaining economic pressure. Resolution requires either a direct US-Iran negotiation channel or an escalation that forces coalition formation.
```

Every step must be defensible. "Iran is using selective access as leverage" is a deduction from the observed transit patterns. "EU refusal means the US cannot assemble a coalition" follows from the diplomatic record. The prediction follows from the strategic logic.

### Be confident about what you see

When the data is clear, say so directly. Do not hedge with "it appears that" or "it seems possible that" when 12 independent sources confirm something happened. CENTCOM says they struck thousands of targets. Al Jazeera confirms Iran is still launching missiles. Both are confirmed facts from primary sources. State them as facts.

Reserve uncertainty language for actual uncertainty: competing claims, single-source reports, ambiguous signals. The Admiralty system exists for this -- use it. C1 means confirmed. D3 means doubtful. Say which one it is and move on.

### Distinguish between what is known and what is predicted

Three categories, always labeled:

- **CONFIRMED**: Multiple independent sources agree. Observable evidence supports it.
- **ASSESSED**: Logical deduction from confirmed facts. The reasoning chain is explicit.
- **PREDICTED**: Forward-looking judgment based on assessed dynamics. Always includes the key assumptions that, if wrong, would invalidate the prediction.

## When Generating Briefings and Analysis

### Daily briefings should answer three questions:
1. What happened? (Confirmed events, sourced)
2. What does it mean? (Assessment with reasoning chain)
3. What happens next? (Prediction with key assumptions)

### I&W evaluations should not be checklists
Do not just list which keywords appeared in today's news. Ask: given what we know about the actors' capabilities, intentions, and constraints, does the pattern of indicators suggest a trajectory toward the scenario? Or is it noise?

### ACH matrices should drive toward a conclusion
The point of ACH is not to list hypotheses. It is to eliminate hypotheses that are inconsistent with the evidence and identify which remaining hypothesis best explains the full body of evidence. End with a judgment, not a matrix.

### Red Team analysis should be genuinely adversarial
When generating counter-assessments, do not simply list alternative possibilities. Attack the strongest link in the reasoning chain. Find the assumption that, if wrong, collapses the entire assessment. That is the vulnerability.

## Technical Notes

- Pipeline: collectors -> dedup -> NLP -> claims -> clustering -> geocoding -> corroboration -> I&W -> alerting
- Database: SQLite default, PostgreSQL+pgvector for scale
- LLM: OpenAI (gpt-5-mini default) for briefings, ACH, Red Team, I&W relevance scoring
- All scores in the API are kept for programmatic use but the UI shows evidence, not numbers
- Corroboration is pre-cached on Event records during pipeline run for instant dashboard loads
