---
type: playbook
title: "Playbook - Attack Chain Visualization"
category: visualization
tags: [playbook, excalibrain, attack-chain, ontology, bb-playbook]
status: active
last_updated: 2026-04-10
---

# Playbook - Attack Chain Visualization

Use **ExcaliBrain** to visualize the relationships between attack chains, targets, findings, and submissions. This document defines the unified frontmatter ontology and usage conventions.

---

## Why ExcaliBrain

Obsidian's built-in Graph View becomes an unreadable "hairball" when there are many notes. ExcaliBrain's advantages:

- **Dynamically expands around the current focus note** instead of rendering the entire graph
- Uses frontmatter to explicitly define parent/child/friend/next/prev relationships
- Supports unresolved link display (notes that haven't been created yet can still be planned)
- Click any node to jump and re-focus

Particularly well-suited for presenting:
1. **Attack chain step sequences** (linear chain: entry -> pivot -> impact)
2. **Target-to-Finding hierarchical relationships**
3. **Cross-target Pattern associations**
4. **Submission status tracking**

---

## Ontology Definition (Mandatory)

All Target / Finding / Attack Chain / Submission notes must follow this ontology in their frontmatter:

### Base Relationship Fields

| Field | Meaning | Use Case |
|-------|---------|----------|
| `parent` | Upper level / belongs to | Finding -> Target; Attack Chain -> Target; Submission -> Finding |
| `child` | Lower level / contains | Target -> Finding list; Attack Chain -> constituent Findings |
| `next` | Next step (sequence) | Step ordering within an Attack Chain |
| `previous` | Previous step (sequence) | Reverse of the above |
| `friend` | Lateral association (non-directional) | Same type but no hierarchical relationship (e.g., different targets with the same pattern) |

### Bug Bounty Specific Relationship Fields

| Field | Meaning | Use Case |
|-------|---------|----------|
| `exploits` | Which vulnerabilities this note leverages | Attack Chain -> Finding - .git exposure |
| `prerequisite` | Precondition (must be achieved first) | Finding -> Finding - subdomain takeover |
| `pattern` | Corresponding cross-target pattern | Finding -> Pattern - Git Exposure |
| `mitigation` | Remediation reference | Finding -> Resource - Git Hardening |

---

## Frontmatter Templates

### Target Note

```yaml
---
type: target
domain: example.com
org: Example Corp
risk: high
status: active
platform: hackerone
child:
  - "[[Finding - example .git exposure]]"
  - "[[Finding - example XSS]]"
  - "[[Attack Chain - Example Supply Chain]]"
pattern:
  - "[[Pattern - Git Exposure]]"
---
```

### Finding Note

```yaml
---
type: finding
target: "[[Target - example-corp]]"
risk: high
status: verified
parent: "[[Target - example-corp]]"
prerequisite:
  - "[[Finding - subdomain discovery]]"
pattern: "[[Pattern - Git Exposure]]"
exploits:
  - ".git directory exposure"
next: "[[Finding - credential extraction]]"
---
```

### Attack Chain Note

```yaml
---
type: attack-chain
target: "[[Target - example-corp]]"
risk: critical
status: complete
parent: "[[Target - example-corp]]"
exploits:
  - "[[Finding - .git exposure]]"
  - "[[Finding - MySQL credentials leak]]"
  - "[[Finding - phpMyAdmin default login]]"
next: "[[Attack Chain - Example lateral movement]]"
---
```

### Submission Note

```yaml
---
type: submission
platform: hackerone
severity: P2
status: submitted
parent:
  - "[[Finding - example .git exposure]]"
  - "[[Attack Chain - Example Supply Chain]]"
submitted_at: 2026-04-10
---
```

---

## Usage Workflow

### Creating an Attack Chain for the First Time

1. Create the Target note first (using QuickAdd `New Target`)
2. Use `New Finding` to create each finding; set frontmatter `parent` pointing back to the Target
3. Create an Attack Chain note; list the constituent findings in the frontmatter `exploits` field
4. Use `next` / `previous` to chain the step sequence
5. Open the Attack Chain note in ExcaliBrain to see the complete graph

### Adjusting the Ontology

ExcaliBrain Settings -> Enable **Hierarchy defined in YAML frontmatter** (should already be configured)

If you need to define custom relationship terms beyond parent/child (such as `exploits`, `prerequisite`), go to ExcaliBrain Settings -> Ontology -> add the following mappings:

| Frontmatter Field | ExcaliBrain Type |
|-------------------|------------------|
| `parent` | parents |
| `child` | children |
| `next` | next |
| `previous` | previous |
| `friend` | friends |
| `exploits` | children (visually equivalent to child) |
| `prerequisite` | parents (visually equivalent to parent) |
| `pattern` | friends |
| `mitigation` | friends |

---

## Example: Supply Chain Attack Chain

Suppose you create `Attack Chain - Example Supply Chain.md`:

```yaml
---
type: attack-chain
target: "[[Target - example-corp]]"
parent: "[[Target - example-corp]]"
risk: critical
status: submitted
exploits:
  - "[[Finding - example .git exposure]]"
  - "[[Finding - example MySQL credentials leak]]"
  - "[[Finding - example phpMyAdmin default login]]"
next: "[[Attack Chain - Example Lateral Movement]]"
pattern:
  - "[[Pattern - Git Exposure]]"
  - "[[Pattern - Supply Chain Analysis]]"
---
```

Opening ExcaliBrain focused on this note will show:

```
         Target - example-corp
                | parent
                v
    Attack Chain - Example Supply Chain  <-- current focus
     |                |               \
     v exploits       v                v
  .git exposure   MySQL leak     phpMyAdmin login
                                         
    --- next -->  Attack Chain - Example Lateral Movement
    
    --- pattern -->  Pattern - Git Exposure
                     Pattern - Supply Chain Analysis
```

---

## Checklist (When Creating Attack Chain Notes)

- [ ] `type: attack-chain` is filled in
- [ ] `parent` points to the Target
- [ ] `exploits` lists all constituent findings (must use `[[...]]` format)
- [ ] If there is a temporal sequence, chain with `next` / `previous`
- [ ] Associated cross-target patterns are filled in under `pattern`
- [ ] All link targets actually exist (unresolved links display as dashed lines -- acceptable but remember to fill in later)
- [ ] Visually verify the graph is correct in ExcaliBrain

---

## Related Notes

- Wiki Schema -- defines the full ontology for all note types
- Knowledge Base Index -- master index of all KB entries
- Pattern - Supply Chain Analysis -- cross-target supply chain patterns
