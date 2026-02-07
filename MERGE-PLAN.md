# HoneyClaw PR Merge Plan

**Generated:** 2026-02-06 22:42 PST  
**Repository:** sarahtwilliams412-bit/honeyclaw  
**QA Lead Analysis**

## Executive Summary

6 PRs with extensive cross-conflicts. The **PR7↔PR8 pair** has the most severe conflict (18 files) and should NOT be merged consecutively without careful resolution. Recommended approach: merge least-conflicting PRs first to establish a stable base.

---

## Recommended Merge Order

| Order | PR | Title | Conflict Score | Rationale |
|-------|-----|-------|----------------|-----------|
| **1** | #5 | SOAR integration & blocklist | ⭐ LOWEST (9) | Only IMPROVEMENTS.md conflicts; cleanest merge |
| **2** | #4 | MITRE ATT&CK mapping | LOW (12) | 2-file conflicts (analysis module); builds on SOAR |
| **3** | #6 | AppArmor/Seccomp isolation | MEDIUM (17) | Security profiles, resolves deploy/* conflicts early |
| **4** | #3 | Log Correlation IDs & Immutability | MEDIUM (20) | Utility files; after security is stable |
| **5** | #7 | Terraform/Helm IaC | HIGH (30) | Infrastructure foundation for health monitoring |
| **6** | #8 | Health monitoring & self-healing | HIGH (30) | Depends on infrastructure; final merge |

---

## Conflict Matrix

```
              PR3    PR4    PR5    PR6    PR7    PR8
PR3 (Log)      -      4      4      4      4      4
PR4 (MITRE)    4      -      2      2      2      2
PR5 (SOAR)     4      2      -      1      1      1
PR6 (AppArmor) 4      2      1      -      5      5
PR7 (Terraform)4      2      1      5      -     18 ⚠️
PR8 (Health)   4      2      1      5     18 ⚠️   -
```

**⚠️ CRITICAL:** PR7 and PR8 have 18 conflicting files - DO NOT merge these back-to-back without thorough conflict resolution.

---

## Hottest Files (Most Conflicts)

| File | Conflict Count | PRs Affected |
|------|----------------|--------------|
| `IMPROVEMENTS.md` | 9 | ALL |
| `src/cli/main.py` | 6 | #3, #4, #5, #6, #7, #8 |
| `src/utils/correlation.py` | 5 | #3 vs all |
| `src/utils/geoip.py` | 5 | #3 vs all |
| `src/analysis/mitre_mapper.py` | 4 | #4 vs all |
| `src/analysis/__init__.py` | 4 | #4 vs all |
| `deploy/seccomp/honeyclaw-default.json` | 3 | #6, #7, #8 |
| `deploy/apparmor/*.profile` | 2 each | #6 vs #7, #8 |

---

## Detailed Merge Instructions

### Step 1: PR #5 - SOAR Integration
**Branch:** `claude/implement-improvement-item-5-pKZcw`  
**Expected Conflicts:** `IMPROVEMENTS.md` only  
**Resolution:** Accept PR5's SOAR section, preserve existing content

```bash
git checkout main
git merge origin/claude/implement-improvement-item-5-pKZcw
# Resolve IMPROVEMENTS.md - accept both sections
git commit
```

### Step 2: PR #4 - MITRE ATT&CK
**Branch:** `claude/implement-improvement-item-6-rrr6J`  
**Expected Conflicts:**
- `src/analysis/__init__.py` (add/add)
- `src/analysis/mitre_mapper.py` (add/add)

**Resolution:** Combine both versions, ensure imports work together

### Step 3: PR #6 - AppArmor/Seccomp
**Branch:** `claude/implement-improvement-item-3-y59Y6`  
**Expected Conflicts:**
- `IMPROVEMENTS.md`
- Security profile files in `deploy/`

**Resolution:** This is the authoritative source for security profiles

### Step 4: PR #3 - Log Correlation IDs
**Branch:** `claude/implement-improvement-item-7-SDadE`  
**Expected Conflicts:**
- `src/utils/correlation.py`
- `src/utils/geoip.py`
- `src/cli/main.py`
- `IMPROVEMENTS.md`

**Resolution:** PR3 is authoritative for logging utilities; integrate CLI carefully

### Step 5: PR #7 - Terraform/Helm IaC
**Branch:** `claude/implement-improvement-item-2-ckZM3`  
**Expected Conflicts:**
- All `deploy/terraform/` files
- All `deploy/kubernetes/helm/` files
- Security profiles (may already be resolved)

**Resolution:** PR7 is authoritative for IaC; preserve security settings from PR6

### Step 6: PR #8 - Health Monitoring ⚠️
**Branch:** `claude/implement-improvement-plan-1-61WxJ`  
**Expected Conflicts (18 files if after PR7):**
- `deploy/apparmor/*.profile`
- `deploy/flyio/deploy.sh`, `rotate.sh`
- `deploy/kubernetes/helm/*` (Chart.yaml, values.yaml, templates/)
- `deploy/terraform/*`
- `src/cli/main.py`

**Resolution:** Health monitoring code should integrate with existing infrastructure. Key files to verify:
- Helm values should include health endpoints
- Terraform should have health check resources
- CLI should have health commands

---

## Files by PR Owner (Authoritative Source)

| Domain | Authoritative PR | Files |
|--------|------------------|-------|
| SOAR/Feeds | PR #5 | `src/integrations/soar/*`, `src/feeds/*` |
| MITRE Analysis | PR #4 | `src/analysis/mitre_*`, `src/alerts/rules.py` |
| Security Profiles | PR #6 | `deploy/apparmor/*`, `deploy/seccomp/*` |
| Logging/Correlation | PR #3 | `src/logging/*`, `src/utils/correlation.py` |
| Infrastructure | PR #7 | `deploy/terraform/*`, `deploy/kubernetes/*` |
| Health/Self-Heal | PR #8 | `src/health/*` |

---

## Risk Mitigation

1. **After each merge:** Run `pytest` to verify no regressions
2. **IMPROVEMENTS.md:** This will conflict on every merge - use a simple append strategy
3. **src/cli/main.py:** Track which commands each PR adds; ensure final CLI includes all commands
4. **Infrastructure files:** After PR7+PR8, validate Helm/Terraform with `helm template` and `terraform validate`

---

## Supervisor Coordination

Each supervisor agent handling a PR should:
1. Check this plan for their PR's position in merge order
2. Wait for earlier PRs to merge before attempting theirs
3. Use the "Authoritative Source" table to know which PR owns which files
4. Report conflicts that differ from this analysis

**Communication Protocol:**
- PR #5 agent: Merge first, signal completion
- PR #4 agent: Wait for #5, then merge
- PR #6 agent: Wait for #4, then merge
- PR #3 agent: Wait for #6, then merge
- PR #7 agent: Wait for #3, then merge
- PR #8 agent: Wait for #7, then merge (prepare for 18+ conflicts)

---

## Appendix: Full Conflict Details

### PR7 ↔ PR8 Conflict (18 files)
```
IMPROVEMENTS.md
deploy/apparmor/honeyclaw-api.profile
deploy/apparmor/honeyclaw-enterprise.profile
deploy/apparmor/honeyclaw-ssh.profile
deploy/flyio/deploy.sh
deploy/flyio/rotate.sh
deploy/kubernetes/helm/honeyclaw/Chart.yaml
deploy/kubernetes/helm/honeyclaw/templates/deployment.yaml
deploy/kubernetes/helm/honeyclaw/templates/networkpolicy.yaml
deploy/kubernetes/helm/honeyclaw/templates/service.yaml
deploy/kubernetes/helm/honeyclaw/values.yaml
deploy/seccomp/honeyclaw-default.json
deploy/terraform/main.tf
deploy/terraform/modules/honeypot/main.tf
deploy/terraform/modules/logging/main.tf
deploy/terraform/modules/networking/main.tf
deploy/terraform/variables.tf
src/cli/main.py
```
