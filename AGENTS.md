# AGENTS.md

## Project Overview

[PLACEHOLDER]

## ⚠️ CRITICAL RULES - READ FIRST

### 🚫 NEVER Push Directly to Main

**The `main` branch is protected. ALL changes MUST go through a pull request.**

❌ **ABSOLUTELY PROHIBITED:**

```bash
git checkout main
git add <files>
git commit -m "changes"
git push origin main  # ❌ BLOCKED - Will be rejected by GitHub
```

**Why this is prohibited:**

- Bypasses code review and CI checks
- Can break production immediately
- Violates GitHub branch protection rules
- Makes it impossible to track changes properly

✅ **CORRECT WORKFLOW (Always Use PRs):**

```bash
# 1. Create feature branch
git checkout -b <issue-number>-description

# 2. Make changes and commit
git add <files>
git commit -m "type(scope): description"

# 3. Push feature branch
git push -u origin <issue-number>-description

# 4. Create pull request
gh pr create \
  --title "Brief description" \
  --body "Closes #<issue-number>" \
  --label "appropriate-label"

# 5. Enable auto-merge
gh pr merge --auto --rebase
```

**Emergency Situations:**

- Even for critical CI fixes, CREATE A PR
- Even for one-line changes, CREATE A PR
- Even if you're fixing your own mistake, CREATE A PR
- NO EXCEPTIONS - Always use the PR workflow


## Key Development Principles

1. KISS - *K*eep *I*t *S*imple *S*tupid -> Don't add complexity when a simpler solution works
1. YAGNI - *Y*ou *A*in't *G*onna *N*eed *I*t -> Don't add things until they are required
1. TDD - *T*est *D*riven *D*evelopment -> Write tests to drive the implementation
1. DRY - *D*on't *R*epeat *Y*ourself -> Don't duplicate functionality, data structures, or algorithms
1. SOLID - *S**O**L**I**D* ->
  . Single Responsibility
  . Open-Closed
  . Liskov Substitution
  . Interface Segregation
  . Dependency Inversion
1. Modularity - Develop independent modules through well defined interfaces
1. POLA - *P*rinciple *O*f *L*east *A*stonishment - Create intuitive and predictable interfaces to not surprise users

## Documentation Rules

- **Developer documentation**: `/docs/dev/` (architectural decisions, design docs)
- **Team guides**: `/agents/` (quick start, hierarchy, templates)
- **Never duplicate** documentation across locations - link instead


## Common Constraints

Shared constraints for all agents. Reference this file instead of duplicating.

### Minimal Changes Principle

Make the SMALLEST change that solves the problem.

**DO:**

- Touch ONLY files directly related to the issue requirements
- Make focused changes that directly address the issue
- Prefer 10-line fixes over 100-line refactors
- Keep scope strictly within issue requirements

**DO NOT:**

- Refactor unrelated code
- Add features beyond issue requirements
- "Improve" code outside the issue scope
- Restructure unless explicitly required by the issue

**Rule of Thumb**: If it's not mentioned in the issue, don't change it.

### Scope Discipline

- Complete assigned task, nothing more
- Do not refactor "while you're in there"
- Do not add features beyond requirements
- Do not "improve" unrelated code

### When Blocked

1. Document what's blocking you
2. Document what you tried
3. Escalate to immediate supervisor
4. Continue with non-blocked work if possible

### Admin Override Prohibition

**NEVER use admin override capabilities.**

Agents must:

- Respect all user decisions and preferences
- Request user approval for significant changes
- Follow established workflows and approval processes
- Escalate to supervisors when blocked, not override policies

Agents must NOT:

- Override user decisions or preferences
- Bypass approval requirements
- Make autonomous commits/pushes without approval
- Skip safety checks or validation steps
- Use emergency/admin capabilities to circumvent processes