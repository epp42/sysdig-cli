# OSS Wisdom Extraction: googleworkspace/cli
## Applied to: Sysdig Backend API CLI

**Source repository:** https://github.com/googleworkspace/cli
**Source version analyzed:** v0.16.0 (Rust, ~20k stars)
**Extraction date:** 2026-03-14
**Methodology:** Full 6-phase OSS Wisdom extraction

---

## Table of Contents

1. [Phase 1 — Context Scan](#phase-1--context-scan)
2. [Phase 2 — Decision Archaeology (Reverse-Engineered ADRs)](#phase-2--decision-archaeology)
3. [Phase 3 — Pattern Detection](#phase-3--pattern-detection)
4. [Phase 4 — Gotchas and Hidden Traps](#phase-4--gotchas-and-hidden-traps)
5. [Phase 5 — Cross-Domain Transfer](#phase-5--cross-domain-transfer)
6. [Phase 6 — Wisdom Document for Sysdig CLI](#phase-6--wisdom-document-for-sysdig-cli)

---

## Phase 1 — Context Scan

### What is googleworkspace/cli?

`gws` is a single unified CLI for all Google Workspace APIs (Drive, Gmail, Calendar, Sheets, Docs, Chat, Meet, Forms, Tasks, etc.). Its central design bet is that the **command surface is dynamically generated at runtime** from Google's Discovery Service — meaning the CLI can expose new API endpoints the day Google ships them, without a code change.

**Language:** Rust
**Key dependencies:** clap (arg parsing), tokio (async), reqwest (HTTP), yup-oauth2 (auth), ratatui/crossterm (TUI), serde/serde_json, keyring, aes-gcm, zeroize
**Distribution:** npm global install, Homebrew, Cargo, Nix flakes, pre-built GitHub Release binaries
**License:** Apache-2.0
**Target users:** humans AND AI agents (explicitly documented)

### Repository Structure

```
src/
  main.rs              — Entry point, argument routing, pagination orchestration
  commands.rs          — Dynamic CLI tree builder from Discovery Documents
  discovery.rs         — Fetch, cache, parse Google API Discovery Documents
  executor.rs          — HTTP request construction, response handling, streaming
  auth.rs              — Multi-source credential resolution (6 sources, priority order)
  auth_commands.rs     — Auth subcommand dispatcher (login/setup/status/export/logout)
  credential_store.rs  — AES-256-GCM encrypted credential storage
  token_storage.rs     — Token caching (in-memory + encrypted at rest)
  oauth_config.rs      — OAuth client_secret.json read/write
  formatter.rs         — Output: JSON / Table / YAML / CSV
  schema.rs            — Schema inspection and client-side validation
  services.rs          — Static service registry (aliases, api_name, version)
  validate.rs          — Input sanitization (path traversal, injection prevention)
  client.rs            — reqwest wrapper with retry logic (429 + exponential backoff)
  error.rs             — Typed error enum, exit codes 1–5, structured JSON errors
  logging.rs           — Zero-overhead logging unless env var set; stdout stays clean
  text.rs              — Description truncation respecting sentence/word boundaries
  fs_util.rs           — Atomic file writes (POSIX rename(2))
  setup.rs             — Interactive GCP/OAuth setup wizard (6 stages)
  setup_tui.rs         — ratatui-based TUI for setup and pickers
  timezone.rs          — Account timezone resolution for calendar helpers
  generate_skills.rs   — AI skill document generation from CLI metadata
  helpers/
    mod.rs             — Helper trait definition + service→helper dispatch
    drive.rs           — +upload
    gmail/             — +send
    sheets.rs          — +append, +read
    docs.rs            — +write
    calendar.rs        — +insert, +agenda
    chat.rs            — +send
    script.rs          — +push
    workflows.rs       — Cross-service compositions
    modelarmor.rs      — Prompt injection protection
    events/            — +subscribe, +renew (Pub/Sub streaming)
skills/                — 92 generated SKILL.md files (agent context docs)
docs/                  — Documentation
registry/              — Persona and recipe YAML registries
.claude/               — Claude AI agent integration config
.gemini/               — Gemini AI agent integration config
```

### Core Design Philosophy (from CONTEXT.md and AGENTS.md)

1. **Dynamic over static** — never hardcode API shapes; derive from live schema
2. **Context efficiency** — field masking, dry-run, schema inspection prevent context-window overload
3. **Agents are first-class users** — inputs are always treated as potentially adversarial
4. **Progressive disclosure** — `--help` works at every nesting level
5. **Stdout is sacred** — only machine-readable JSON goes to stdout; all human guidance goes to stderr

---

## Phase 2 — Decision Archaeology

### ADR-001: Dynamic Command Surface from Discovery Documents

**Decision:** Commands are not hardcoded. At runtime, `gws` fetches the API's Discovery Document, parses it into a resource/method tree, and uses `clap` to build the command hierarchy dynamically.

**Evidence:** `commands.rs` `build_cli()` + `build_resource_command()` recursively walk `RestDescription` objects. Method parameters become CLI flags. The entire `SERVICES` registry in `services.rs` only needs an `(api_name, version)` tuple.

**Why:** Google has 100+ APIs with hundreds of methods. Manually mapping them would create a maintenance nightmare and always lag behind Google's releases. The discovery approach means the CLI is always complete by definition.

**Trade-offs accepted:**
- Startup cost (Discovery Document fetch + 24-hour cache)
- Less compile-time safety on command structure
- Fallback URL needed for newer APIs that use `$discovery/rest` instead of the v1 path

**Sysdig relevance:** HIGH. Sysdig has many backend APIs with independent release cycles. A similar schema-driven approach avoids the CLI team becoming a bottleneck.

---

### ADR-002: Static Service Registry as the Only Hardcoded Layer

**Decision:** `services.rs` contains a compile-time `SERVICES` array of `ServiceEntry` structs with `aliases`, `api_name`, `version`, and `description`. This is the only layer that requires a code change to add a new service.

**Evidence:** 17 services defined. `resolve_service()` matches user input against aliases. Unlisted APIs can still be accessed via `<api>:<version>` syntax.

**Why:** The registry provides discoverability (you can list all known services) and stable aliases (users type `drive`, not `drive:v3`) while keeping the door open for ad-hoc access. It is a controlled seam — small, testable, isolated.

**Sysdig relevance:** HIGH. Define a service registry for `vulnerabilities`, `posture`, `threats`, `events`, `policies`, etc. with stable aliases. The registry is the only place that changes when a new Sysdig API is added to the CLI.

---

### ADR-003: Typed Error Enum with Documented Exit Codes

**Decision:** `GwsError` has exactly 5 variants: `Api`, `Validation`, `Auth`, `Discovery`, `Other`. Each maps to a stable exit code (1–5). Errors serialize to JSON with consistent `{code, message, reason}` fields. The enable_url is surfaced for `accessNotConfigured` API errors.

**Evidence:** `error.rs` defines the enum. `print_error_json()` writes JSON to stdout; human guidance goes to stderr.

**Why:** Exit codes let scripts and agents branch on error type. The separation of machine-readable (stdout JSON) and human-readable (stderr) output is critical for pipeline composability.

**Sysdig relevance:** HIGH. CISOs and AI agents both consume this CLI. Stable, documented exit codes are a contract. Define them on day one and never renumber them.

---

### ADR-004: Multi-Source Credential Resolution with Priority Order

**Decision:** Auth is resolved from 6 sources in strict priority order:
1. `GOOGLE_WORKSPACE_CLI_TOKEN` env var (direct token, highest priority)
2. `GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE` env var (explicit path)
3. `~/.config/gws/credentials.enc` (encrypted local file)
4. `~/.config/gws/credentials.json` (plaintext local, authorized user only)
5. `GOOGLE_APPLICATION_CREDENTIALS` env var (ADC)
6. `~/.config/gcloud/application_default_credentials.json` (gcloud ADC)

**Evidence:** `auth.rs` lists these sources. Graceful degradation: corrupted encrypted credentials are removed and the fallback chain continues.

**Why:** Different deployment contexts (developer laptop, CI, container, agent) need different auth flows. A priority chain handles all cases without branching the CLI binary.

**Sysdig relevance:** HIGH. Sysdig deployments span developer workstations (interactive OAuth), CI pipelines (token env var), air-gapped environments (explicit credential files), and AI agent contexts (token injection). Design the same priority chain.

---

### ADR-005: Credentials Encrypted at Rest with AES-256-GCM

**Decision:** Credentials and tokens are encrypted with AES-256-GCM. The encryption key lives in the OS keyring (primary) or a `0600`-permissioned fallback file. Sensitive byte slices are zeroed on drop via `zeroize`. Files are written atomically via `tmp` + `rename(2)`.

**Evidence:** `credential_store.rs` implements this. `token_storage.rs` uses the same store for token caching.

**Why:** Credentials at rest in plaintext are a common security failure mode. The keyring integration leverages OS-level security. The file fallback ensures operation in environments (containers, CI) where the keyring is unavailable.

**Sysdig relevance:** HIGH. The CLI will handle Sysdig API tokens that provide broad access to security posture data. Encryption at rest is not optional.

---

### ADR-006: Helper Trait for High-Level Commands Over Raw API

**Decision:** A `Helper` trait with `inject_commands()`, `handle()`, and `helper_only()` methods allows per-service modules to inject hand-crafted subcommands (prefixed with `+`) alongside or instead of raw Discovery-generated commands.

**Evidence:** `helpers/mod.rs` defines the trait. `drive.rs` implements `+upload`, `sheets.rs` implements `+append`/`+read`, `workflows.rs` implements cross-service compositions. The `+` prefix makes helpers visually distinct.

**Why:** Raw API methods expose full JSON complexity. For common tasks (send email, upload file, append rows), users need simpler abstractions. Helpers bridge the gap without polluting the raw API surface.

**Sysdig relevance:** HIGH. Raw API calls to `POST /api/scanning/v1/image` require complex JSON payloads. Helpers like `+scan-image`, `+check-policy`, `+get-risk-score` will be the primary user-facing surface for CISOs and SOC analysts.

---

### ADR-007: Output Formats — JSON Default, Table/YAML/CSV Optional

**Decision:** All output is JSON by default. `--format` accepts `json|table|yaml|csv`. Table format flattens nested objects to dot-notation columns with 60-char max width. CSV handles array-of-objects, array-of-arrays, and scalars. Pagination maintains machine-parseability (CSV headers only on first page, YAML `---` separators between pages).

**Evidence:** `formatter.rs` implements all four. `--format` is a global root flag.

**Why:** AI agents need JSON. Humans need tables. Scripts need CSV. YAML is a readable middle ground. Making format a global flag means it works across all commands without per-command wiring.

**Sysdig relevance:** HIGH. SOC analysts will `--format table`. AI agents will consume JSON. Automation pipelines will use CSV. The global flag approach is the right design.

---

### ADR-008: Pagination as a First-Class Concern

**Decision:** `--page-all` auto-fetches all pages. `--page-limit N` caps pages. `--page-delay N` adds inter-page delay. Paginated output streams as NDJSON (one JSON object per line). CSV omits headers after page 1.

**Evidence:** `executor.rs` implements token-following pagination. `main.rs` parses the pagination flags.

**Why:** APIs that return lists often have pagination. If the CLI doesn't handle it, every consumer re-implements it. For AI agents, partial result sets without warning are silently wrong.

**Sysdig relevance:** HIGH. Sysdig APIs return paginated vulnerability lists, event streams, policy violations. `--page-all` is essential for agents that need complete data.

---

### ADR-009: Validation as a Security Boundary for Agent Inputs

**Decision:** `validate.rs` implements: path traversal prevention, control character rejection, URL injection blocking (`?`, `#`, `%`), API identifier restriction to `[a-zA-Z0-9._-]`, and CWD-boundary enforcement for output paths. Comprehensive unit tests for each defense.

**Evidence:** The AGENTS.md comment: *"This CLI is frequently invoked by AI/LLM agents. Always assume inputs can be adversarial."*

**Why:** LLMs can hallucinate paths, inject query parameters into resource names, or generate encoded traversal attacks. Validation at the CLI boundary prevents these from reaching the API.

**Sysdig relevance:** HIGH. Sysdig CLI will be used by AI agents in SOC automation workflows. An agent instructed to "check the policy for ../../../etc/passwd" must be stopped at the CLI layer.

---

### ADR-010: Stdout Discipline — Machine Output Only

**Decision:** All human-readable output (guidance, errors, hints, progress) goes to stderr. Stdout carries only structured JSON. Even error messages follow `{code, message, reason}` JSON format to stdout while stderr gets the user-friendly explanation.

**Evidence:** `logging.rs`: *"All logging writes to stderr or files, keeping stdout clean for machine-consumable JSON output."* `error.rs` `print_error_json()` writes JSON to stdout, guidance to stderr.

**Why:** Pipelines fail silently when tools mix human text and JSON on stdout. An agent parsing stdout gets corrupted JSON if progress messages are mixed in.

**Sysdig relevance:** CRITICAL. The CLI serves AI agents. Any stdout contamination breaks agent pipelines. This must be enforced in code review as an invariant.

---

### ADR-011: Schema Inspection as a Built-In Command

**Decision:** `gws schema <service> <method>` returns the full method signature: HTTP verb, path, required/optional parameters, request body schema, response schema, OAuth scopes. Reference resolution is optional.

**Evidence:** `schema.rs` `handle_schema_command()`.

**Why:** Agents need to construct correct payloads before calling APIs. Without schema inspection, agents guess at parameter names and body shapes. Schema inspection enables "plan before execute" workflows.

**Sysdig relevance:** HIGH. Add `sysdig schema <api> <resource> <method>` from day one. This is the primary onboarding tool for AI agents.

---

### ADR-012: Agent Skill Documents as First-Class Deliverables

**Decision:** `gws generate-skills` produces 92 `SKILL.md` files (one per service, plus helpers, personas, recipes). Skills are structured markdown files listing available commands with examples, flag tables, and write-operation warnings. A master index links them all.

**Evidence:** `generate_skills.rs`. The `skills/` directory contains persona skills (`persona-executive-assistant/`) and recipe skills (`recipe-generate-report-from-sheet/`).

**Why:** AI agents need grounded context about what the CLI can do. SKILL.md files are pre-digested API documentation that fit in an agent's context window without overload.

**Sysdig relevance:** MEDIUM-HIGH. CISO and SOC analyst personas should have corresponding skill documents. Recipe skills for "check unresolved vulnerabilities in a given image" are high-value for agent automation.

---

### ADR-013: Retry Logic Encapsulated in HTTP Client Layer

**Decision:** `client.rs` `send_with_retry()` retries up to 3 times on HTTP 429. It respects the `Retry-After` header, falling back to exponential backoff (1s, 2s, 4s). The retry uses a closure `Fn()` to reconstruct the request each attempt.

**Evidence:** `client.rs` analysis.

**Why:** Cloud APIs rate-limit. Scripts that hit 429 and fail without retry force every consumer to implement retry logic. Centralizing it in the HTTP layer is the correct abstraction.

**Sysdig relevance:** HIGH. Sysdig APIs have rate limits. The retry closure pattern (rebuild request each attempt) is critical — `reqwest::Request` is not cloneable and cannot be replayed as-is.

---

### ADR-014: Zero-Overhead Logging by Default

**Decision:** Logging only initializes if `GOOGLE_WORKSPACE_CLI_LOG` is set. If neither env var is set, `init_logging()` returns immediately: *"adding zero overhead."* File logging uses daily rotation and JSON-line format when enabled.

**Evidence:** `logging.rs`.

**Why:** CLI startup latency is user-visible. Initializing a logging framework (allocations, file handles, filter compilation) adds tens of milliseconds. Zero-overhead default is correct.

**Sysdig relevance:** HIGH. AI agents call the CLI in tight loops. Startup overhead compounds. Zero-overhead logging default is non-negotiable.

---

## Phase 3 — Pattern Detection

### Structural Patterns

#### Pattern 1: Schema-Driven Command Generation (SDCG)
The entire command surface is derived from a runtime schema fetch. This is the most powerful pattern in the codebase. It decouples the CLI release cycle from the API release cycle entirely. The CLI is complete by definition because the API is the source of truth.

**Shape:**
```
schema_fetch() → parse_schema() → build_command_tree() → execute_leaf()
```

#### Pattern 2: Two-Layer Command Surface (Raw + Helper)
Every service has two command layers:
1. **Raw layer** — generated from Discovery, exposes every method with `--params JSON` and `--json JSON`
2. **Helper layer** — hand-crafted `+verb-noun` commands with ergonomic flags

The `Helper` trait's `helper_only()` method allows helpers to completely suppress the raw layer for services where raw commands would be dangerous or confusing.

**Shape:**
```
service/
  raw/    (auto-generated: list, get, create, delete, ...)
  +send   (helper: human-ergonomic)
  +append (helper: human-ergonomic)
```

#### Pattern 3: Error-First Output Design
Every code path that writes to stdout writes JSON with a consistent shape. Errors are JSON. Successes are JSON. The schema is `{code, message, reason}` for errors and the raw API response for successes. There is no text-mode output.

#### Pattern 4: Credential Priority Chain
Auth is a pure function: `env_vars → explicit_files → encrypted_local → plaintext_local → ADC → gcloud_ADC`. Each source is attempted in order, with graceful fallback on failure. The first source that succeeds wins.

#### Pattern 5: Atomic Writes + fsync Everywhere
Any time a file is written (credentials, tokens, cache, OAuth config), it goes through `atomic_write()`: write to `.tmp` in same directory → `fsync()` → `rename(2)`. No credential corruption from partial writes.

#### Pattern 6: Defensive Validation at the CLI Boundary
Inputs are validated before they touch any filesystem path or API URL. Validation is not in the executor or the API client — it is at the CLI argument parsing layer. This ensures that invalid inputs fail fast with a useful error, not a confusing API error 3 hops later.

---

### Anti-Patterns Avoided

#### Anti-Pattern 1: Hardcoded Command Definitions
The project explicitly avoids writing `fn list_drive_files()`, `fn get_drive_file()`, etc. for each API method. This would mean ~500+ manually maintained functions.

#### Anti-Pattern 2: Mixed Stdout Output
The project explicitly separates machine output (stdout) from human output (stderr). It never writes progress bars, spinners, or informational text to stdout.

#### Anti-Pattern 3: Unauthenticated Fallthrough
The auth system does not silently fall through to unauthenticated requests. If credentials are configured but invalid, it fails. It only falls back to unauthenticated mode when *no credentials are configured at all*.

#### Anti-Pattern 4: Unbounded Memory for Large Files
The executor uses 64KB streaming chunks for file uploads. It never buffers an entire upload in memory. Similarly, Discovery Documents are cached to disk, not held in memory permanently.

#### Anti-Pattern 5: Scope Maximalism
The comment in `main.rs` explicitly addresses scope selection: *"The first scope is typically the broadest. Using all scopes causes issues when restrictive scopes are included."* The CLI picks the first (broadest) scope rather than requesting all scopes.

---

## Phase 4 — Gotchas and Hidden Traps

### Gotcha 1: Discovery Document Fallback URL is Mandatory
Google has two Discovery endpoints. Newer APIs (Forms, Keep) use `https://{service}.googleapis.com/$discovery/rest` instead of the v1 URL. A CLI that only uses the v1 URL will silently fail to load newer services. The fallback must be tried before reporting a discovery failure.

**Sysdig trap:** Sysdig's newer microservices may move to a different schema endpoint format. Build the fallback URL mechanism from day one.

---

### Gotcha 2: Request Objects Cannot Be Replayed — Always Use a Builder Closure
`reqwest::Request` is not `Clone`. Retry logic that stores a `Request` and resends it will panic or fail to compile. The solution is a closure `Fn() -> Request` that rebuilds the request fresh each retry attempt. This is subtle — most examples of retry logic store the request directly.

**Sysdig trap:** When implementing retry logic in the Sysdig HTTP client, always use a builder closure pattern, not a stored request.

---

### Gotcha 3: Scope Conflict — Readonly and Readwrite Scopes Are Mutually Exclusive
Google OAuth scopes have a hierarchy where including a broad scope alongside a restrictive scope can cause authentication failures. The TUI picker handles this by deselecting conflicting scopes when one is selected. This is invisible in the API documentation but causes confusing `403` errors.

**Sysdig trap:** If Sysdig's auth model uses role-based or scope-based access, ensure the CLI scope picker prevents conflicting scope combinations.

---

### Gotcha 4: 24-Hour Cache TTL Can Serve Stale Schemas
Discovery Documents are cached for 24 hours. If Sysdig deploys a new API version or removes a deprecated field, the CLI may continue using the old schema for up to 24 hours. For a security platform where API changes may remove vulnerable endpoints, stale cache could mislead users.

**Sysdig mitigation:** Add a `--refresh-schema` flag that bypasses cache. Use a shorter TTL (1 hour) for development environments. Embed a cache invalidation token in the schema URL (e.g., include the API version).

---

### Gotcha 5: `flatPath` vs `path` URL Template Selection
The executor has a subtle rule: use `flatPath` if its placeholders match the parameter names; otherwise fall back to `path`. This handles Google's decision to add `flatPath` for hierarchical resource names. Getting this wrong produces URLs with unresolved `{+name}` segments that the API rejects.

**Sysdig trap:** If the Sysdig OpenAPI spec uses path templates, ensure the URL builder correctly resolves all path parameters. Test with nested resources like `/orgs/{orgId}/teams/{teamId}/policies/{policyId}`.

---

### Gotcha 6: RFC 6570 `{+var}` Must NOT Be URL-Encoded
Standard path parameters like `{fileId}` should be percent-encoded. RFC 6570 parameters like `{+name}` indicate that the value contains slashes that must be preserved. URL-encoding them produces `%2F` where the API expects `/`. The `encode_path_segment()` vs `encode_path_preserving_slashes()` distinction in `validate.rs` addresses this.

**Sysdig trap:** Sysdig APIs with hierarchical resource names (e.g., `namespace/workload/container`) need the slash-preserving encoder. Check the OpenAPI spec for `x-google-url-encoding` or similar annotations.

---

### Gotcha 7: CSV Header Suppression on Paginated Output
CSV output only emits headers on the first page. If a caller starts reading from page 2 (e.g., after resuming a failed pipeline), they get no headers. This is correct behavior for piping to tools like `xsv` or `csvkit`, but unexpected if a caller assumes each page is a standalone CSV.

**Sysdig trap:** Document this behavior explicitly. Add a `--csv-no-header` flag for callers that always want headerless output.

---

### Gotcha 8: Token Storage Key Is Scope-Order-Dependent
Tokens are keyed by sorted, deduplicated, space-joined scopes. If a caller requests `["write", "read"]` once and `["read", "write"]` the next call, they will get the same cached token (correct). But if a caller uses scope subsets inconsistently, they will create multiple cache entries and potentially re-authenticate unnecessarily.

**Sysdig trap:** Normalize scope lists to sorted order at the auth call site, not just in the storage layer.

---

### Gotcha 9: Helper `helper_only()` Completely Hides Raw Commands
If a helper returns `helper_only() = true`, the Discovery-generated raw commands are not registered at all. For services like Workflows (which has a synthetic service with no real Discovery Document), this is correct. But if a helper mistakenly returns `true`, users silently lose access to all raw API methods.

**Sysdig trap:** Default `helper_only()` to `false`. Use `true` only for synthetic services or services where raw access is genuinely dangerous.

---

### Gotcha 10: Logging Guard Must Be Leaked (Not Dropped Early)
The file logging guard from `tracing_subscriber`'s file appender must be kept alive for the process lifetime. If it drops at end of `init_logging()`, file logging silently stops. The code uses `std::mem::forget()` on the guard. This is intentional, not a bug.

**Sysdig trap:** If using a similar structured logging setup, ensure the guard is stored at process scope or leaked intentionally.

---

### Gotcha 11: Setup Wizard Emits JSON Summary — Not Interactive Text
The `setup` command's output is a JSON summary of enabled/skipped/failed APIs. This means the setup command is also agent-parseable. However, it also means a failed setup step doesn't produce a visible red error — it produces a JSON field `"status": "failed"`. Users who don't read the JSON may miss failures.

**Sysdig mitigation:** In interactive mode (detected via `is_terminal(stdin)`), emit a human-readable summary to stderr in addition to the JSON summary to stdout.

---

## Phase 5 — Cross-Domain Transfer

### Translation Matrix: Google Workspace → Sysdig

| Google Workspace Context | Sysdig Equivalent | Transfer Fidelity |
|---|---|---|
| Google Discovery Service (JSON) | Sysdig OpenAPI/Swagger specs | High — same concept, different spec format |
| `drive`, `gmail`, `calendar` services | `vulnerabilities`, `posture`, `threats`, `policies`, `events` services | Direct |
| Service account credentials | Sysdig API tokens / service accounts | Direct |
| OAuth 2.0 scopes | Sysdig role-based scopes (admin, analyst, viewer) | High |
| `--page-all` for large file lists | `--page-all` for vulnerability lists, event streams | Direct |
| `+send` email helper | `+scan-image`, `+check-policy` helpers | Direct pattern |
| `persona-executive-assistant/` skills | `persona-ciso/`, `persona-soc-analyst/` skills | Direct |
| Model Armor prompt injection protection | Response sanitization for PII/secrets in vulnerability data | High |
| `gws schema drive files.list` | `sysdig schema vulnerabilities images.list` | Direct |
| Discovery cache TTL (24h) | OpenAPI spec cache TTL (1h for security platform) | Adapt: shorter TTL |
| `accessNotConfigured` enable_url | Sysdig "feature not licensed" with upgrade URL | Same pattern |
| `recipe-generate-report-from-sheet` | `recipe-weekly-risk-report`, `recipe-incident-triage` | Direct |

---

### The 5 Most Valuable Transfers for Sysdig CLI

#### Transfer 1: OpenAPI-Driven Command Generation
The single most valuable pattern. Instead of manually writing `sysdig vulns list`, `sysdig vulns get`, etc., generate the entire command surface from Sysdig's OpenAPI specs at startup. Add a service registry with stable aliases. The CLI becomes complete by definition.

**Implementation path:**
1. Fetch OpenAPI spec from Sysdig API gateway (or bundle at build time with version pinning)
2. Walk `paths` → build `resource → method` tree
3. Build clap subcommands from `operationId`, `parameters`, and `requestBody`
4. Cache spec with configurable TTL

#### Transfer 2: Two-Layer Surface (Raw + Helper) with + Prefix Convention
Add a helper layer on top of the raw generated layer. Use `+` prefix to distinguish. Start with 5-10 high-value helpers for the most common CISO/SOC workflows:
- `vulns +scan-image <image>` — wraps multipart scan initiation
- `policies +check <image>` — wraps policy evaluation with human-readable pass/fail
- `events +tail` — wraps event stream subscription with reconnect
- `posture +drift-report` — wraps drift detection query composition

#### Transfer 3: Documented Exit Code Contract
Define exit codes on day one:
- `0` — success
- `1` — API error (with `{code, message, reason}` JSON to stdout)
- `2` — auth error
- `3` — validation error
- `4` — schema/spec error
- `5` — internal error

Never renumber. Add to CHANGELOG when a new code is added. This is the contract AI agents sign when they integrate.

#### Transfer 4: Agent-First Input Validation
Treat every input as potentially from an LLM. Add validation for:
- Resource names: alphanumeric, dots, hyphens, underscores only
- Path parameters: no traversal, no encoded traversal
- Output paths: CWD-bounded, no absolute paths
- Query parameters: no injection of `?`, `#`, `%` into resource name fields

This is cheap to add at the start and expensive to retrofit after agents are in production.

#### Transfer 5: Stdout Discipline from Day One
Enforce as a team rule: **nothing goes to stdout that is not valid JSON**. Add a linting rule or test that captures stdout in all error paths and asserts `serde_json::from_str()` succeeds.

---

## Phase 6 — Wisdom Document for Sysdig CLI

This is the synthesized, actionable wisdom for building the Sysdig backend API CLI.

---

# Sysdig CLI Architecture Wisdom
## Derived from googleworkspace/cli v0.16.0 Analysis

### Foundational Invariants

These are the non-negotiable rules derived from hard lessons in the source repository. Violating them will cause exactly the class of problems the reference project evolved past.

---

#### INVARIANT-1: Stdout Is Inviolable JSON

**Rule:** Nothing is ever written to stdout except valid JSON.

**Why:** The CLI serves AI agents that parse stdout. A single line of "Loading..." on stdout breaks every agent pipeline silently. Errors, progress, hints, warnings — all go to stderr. The stdout contract is: if the command exits 0, stdout is the JSON response. If it exits non-zero, stdout is `{"code": N, "message": "...", "reason": "..."}`.

**How to enforce:**
- Add an integration test that spawns every command and asserts `jq . <stdout>` succeeds
- Code review checklist item: "Does this write to stdout?"
- Create a `stdout_json!()` macro that writes formatted JSON and nothing else

---

#### INVARIANT-2: Exit Codes Are a Versioned Contract

**Rule:** Define exit codes in a `CHANGELOG`-tracked table. Never renumber. Only add.

```
0 — success
1 — api_error       (Sysdig API returned 4xx/5xx)
2 — auth_error      (credentials missing, expired, or rejected)
3 — validation_error (bad input before any API call)
4 — schema_error    (OpenAPI spec unavailable or malformed)
5 — internal_error  (unexpected panic or logic error)
```

**Why:** Scripts and agents branch on exit codes. If `2` changes meaning, every downstream script silently misbehaves.

---

#### INVARIANT-3: Auth Is a Priority Chain, Never a Single Source

**Rule:** Implement credential resolution as an ordered fallback chain:
1. `SYSDIG_TOKEN` env var (for CI, agents, containers)
2. `SYSDIG_CREDENTIALS_FILE` env var (explicit path)
3. `~/.config/sysdig-cli/credentials.enc` (encrypted local)
4. `~/.config/sysdig-cli/credentials.json` (plaintext local, legacy)
5. `SYSDIG_API_TOKEN` env var (legacy compatibility)

**Why:** Different deployment contexts need different auth flows. A priority chain handles all without branching the binary. Never hardcode "use exactly one auth source."

---

#### INVARIANT-4: Credentials Are Always Encrypted at Rest

**Rule:** Use AES-256-GCM. Key lives in OS keyring (primary) or a `0600` file (fallback). Sensitive byte buffers are zeroed on drop. File writes are atomic (tmp + rename).

**Why:** Sysdig API tokens provide broad access to an organization's security posture. Storing them in plaintext is a security failure. The OS keyring integration is especially important on macOS (Keychain) and Linux (libsecret/KWallet).

---

#### INVARIANT-5: All Inputs Are Adversarial

**Rule:** Validate all inputs as if they come from a hostile LLM:
- Resource names: `^[a-zA-Z0-9._/-]+$` (allow `/` for hierarchical names)
- Output file paths: CWD-bounded, no `..`, no absolute paths
- Query parameters must not be embedded in resource name fields
- API identifiers for cache keys: `^[a-zA-Z0-9._-]+$`

**Why:** The CLI will be invoked by AI agents in SOC automation. An agent hallucinating `../../../etc/passwd` as an image name must be stopped at the CLI, not at the API.

---

### Architecture Decisions

#### DECISION-1: Schema-Driven Commands from OpenAPI Specs

Generate the command surface dynamically from Sysdig's OpenAPI specs. Do not manually write command handlers for each API endpoint.

**Implementation:**
```
on startup:
  1. load_spec() → fetch from $SYSDIG_API_URL/openapi.json (or bundled fallback)
  2. cache to ~/.config/sysdig-cli/spec-cache/{api_name}-{version}.json (TTL: 1 hour)
  3. parse_spec() → walk paths, extract operations
  4. build_command_tree() → map operationId to clap subcommands
  5. register_helpers() → inject + commands on top of raw surface
```

**Service registry shape:**
```rust
struct ServiceEntry {
    aliases: &'static [&'static str],  // ["vulns", "vulnerabilities", "scanning"]
    api_name: &'static str,             // "vulnerabilities"
    version: &'static str,              // "v1"
    base_url: &'static str,             // "https://app.sysdigcloud.com/api/scanning"
    description: &'static str,
}
```

**Cache invalidation:** Add `--refresh-spec` flag. Use spec `info.version` as part of cache key to auto-invalidate on server-side spec updates.

---

#### DECISION-2: Two-Layer Command Surface

```
sysdig vulns images list --params '{"limit": 10}'    ← raw generated
sysdig vulns +scan-image nginx:latest                 ← helper abstraction
sysdig posture +drift-report --since 24h             ← helper abstraction
sysdig events +tail --filter severity=high           ← helper abstraction
```

The `+` prefix is a convention, not a CLI mechanism — clap handles them as normal subcommand names starting with `+`.

**Helper trait:**
```rust
trait Helper {
    fn inject_commands(&self, cmd: Command, spec: &OpenApiSpec) -> Command;
    async fn handle(&self, matches: &ArgMatches, ctx: &Context) -> Result<bool>;
    fn helper_only(&self) -> bool { false }  // default: expose raw commands too
}
```

**Starting helper inventory (by persona):**

| Helper | Target persona | Wraps |
|---|---|---|
| `vulns +scan-image <image>` | VM manager | `POST /api/scanning/v1/scan` |
| `vulns +list-critical` | SOC analyst | `GET /api/scanning/v1/results` with severity filter |
| `policies +check <image>` | CISO | `POST /api/scanning/v1/policies/evaluate` |
| `policies +list-violations` | CISO | `GET /api/scanning/v1/policies/results` |
| `events +tail` | SOC analyst | WebSocket/SSE event stream |
| `posture +drift-report` | VM manager | Compose drift query + format |
| `threats +triage <id>` | SOC analyst | Get threat + related events |

---

#### DECISION-3: Pagination as First-Class Concern

Every list endpoint must support:
- `--page-all` — auto-fetch all pages, stream as NDJSON
- `--page-limit N` — fetch at most N pages
- `--page-delay MS` — sleep between pages (respect rate limits)

NDJSON output format for paginated streams (one JSON object per line, not a JSON array) makes the output pipeable to `jq`, `grep`, and agent tools without buffering the entire response.

**CSV pagination:** Emit headers only on page 1. Emit no separator between pages for table format.

---

#### DECISION-4: Output Format as Global Flag

```
sysdig vulns images list --format table
sysdig vulns images list --format json      # default
sysdig vulns images list --format yaml
sysdig vulns images list --format csv
sysdig vulns images list --format ndjson    # streaming pages
```

Table format must flatten nested objects: `vulnerability.cvss.score` becomes a column header `cvss.score`. Cap column width at 60 characters with Unicode-safe truncation.

---

#### DECISION-5: Schema Inspection as a First-Class Command

```bash
# Inspect a method's signature
sysdig schema vulns images.list

# Inspect a type definition
sysdig schema vulns Image

# Dry-run validates input without API call
sysdig vulns images list --params '{"limit": "not-a-number"}' --dry-run
```

This is the primary onboarding tool for AI agents. An agent that can run `sysdig schema` before attempting an API call will produce far fewer validation errors.

---

#### DECISION-6: Retry Logic in the HTTP Client Layer

```rust
// Client-level retry — not in individual commands
send_with_retry(build_request: impl Fn() -> Request) → Result<Response>
// Retries: up to 3 attempts on HTTP 429
// Respects Retry-After header; falls back to exponential backoff (1s, 2s, 4s)
// The Fn() closure rebuilds the request each attempt (Request is not Clone)
```

Add to the retry surface: `502`, `503`, `504` gateway errors from Sysdig's load balancer. These are transient in practice.

---

#### DECISION-7: Zero-Overhead Logging by Default

```bash
SYSDIG_CLI_LOG=sysdig=debug sysdig vulns images list   # stderr debug output
SYSDIG_CLI_LOG_FILE=/var/log/sysdig-cli sysdig ...     # daily-rotating JSON-line files
```

No logging infrastructure initializes unless an env var is set. Startup cost is constant regardless of log verbosity. This matters for AI agents calling the CLI in tight loops.

---

### Design Patterns

#### PATTERN-1: Spec-Driven Help Text

Help text for generated commands comes from the OpenAPI spec's `summary` and `description` fields, not from hardcoded strings. This means help text is always synchronized with the API.

**Truncation:** Use sentence-boundary truncation for `--help` (200 char limit) and full description for `sysdig schema`. Strip markdown links from spec descriptions (they don't render in terminals).

---

#### PATTERN-2: Structured Error with Context Links

For errors that have a known remediation, include an `action_url`:

```json
{
  "code": 2,
  "message": "authentication failed",
  "reason": "token expired",
  "action_url": "https://app.sysdigcloud.com/api/token"
}
```

This is the equivalent of the `enable_url` for `accessNotConfigured` Google errors. Agents can surface this URL to users. CI pipelines can emit it to build logs.

---

#### PATTERN-3: Dry Run Everywhere

Every mutating command supports `--dry-run`. In dry-run mode, the CLI:
1. Validates all inputs
2. Constructs the HTTP request
3. Prints what it *would* send as JSON to stdout
4. Exits 0 without making any API call

This is essential for AI agents that need to confirm their intent before executing.

---

#### PATTERN-4: Atomic Credential Writes

All credential and token writes use:
```
write_to_tmp() → fsync() → rename_to_target()
```

Never write directly to the credential file. A crash mid-write corrupts credentials and requires re-authentication.

---

#### PATTERN-5: Service-Scoped Skill Documents

Generate one `SKILL.md` per Sysdig service, plus cross-cutting skills per persona:

```
skills/
  sysdig-vulnerabilities/SKILL.md     — raw API + helpers
  sysdig-posture/SKILL.md
  sysdig-threats/SKILL.md
  sysdig-policies/SKILL.md
  sysdig-events/SKILL.md
  persona-ciso/SKILL.md               — CISO workflows
  persona-soc-analyst/SKILL.md        — SOC analyst workflows
  persona-vm-manager/SKILL.md         — Vulnerability management workflows
  persona-ai-agent/SKILL.md           — Agent-safe command subset
  recipe-weekly-risk-report/SKILL.md  — Multi-step recipe
  recipe-incident-triage/SKILL.md     — Multi-step recipe
```

Skill documents are the agent's grounding context. They enumerate available commands, show examples, warn about write operations, and explain required auth scopes.

---

### What to Build First (Priority Order)

Based on the patterns observed in the reference project, the recommended build order is:

1. **Core infrastructure** (week 1-2)
   - OpenAPI spec fetcher + cache
   - Service registry (5-10 initial Sysdig services)
   - Dynamic clap tree builder
   - Error enum + exit codes
   - Stdout discipline enforcement

2. **Auth layer** (week 2-3)
   - Priority chain credential resolver
   - Encrypted credential store (AES-256-GCM + OS keyring)
   - Atomic token storage
   - `sysdig auth setup/login/status/logout`

3. **Execution layer** (week 3-4)
   - HTTP client with retry logic
   - URL template resolver (path parameter substitution)
   - Request body validation against spec
   - Response formatter (JSON, table, YAML, CSV)
   - Pagination (`--page-all`, `--page-limit`, `--page-delay`)

4. **Schema inspection** (week 4)
   - `sysdig schema <service> <method>`
   - `--dry-run` support across all commands

5. **Helper layer** (week 5-6)
   - `Helper` trait
   - Initial 5-7 helpers for the highest-value SOC/CISO workflows

6. **Validation layer** (week 6)
   - `validate.rs` equivalent
   - Agent-input sanitization

7. **Skill generation** (week 7-8)
   - `sysdig generate-skills`
   - Persona skill documents
   - Master skill index

---

### Anti-Patterns to Actively Avoid

| Anti-pattern | Why | Alternative |
|---|---|---|
| Hardcoding command handlers per API endpoint | Maintenance burden, always lags API | Generate from OpenAPI spec |
| Writing non-JSON to stdout | Breaks agent pipelines silently | All stdout is JSON; guidance to stderr |
| Single auth source | Breaks CI / container / agent deployments | Priority chain with 5+ sources |
| Plaintext credential storage | Security failure for a security platform CLI | AES-256-GCM + OS keyring |
| Direct file writes for credentials | Corruption on crash | atomic_write() always |
| Logging to stdout | Corrupts JSON output | Logging to stderr or file only |
| `reqwest::Request` stored for retry | Does not compile / panics | Builder closure `Fn() -> Request` |
| Requesting all OAuth/API scopes | Scope conflicts cause silent 403s | Request minimal required scope |
| Ignoring pagination | Silently incomplete data for agents | `--page-all` implemented from day one |
| Buffering large file uploads | OOM on large container images | Stream with 64KB chunks |
| Absolute output paths from agent input | Path traversal attack surface | CWD-bounded path validation |

---

### Open Questions for the Sysdig CLI Team

1. **OpenAPI spec delivery:** Are Sysdig's OpenAPI specs publicly accessible at a stable URL, or do they need to be bundled at build time? Bundled specs require a CLI release to pick up API changes; URL-fetched specs are always current. Consider supporting both with a flag.

2. **Multi-region/multi-cluster:** Does the CLI need to manage multiple Sysdig backends (e.g., US vs EU, different SaaS regions, on-prem vs cloud)? If yes, design a `--context` flag (analogous to `kubectl --context`) from day one.

3. **WebSocket/SSE for event streams:** The `events +tail` helper implies a streaming connection. Does the Sysdig API expose this? The current reference project uses Pub/Sub `+subscribe`. Determine whether to use polling or true streaming, and whether reconnect logic belongs in the CLI or the helper.

4. **Spec caching TTL:** 1 hour is recommended for a security platform (vs 24 hours for Google), but this increases startup latency in offline environments. Consider: bundle a spec at build time as the offline fallback, and fetch live spec only if network is available.

5. **Mutating command warnings:** The reference project explicitly flags write operations in skill documents with warnings. For a security CLI, commands that modify policies, suppress findings, or acknowledge risks deserve interactive confirmation prompts when run by humans (not agents). Use `is_terminal(stdin)` to distinguish.

6. **Output field filtering:** The reference project mentions `--fields` for response field masking. For Sysdig's APIs that return large vulnerability objects, `--fields` is critical for keeping AI agent context windows manageable. Implement as a JMESPath or dot-notation filter.

---

### Appendix: Key Files in Reference Project

| File | Purpose | Priority to study |
|---|---|---|
| `src/commands.rs` | Dynamic CLI tree from Discovery | CRITICAL |
| `src/executor.rs` | HTTP request construction + pagination | CRITICAL |
| `src/error.rs` | Error enum + exit codes + JSON serialization | CRITICAL |
| `src/auth.rs` | Priority chain credential resolution | HIGH |
| `src/credential_store.rs` | AES-256-GCM storage + atomic writes | HIGH |
| `src/formatter.rs` | JSON/table/YAML/CSV output | HIGH |
| `src/validate.rs` | Agent-input sanitization | HIGH |
| `src/client.rs` | Retry logic with builder closure | HIGH |
| `src/helpers/mod.rs` | Helper trait definition | MEDIUM |
| `src/helpers/drive.rs` | Concrete helper implementation example | MEDIUM |
| `src/helpers/workflows.rs` | Cross-service composition pattern | MEDIUM |
| `src/generate_skills.rs` | Skill document generation | MEDIUM |
| `src/services.rs` | Service registry pattern | MEDIUM |
| `src/schema.rs` | Schema inspection command | MEDIUM |
| `src/discovery.rs` | Cache + fetch + fallback URL logic | MEDIUM |
| `src/logging.rs` | Zero-overhead logging | LOW |
| `src/fs_util.rs` | Atomic write implementation | LOW |

---

*End of wisdom document. Total patterns extracted: 14 ADRs, 6 structural patterns, 5 avoided anti-patterns, 11 gotchas, 5 high-value cross-domain transfers, 7 foundational invariants, 7 architecture decisions, 5 design patterns.*
