# Milestone 2 — Phase 3 Official Codex Protocol Reference

**Status:** source reference for the Phase 3 verifier. This document records the current OpenAI Codex loading, precedence, discovery, activation, trust, and runtime-diagnostic rules that matter to the files discovered by Milestone 2 Phases 1 and 2.

**Source snapshot date:** 2026-08-25

**Authority used here:** official OpenAI / ChatGPT Codex documentation and the public Codex CLI behavior documented by OpenAI. This document is not the verifier implementation and does not replace runtime checks against the installed Codex version.

---

## 1. Official source set

Canonical OpenAI documentation used for this reference:

- Config basics: https://developers.openai.com/codex/config-basic
- Configuration reference: https://developers.openai.com/codex/config-reference
- AGENTS.md: https://developers.openai.com/codex/guides/agents-md
- Hooks: https://developers.openai.com/codex/hooks
- Skills: https://developers.openai.com/codex/skills
- Rules: https://developers.openai.com/codex/rules
- Plugin packaging: https://developers.openai.com/codex/plugins/build
- CLI / developer commands: https://developers.openai.com/codex/cli/reference

The OpenAI documentation currently redirects some Codex pages to `learn.chatgpt.com`; the developer URLs above remain the canonical entry points used by this project.

---

## 2. Terms that determine whether a discovered file is effective

The following OpenAI terms must remain distinct:

- **Codex home / `CODEX_HOME`** — defaults to `~/.codex` unless overridden.
- **Current working directory / CWD** — the working directory from which Codex is operating.
- **Project root** — normally the Git root; configurable root markers can affect discovery.
- **Trusted project** — project-local `.codex/` configuration, hooks, and rules require project trust before they load.
- **Active config layer** — a configuration layer that participates in the effective configuration for the current run.
- **Profile** — selected with `--profile profile-name`; profile files live next to the user config.
- **Managed** — policy/configuration supplied through managed sources such as `requirements.toml`; managed hooks have different trust/disable behavior from normal hooks.
- **Effective state** — the runtime result after discovery, precedence, trust, profile selection, feature state, and version compatibility are applied.

A filesystem match alone does not establish any of these states.

---

# 3. `config.toml` protocol

## 3.1 Official precedence

OpenAI states: **“Codex resolves values in this order (highest precedence first)”**.

The documented order is:

1. CLI flags and `--config` overrides.
2. Project `.codex/config.toml` files, ordered from project root down to CWD; the closest project layer wins for conflicting config values. Project layers are trusted-project only.
3. Profile file selected with `--profile profile-name`: `$CODEX_HOME/profile-name.config.toml` (normally `~/.codex/profile-name.config.toml`).
4. User config: `$CODEX_HOME/config.toml` (normally `~/.codex/config.toml`).
5. Unix system config: `/etc/codex/config.toml`.
6. Built-in defaults.

Official source: Config basics, “Configuration precedence”.

## 3.2 Project config activation

OpenAI documents that user-level configuration lives in `~/.codex/config.toml`, while project-scoped overrides may live in `.codex/config.toml` files. Project-scoped config files load **only when the project is trusted**.

A discovered `<repo>/.codex/config.toml` therefore has at least three separate questions:

- Is the file present?
- Does it parse for the installed Codex version?
- Is its project layer trusted and active for the current CWD/project root?

## 3.3 Project-local keys that Codex ignores

The current OpenAI Configuration Reference states that project-scoped config cannot override several machine-local/provider keys. It specifically lists these as ignored when placed in project-local `.codex/config.toml`:

- `openai_base_url`
- `chatgpt_base_url`
- `apps_mcp_product_sku`
- `model_provider`
- `model_providers`
- `notify`
- `profile`
- `profiles`
- `experimental_realtime_ws_base_url`
- `otel`

Those keys belong in user-level configuration instead.

## 3.4 Profile files

Official path form:

```text
$CODEX_HOME/profile-name.config.toml
```

A profile file is relevant only when the corresponding profile is selected with:

```text
--profile profile-name
```

Existence without profile selection does not make the profile file the active profile layer.

## 3.5 Role-specific config files

The Configuration Reference defines:

```text
agents.<name>.config_file
```

as a **path to a TOML config layer for that role**. Relative paths resolve from the config file that declares the role.

This means the effective filename is dynamic; Phase 3 cannot rely only on a fixed filename list. Once an active config layer is known, role config paths must be resolved from the config value itself.

## 3.6 Model instruction file

The Configuration Reference defines:

```text
model_instructions_file
```

as a path to a replacement for built-in instructions instead of `AGENTS.md`.

This is also a dynamic filename. Its relevance comes from an active config value, not from a hardcoded filename.

## 3.7 Project instruction fallback names

The Configuration Reference defines:

```text
project_doc_fallback_filenames
```

as additional filenames to try when `AGENTS.md` is missing.

Therefore the complete instruction-filename set is partly runtime-configured.

---

# 4. `AGENTS.md` / `AGENTS.override.md` protocol

OpenAI describes this as an **instruction chain** built when Codex starts.

## 4.1 Global scope

In Codex home (`CODEX_HOME`, default `~/.codex`):

1. Codex reads `AGENTS.override.md` if it exists.
2. Otherwise Codex reads `AGENTS.md`.
3. Codex uses only the first non-empty file at this global level.

Typical paths:

```text
~/.codex/AGENTS.override.md
~/.codex/AGENTS.md
```

## 4.2 Project scope

Starting at the project root, Codex walks down to the current working directory.

At **each directory level** Codex checks, in order:

1. `AGENTS.override.md`
2. `AGENTS.md`
3. names configured in `project_doc_fallback_filenames`

OpenAI explicitly states that Codex includes **“at most one file per directory.”**

If no project root can be found, only the current directory is checked for project-scope instructions.

## 4.3 Merge order

Selected project instruction files are concatenated from root toward CWD. Files nearer the current directory occur later in the combined prompt and therefore override earlier guidance when instructions conflict.

This is the place where “closest to the working directory wins” is relevant, but it is not a universal rule for every Codex file type.

## 4.4 Empty files and byte limit

Codex skips empty instruction files. It stops adding project instruction files when the combined instructions reach `project_doc_max_bytes` (documented default: 32 KiB).

## 4.5 Runtime confirmation

OpenAI documents `codex debug prompt-input` as a developer command that renders the **model-visible prompt input list as JSON**. This is the strongest documented runtime check for whether instruction material reached model-visible input.

---

# 5. Hooks protocol

## 5.1 Discovery forms

Codex discovers hooks next to **active config layers** in either form:

```text
hooks.json
```

or inline:

```toml
[hooks]
```

inside `config.toml`.

OpenAI lists the common locations:

```text
~/.codex/hooks.json
~/.codex/config.toml
<repo>/.codex/hooks.json
<repo>/.codex/config.toml
```

Installed plugins can also provide hooks through their plugin manifest or default `hooks/hooks.json`.

## 5.2 Multiple sources

Hooks do not use ordinary config-value replacement semantics. If multiple active hook sources match, Codex loads the matching hooks from all of them.

OpenAI states: **“Matching hooks from multiple files all run.”**

Higher-precedence config layers do not replace lower-precedence hooks.

If one layer contains both `hooks.json` and inline `[hooks]`, Codex merges them and warns at startup.

## 5.3 Project trust

Project-local hooks load only when the project `.codex/` layer is trusted. User and system hooks can remain active even when a project is untrusted.

## 5.4 Hook trust

Before a non-managed hook runs, Codex requires review/trust of the exact hook definition. Trust is recorded against the hook’s current hash. A changed hook is therefore a new trust state and is skipped until trusted again.

The `/hooks` CLI UI is the documented place to inspect:

- hook sources
- review state
- trust state
- individual disabled state

## 5.5 Hook feature state

Hooks are enabled by default. OpenAI documents the canonical feature key:

```toml
[features]
hooks = false
```

`codex_hooks` is documented as a deprecated alias.

## 5.6 Managed hooks / `requirements.toml`

Managed hooks can be supplied through system, MDM, cloud, or `requirements.toml` sources. OpenAI documents managed hooks as trusted by policy and not disableable from the normal user hook browser.

`requirements.toml` can also pin:

```toml
[features]
hooks = true
```

and can use:

```toml
allow_managed_hooks_only = true
```

to skip user, project, session, and plugin hooks while still loading managed hooks.

## 5.7 Plugin hooks

Default plugin hook path:

```text
hooks/hooks.json
```

A plugin can override the default hook location with the `hooks` entry in:

```text
.codex-plugin/plugin.json
```

Manifest hook paths resolve relative to the plugin root and must remain inside that root.

---

# 6. Skills protocol

## 6.1 Required structure

A skill is a directory containing:

```text
SKILL.md
```

`SKILL.md` must contain at least:

- `name`
- `description`

Optional skill content documented by OpenAI includes:

```text
scripts/
references/
assets/
agents/openai.yaml
```

`agents/openai.yaml` is optional and can configure appearance, invocation policy, and tool dependencies.

## 6.2 Local discovery locations

OpenAI documents repository, user, admin, and system skill scopes.

Repository discovery scans `.agents/skills` from CWD upward to repo root:

```text
$CWD/.agents/skills
$CWD/../.agents/skills
...
$REPO_ROOT/.agents/skills
```

User scope:

```text
$HOME/.agents/skills
```

Admin scope:

```text
/etc/codex/skills
```

System scope consists of skills bundled with Codex by OpenAI.

Codex supports symlinked skill directories and follows the symlink target during discovery.

## 6.3 Duplicate skill names

If multiple discovered skills have the same `name`, Codex does not merge them; both can appear in skill selectors.

## 6.4 Enable / disable state

A local skill can exist and be valid but be explicitly disabled in user config:

```toml
[[skills.config]]
path = "/path/to/skill/SKILL.md"
enabled = false
```

OpenAI says Codex should be restarted after changing this user config.

## 6.5 Invocation policy

`agents/openai.yaml` can set:

```yaml
policy:
  allow_implicit_invocation: false
```

When false, implicit invocation is disabled, while explicit `$skill` invocation still works.

---

# 7. Rules protocol

## 7.1 File location

Rules are `.rules` files under a `rules/` folder next to an active config layer.

Example:

```text
~/.codex/rules/default.rules
```

Codex scans `rules/` under every active config layer at startup.

Project-local rules:

```text
<repo>/.codex/rules/
```

load only when the project `.codex/` layer is trusted.

Admins can also enforce restrictive rule entries from `requirements.toml`.

## 7.2 Multiple matches

When multiple rules match, OpenAI documents the restrictive decision order as:

```text
forbidden > prompt > allow
```

## 7.3 Native rule verifier

OpenAI provides:

```text
codex execpolicy check
```

The command emits JSON containing the strictest decision and matching rules. Multiple `--rules` arguments can be supplied to combine rule files.

---

# 8. Plugin protocol

## 8.1 Required plugin entry point

Every plugin has a manifest at:

```text
.codex-plugin/plugin.json
```

OpenAI describes this as the required plugin manifest / entry point.

The documented plugin root may also contain:

```text
skills/
hooks/
.app.json
.mcp.json
assets/
```

Only `plugin.json` belongs inside `.codex-plugin/`; the other components remain at the plugin root.

## 8.2 Plugin-bundled files

Typical documented structure:

```text
my-plugin/
  .codex-plugin/
    plugin.json
  skills/
    my-skill/
      SKILL.md
  hooks/
    hooks.json
  .app.json
  .mcp.json
  assets/
```

## 8.3 Marketplace files

OpenAI documents local marketplace files at:

```text
$REPO_ROOT/.agents/plugins/marketplace.json
~/.agents/plugins/marketplace.json
```

A legacy-compatible repo marketplace path is also documented:

```text
$REPO_ROOT/.claude-plugin/marketplace.json
```

Marketplace entries point to plugin locations; the example plugin directories themselves are not fixed requirements.

## 8.4 Installed plugin copy

For marketplace-installed local plugins, OpenAI documents an installed cache path form:

```text
~/.codex/plugins/cache/$MARKETPLACE_NAME/$PLUGIN_NAME/$VERSION/
```

The installed copy is loaded from the cache rather than directly from the marketplace entry.

## 8.5 Plugin enabled state

OpenAI states that each plugin can be enabled or disabled individually, with state stored in:

```text
~/.codex/config.toml
```

Existence of a plugin directory or manifest therefore does not alone prove that the plugin is enabled.

## 8.6 Native plugin diagnostics

OpenAI documents:

```text
codex plugin list --json
```

which reports installed and available entries, including fields such as `installed`, `enabled`, `source`, version, marketplace information, install policy, and auth policy.

OpenAI also documents:

```text
codex plugin marketplace list --json
```

for the marketplace sources Codex is currently considering and each marketplace root path.

---

# 9. Runtime diagnostic interfaces documented by OpenAI

These are official Codex runtime observations that Phase 3 can later use instead of inferring state from filenames alone.

## 9.1 `codex doctor`

```text
codex doctor
```

OpenAI documents this as a local diagnostic report covering installation, configuration, authentication, runtime, Git, terminal, app-server, and thread inventory health.

## 9.2 `/debug-config`

```text
/debug-config
```

OpenAI says to review:

- config layer order (shown lowest precedence first)
- on/off state
- policy sources

It is specifically documented for debugging why an effective setting differs from `config.toml`.

## 9.3 `--strict-config`

```text
--strict-config
```

OpenAI documents this option as causing an error when `config.toml` contains fields the installed Codex version does not recognize.

This makes installed-version compatibility mechanically observable.

## 9.4 `codex debug prompt-input`

```text
codex debug prompt-input
```

OpenAI documents it as rendering the model-visible prompt input list as JSON.

This is relevant to effective instruction verification, including instruction material derived from AGENTS discovery.

## 9.5 `/hooks`

```text
/hooks
```

Used to inspect hook sources, review changed/new hooks, trust them, and disable individual non-managed hooks.

## 9.6 `codex execpolicy check`

```text
codex execpolicy check
```

Uses Codex’s documented rule evaluator and reports matching rules plus the strictest decision.

## 9.7 `codex plugin list --json`

```text
codex plugin list --json
```

Reports plugin installed/enabled state and source metadata.

## 9.8 `codex plugin marketplace list --json`

```text
codex plugin marketplace list --json
```

Reports marketplace sources currently considered and root paths.

## 9.9 `codex features list`

```text
codex features list
```

OpenAI documents this as showing known feature flags, maturity stage, and effective state.

This is relevant when a feature gate changes whether an otherwise valid configuration is active.

---

# 10. File classes already encountered by Milestone 2

The Phase 2 scanner has encountered or discussed these concrete names. Phase 3 must not treat them all as the same protocol class.

| Name | Official protocol role relevant here |
|---|---|
| `config.toml` | Config layer; precedence rules apply. |
| `<profile>.config.toml` | Selected profile config layer. |
| `AGENTS.md` | Global/project instruction discovery chain. |
| `AGENTS.override.md` | Higher-priority instruction filename at the same discovery level. |
| fallback project instruction filename | Dynamic list from `project_doc_fallback_filenames`. |
| `SKILL.md` | Required skill definition file. |
| `agents/openai.yaml` | Optional skill invocation/UI/dependency metadata. |
| `hooks.json` | Hook source adjacent to active config layer. |
| `hooks/hooks.json` | Default plugin-bundled hook location. |
| `*.rules` | Execpolicy rule file under an active layer’s `rules/`. |
| `.codex-plugin/plugin.json` | Required plugin manifest. |
| `.app.json` | Optional plugin registered MCP mapping. |
| `.mcp.json` | Optional bundled plugin MCP configuration. |
| `marketplace.json` | Local plugin marketplace catalog. |
| `requirements.toml` | Managed requirements/policy source; may define managed hooks and restrictive rules. |
| role config file | Dynamic path from `agents.<name>.config_file`. |
| model instruction file | Dynamic path from `model_instructions_file`. |
| `auth.json` | Codex authentication/state file; not a config-precedence layer. |
| `history.jsonl` | Codex history/state file; not a config-precedence layer. |
| `pet.json` | Custom pet asset/config file; not a config-precedence layer. |
| `config-schema.json` | Schema/reference artifact used to validate configuration structure; not itself an ordinary active `config.toml` layer. |

---

# 11. Protocol consequences for verification

The official rules above imply the following distinctions. These are not interchangeable:

```text
FOUND
PARSEABLE
RECOGNIZED_FOR_INSTALLED_VERSION
IN_RECOGNIZED_LOCATION
ACTIVE_LAYER
SELECTED_BY_PRECEDENCE
TRUSTED
ENABLED
MODEL_VISIBLE
RUNTIME_EFFECTIVE
```

Examples:

- A valid `.codex/config.toml` in an untrusted project is not an active project config layer.
- A valid profile file is not the selected profile unless that profile is selected.
- An `AGENTS.md` beside `AGENTS.override.md` at the same directory level is not the selected instruction file for that level.
- A valid non-managed hook may be discovered but skipped until its current definition is trusted.
- A valid `SKILL.md` may be disabled by `[[skills.config]]`.
- A plugin manifest may be valid while the installed plugin is disabled.
- A `.rules` file may be valid but irrelevant if it is not under an active rule/config layer for the current run.
- A syntactically valid `config.toml` may contain fields unknown to the installed Codex version; `--strict-config` exposes this condition.

---

# 12. Phase 3 input context required before an “effective” verdict

The official protocols depend on runtime context. A deterministic verifier cannot issue a final effective/not-effective verdict without resolving at least:

```text
installed Codex version
effective user / HOME
CODEX_HOME
current working directory
project root
project trust state
selected profile
CLI --config overrides
feature states
plugin installed/enabled state
hook trust state
```

This document intentionally stops at the official protocol boundary. Phase 3 implementation must consume these facts and reproduce or query the documented Codex behavior rather than replace it with heuristic ranking.
