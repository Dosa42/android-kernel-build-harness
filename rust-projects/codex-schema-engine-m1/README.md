# Codex Schema Engine — Milestone 1

Native Rust foundation for one narrow task: answer natural-language questions about the embedded OpenAI Codex `config-schema.json` using ChatGPT Codex OAuth and `gpt-5.6-sol`.

Milestone 1 contains the embedded schema viewer with syntax highlighting, ChatGPT OAuth + PKCE, direct Codex Responses request handling, explicit failures, and no tools/RAG/edit mode/API-key fallback.

The GitHub Actions build materializes the exact schema identified by SHA-256 `affe54cce9b9945ffd32d322415ff4cc844c62068c1190be6355580be4ca9350`, verifies 6,212 lines and 181,805 bytes, then compiles it into the release binary.
