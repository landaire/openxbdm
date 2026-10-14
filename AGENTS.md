# AGENTS.md

Guidance for agents working in the openxbdm repository. These rules override default behavior and apply to every crate unless a crate-local AGENTS.md says otherwise.

## High-Level

- Behaviors must match original, but the implementation does not need to match.
- We have limited system RAM. We need to prioritize small binary size over all else.

## Reverse Engineering

- This is a greenfield project. We do not make assumptions based on any public reporting or source code. We do everything clean room.
- When reverse engineering the source material, keep a record of major components / moving parts in docs/re-notes, organized by feature
- Make a global list of all known features and how much has been reverse engineered.
- Make a ledger of weird nuance and odd behaviors that should have care when re-implemented.
- If a function's purpose is not known, label it as such. If it's known but not 1:1 reverse engineered, label it as such.
- Rename functions and add type definitions where possible in the disassembler's source database.
- If it helps for documentation, add pseudocode, but the implementation should be ported appropriately to the target language as a fresh architecture.
- You should write a sample C function and try compiling it in isolation to see if the disassembled output is close to the one you're reverse engineering if you cannot get it 1:1
- No heuristics. No shortcuts that "win" but are imprecise. No exceptions.

## Development

- We primarily use buck2 for building, testing, etc., but all code should compile with Cargo.
- Vendor 3rd party code.
- Code should be explicitly cross-platform.
- No cutting corners. Do things _the correct way_. Do not, for example, read an entire file into memory to parse it. We do not know how large files may be and this may consume a lot of memory. Instead, mmap it.
- All tests, clippy, fixers get primarily run through buck2 to the best of our ability. Reference G:\dev\rarchive for test harnessing.
- Nothing that ties simulation to framerate, if possible. i.e. physics code should not be framerate-driven.

### Binary Readers

This section pertains to any readers of binary data. For example, game data, 3D models, video formats, etc.

- Use `winnow`, `thiserror`, and `rootcause` as core crates for binary readers.
- The core should be sans-io, supporting both async and sync interfaces with a runtime-agnostic async runtime. Reference https://github.com/landaire/enfusion\_tools as an example.
- The core should avoid allocations as well, and be `no_std`. The sync/async do not have this requirement, but the absolute core reader/writers should meet this requirement.
- The frontend should be a CLI using `clap`
- For any time related fields, use `jiff`
- Checksum-checked readers should be the default, but optional. Users should have the ability to inspect the calculated vs expected checksum. This could probably be implemented via typestate pattern or something
- Use `tracing` for logging - include spans where appropriate
- Add a `dhat` feature which allows for instrumenting memory allocations
- We use bevy as our game engine.
- For filesystems, if it makes sense, let's use a proper VFS implementation using the `vfs` crate. Refer to https://github.com/landaire/wows-toolkit/blob/main/crates/wowsunpack/src/data/idx_vfs.rs and/or https://github.com/landaire/enfusion_tools/tree/main/crates/enfusion_pak
- No corner cutting on dev work. For example, an async implementation should be actually async and not calling `block_on()` with the sync implementation under the hood.

## Version control

- The repo is jj-colocated. Use `jj`, not `git`, as the authoritative interface.
- Never append `Co-Authored-By` or any AI attribution to commit messages.
- Make focused commits, one per logical change or milestone.
- Changes should be rolled into one commit where it makes sense, as if sending patches to Phabricator (stacked diffs) or Gerrit.
- When working on a sequence of uncommit changes, prefer to edit prior commits to contain new requirements rather than creating a new commit.
- One isolated change per commit. Each commit should stand on its own and be reviewable.

## Types and data modeling

- Prefer newtypes over raw primitives for domain values, even when the value arrives as a primitive. Wrap identifiers and any quantities that could be confused with each other (angles together with their unit, bitflags, durations, indices, weapon groups) in distinct newtypes so the type system rejects mixing them. Reuse existing newtypes (`wowsunpack` `TeamId`, `GameParamId`, `EntityId`, etc.) instead of storing their raw inner value.
- **IMPORTANT**: Model "absent" or "unlimited" with `Option` or an enum, never sentinel values like `-1`, `0`, or empty string.
- Bubble `Option` and `Result` up as far as practical. Resolve them at the boundary where there is enough context to handle them correctly.

## Defaults and missing data

- Scrutinize every `.unwrap_or`, `.unwrap_or_default`, `.unwrap_or_else`, and `Default` applied to parsed or possibly-missing data.
- Do not paper over malformed or absent input with a default unless that default is genuinely correct. When it is, document why at the call site. Otherwise propagate the error or the option.

## Errors

- Use strong `thiserror` enums with structured fields.
- Never match on an error's `Display` or `Debug` string to recover data. If meaningful data is only reachable by parsing a formatted string, the error type is wrong; add a field.
- Use `rootcause` to attach context as errors cross boundaries.

## Comments

- Comments explain non-obvious intent only. Keep them terse and DRY.
- No salesmanship or filler wording.
- No historical framing ("now X", "was Y, now Z"). Describe current behavior.
- No numbered step-recaps of the implementation. Short WHY lines only.

## Tests

- Prefer snapshot tests in scenarios where data is being deserialized or parsed to assert correctness
- Tautological tests considered harmful.

## Text and formatting
- ASCII only in code, comments, UI strings, and commit messages. No emdash, endash, ellipsis, arrows, or other unicode symbols. Unicode words and phrases are fine -- just no symbols.
- No separator or banner comments (`// ---`, `// ===`, long dashed/equals rules, section dividers). Structure code with modules, functions, and blank lines, not comment dividers.
- Use only technical language you'd find in an IBM manual from the 1970s. No slang, casual shorthand, cute or clever names, no borrowed words from chat culture. Be succinct and clear. For example, do not use phrases like "golden snapshot". Another example: a script which updates build data should be named `update_build_data.sh` and not `push_build_data.sh`.
- Do not include unnecessary details. No, "The X describes the Y" type phrases or "caveats" unless asked for it.
- Commit messages should be short. Do not include unnecessary details in the longform commit message. Generally the commit details should just not even be included unless there is necessary context behind a change. Otherwise the commit title should speak for itself.


## Review

- At the end of each milestone, run an adversarial code review with a fresh subagent before committing. For ECS work for example the reviewer must be framed as a bevy_ecs/ECS expert and instructed to challenge the design itself (component vs resource boundaries, query patterns, archetype/iteration-order determinism, entity lifecycle), not just surface code quality.
