# General Principles

G1. All project documentation and in-code comments must be written in English.

**Tags:** `documentation`, `code-style`

G2. The `README.md` must remain up to date; any change to code or documentation must update the README to reflect the
new behaviour.

**Tags:** `documentation`, `maintenance`

G3. The proxy is intended to run on modern Linux distributions (for example, Ubuntu LTS or compatible) and must function
correctly in such environments.

**Tags:** `platform`, `deployment`

G4. All source files must be formatted with `rustfmt` before committing changes.

**Tags:** `code-style`, `formatting`

G5. Configuration must be kept under `config/` and modeled with strongly typed structures.

**Tags:** `config-loading`, `code-style`

G6. Use `tracing` for logging and include structured fields in log messages.

**Tags:** `logging`, `observability`

G7. Functional tests for proxy request flows must be added under `tests/functional/`.

**Tags:** `testing`, `functional-tests`

G8. Public modules must be documented with `//!` doc comments that summarize their responsibilities.

**Tags:** `documentation`, `code-style`

G9. Requirements must be referenced in code using `// Requirement: F2` or `/// Requirement: F2` format.

**Tags:** `documentation`, `code-style`, `traceability`

G10. Requirements must be referenced in tests using `/// # Requirements: F2, F3` format.

**Tags:** `documentation`, `testing`, `traceability`

G11. All requirements must be numbered using a consistent format (e.g., F1, F2, F3 for functional requirements, C1, C2, C3
for configuration requirements, etc.) and ordered sequentially by their numeric identifiers within each category. Each
requirement must have a unique identifier that can be referenced in code and documentation. Requirements must appear in
ascending order (e.g., F1, F2, F3, ...) without gaps or out-of-order placements, regardless of their logical grouping
in sections or subsections.

**Tags:** `documentation`, `traceability`

