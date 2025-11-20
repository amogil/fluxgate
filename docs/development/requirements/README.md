# Fluxgate Requirements - Single Source of Truth

**This is the single entry point for all requirements-related information. Always start here when working with requirements.**

## Quick Start: Validation

There are **two types of validation**:

- **`make validate`** - Quick validation (unit tests only). Use during development for fast feedback.
- **`make full-validate`** - Full validation (unit + functional tests). Use before completing work for final verification.

See [How to Validate Changes](#how-to-validate-changes) for details.

## Table of Contents

1. [How Requirements Are Structured](#how-requirements-are-structured)
2. [How to Find Requirements](#how-to-find-requirements)
3. [How to Update Requirements](#how-to-update-requirements)
4. [How to Find Tests](#how-to-find-tests)
5. [How to Write Tests](#how-to-write-tests)
6. [How to Validate Changes](#how-to-validate-changes)
7. [Automated and Manual Checks](#automated-and-manual-checks)
8. [Quick Reference](#quick-reference)

---

## How Requirements Are Structured

### File Organization

Requirements are organized in separate files by functional area:

- `00-general.md` - General principles (G1-G11)
- `01-performance.md` - Performance requirements (P1-P4)
- `02-functional.md` - Functional requirements (F1-F24)
- `03-configuration.md` - Configuration management (C1-C17)
- `04-testing.md` - Testing requirements (T1-T2, UT1-UT4, FT1-FT7)
- `05-cli.md` - Command-line interface (CLI1-CLI4)
- `06-operational.md` - Operational requirements (OP1-OP2)
- `07-observability.md` - Observability requirements (O1-O9)

### Requirement Format

Each requirement follows this structure:

```markdown
**F2.** The requirement description...

**Tags:** `tag1`, `tag2`, `tag3`

**Related Requirements:**
- F3: Related requirement description
- C8: Another related requirement
```

### Requirement Categories

- **G** - General principles
- **P** - Performance requirements
- **F** - Functional requirements
- **C** - Configuration requirements
- **T** - Testing requirements (general)
- **UT** - Unit test requirements
- **FT** - Functional test requirements
- **CLI** - CLI requirements
- **OP** - Operational requirements
- **O** - Observability requirements

### Semantic Tags

Each requirement has semantic tags for categorization. Common tags:

- **Core Functionality:** `authentication`, `bearer-auth`, `jwt-auth`, `routing`, `path-matching`, `request-forwarding`, `response-forwarding`, `streaming`, `http-protocol`, `header-preservation`
- **Configuration:** `config-loading`, `config-validation`, `hot-reload`, `cli`
- **Error Handling:** `error-handling`, `http-400`, `http-401`, `http-404`, `http-501`, `http-502`, `http-503`, `http-504`, `http-505`, `http-responses`, `response-delivery`
- **Performance:** `performance`, `latency`, `scaling`, `architecture`, `memory-management`, `timeout`
- **Security:** `security`
- **Observability:** `logging`, `observability`
- **Connection Management:** `connection-management`, `shutdown`
- **Code Quality:** `documentation`, `code-style`, `formatting`, `traceability`, `code-organization`, `maintenance`
- **Testing:** `testing`, `test-coverage`, `unit-tests`, `functional-tests`
- **Deployment:** `platform`, `deployment`, `build-system`

---

## How to Find Requirements

### By Requirement ID

**Automated (recommended):**
```bash
cargo run --bin find-requirement F2
# or
make find-requirement REQ=F2
```

**Manual:**
1. Identify category (G, P, F, C, T, UT, FT, CLI, OP, O)
2. Open corresponding file (e.g., `02-functional.md` for F1-F24)
3. Search for requirement ID: `grep "^\\*\\*F2\\." docs/development/requirements/02-functional.md`

### By Semantic Tag

**Automated (recommended):**
```bash
cargo run --bin find-requirement -- --tag authentication
cargo run --bin find-requirement -- --tag security --show-code
# or
make find-requirement TAG=authentication
```

**Manual:**
```bash
grep -r "Tags:" docs/development/requirements/ | grep "authentication"
```

### By Related Requirements

**Automated:**
```bash
# Find requirement first
cargo run --bin find-requirement F2

# Then check "Related Requirements" section in the output
# Or search for references
grep -r "F2" docs/development/requirements/
```

**Manual:**
1. Find the requirement using ID or tag
2. Check the "Related Requirements" section in the requirement
3. Review those requirements

### By Feature Area

**Automated:**
```bash
# Find all requirements for a feature using tags
cargo run --bin find-requirement -- --tag jwt-auth
cargo run --bin find-requirement -- --tag hot-reload
```

**Manual:**
- Check feature documentation: `docs/development/features/`
- Use tags to find related requirements

### Finding Requirements Referenced in Code

**Automated:**
```bash
# Find where requirement F2 is referenced
grep -r "Requirement.*F2" src/ tests/
```

**Manual:**
- Search codebase for requirement ID
- Check test files for requirement references

---

## How to Update Requirements

### Before Making Changes

1. **Find all related requirements:**
   ```bash
   # If you know the requirement ID
   cargo run --bin find-requirement F2
   
   # If you know the area (use tags)
   cargo run --bin find-requirement -- --tag authentication
   ```

2. **Check current implementation:**
   ```bash
   # Find code references
   grep -r "Requirement.*F2" src/ tests/
   
   # Find test coverage
   grep -r "# Requirements.*F2" tests/
   ```

3. **Review related requirements:**
   - Check "Related Requirements" section
   - Use tags to find all related requirements
   - Review feature documentation

### Making Changes

1. **Update requirement text** in the appropriate file
2. **Update tags** if functionality changes
3. **Update "Related Requirements"** if relationships change
4. **Update code references** if requirement ID changes

### Validation Checklist

After updating requirements, verify:

```bash
# 1. Requirements are complete and consistent
make validate-requirements-quality

# 2. All tags are documented
grep -r "Tags:" docs/development/requirements/*.md | grep -v "README.md" | \
  sed 's/.*Tags: //' | sed 's/`//g' | tr ',' '\n' | sed 's/^ *//' | \
  sort -u > /tmp/used_tags.txt
grep -A 200 "Common tags" docs/development/requirements/README.md | \
  grep "^- \`" | sed 's/^- \`//' | sed 's/\`.*//' | sort > /tmp/readme_tags.txt
comm -23 /tmp/used_tags.txt /tmp/readme_tags.txt  # Should be empty

# 3. Cross-references are valid
make validate-requirements-quality

# 4. No keys/secrets in examples
grep -r "sk-" docs/development/requirements/ config/ | grep -v "REPLACE"
grep -r "api[_-]key" docs/development/requirements/ config/ | grep -v "REPLACE\|placeholder\|example"

# 5. User documentation is updated (if requirements affect user-facing behavior)
# Check if changes require updates to:
# - README.md (root) - for high-level changes
# - docs/user/configuration.md - for configuration changes
# - docs/user/configuration.md - for authentication changes (see Client API Keys section)
# - docs/user/logging.md - for logging/observability changes
```

---

## How to Find Tests

### By Requirement ID

**Automated:**
```bash
# Find tests covering requirement F2
grep -r "# Requirements.*F2" tests/
# or more specific
grep -r "Requirements.*F2" tests/unit/ tests/functional/
```

**Manual:**
1. Find requirement using `cargo run --bin find-requirement F2`
2. Check test files mentioned in requirement's "Unit Tests" section
3. Search for requirement ID in test files

### By Semantic Tag

**Automated:**
```bash
# Find all tests for authentication
grep -r "# Requirements" tests/ | grep -E "authentication|bearer-auth|jwt-auth" | \
  grep -o "Requirements: [^#]*" | sort -u
```

**Manual:**
1. Find requirements with tag: `cargo run --bin find-requirement -- --tag authentication`
2. Find tests for those requirements
3. Check feature documentation for test organization

### By Test Type

**Unit tests:**
```bash
# Find unit tests
find tests/unit/ -name "*.rs" -exec grep -l "# Requirements" {} \;
```

**Functional tests:**
```bash
# Find functional tests
find tests/functional/ -name "*.rs" -exec grep -l "# Requirements" {} \;
```

### By Feature Area

**Automated:**
```bash
# Find tests for JWT authentication
grep -r "jwt-auth\|jwt-header\|jwt-signature" tests/ | grep "# Requirements"
```

**Manual:**
- Check feature documentation: `docs/development/features/`
- Review test organization in `04-testing.md`

### Finding Test Files for a Requirement

**Automated:**
```bash
# Find all test files that mention requirement F2
grep -l "F2" tests/unit/*.rs tests/functional/*.rs 2>/dev/null
```

**Manual:**
- Check requirement's "Unit Tests" section
- Review test organization documentation

---

## How to Write Tests

### Test Documentation Format

**Unit tests:**
```rust
/// # Requirements: F2, F3
/// 
/// Precondition: Valid configuration with upstreams and API keys
/// Action: Send request with valid API key matching request_path
/// Expected behavior: Request proxied with Authorization replaced, routed to correct upstream
#[test]
fn test_authentication_and_routing() {
    // Test implementation
}
```

**Functional tests:**
```rust
/// # Requirements: F2, F3
/// 
/// Precondition: Valid config with upstreams and API keys
/// Action: Send request with valid API key matching request_path
/// Expected behavior: Request proxied with Authorization replaced, routed to correct upstream
#[tokio::test]
async fn proxy_authenticates_and_routes_to_permitted_upstream() {
    // Test implementation
}
```

### Test Organization

- **Unit tests:** `tests/unit/` - Organized by functional area
  - **CRITICAL:** Unit tests MUST be placed in `tests/unit/`, NOT in `src/` with `#[cfg(test)]` modules
  - All unit tests must be in separate files under `tests/unit/` directory
  - Never use `#[cfg(test)] mod tests` in source files - this violates UT1 requirement
- **Functional tests:** `tests/functional/` - Organized by feature

### Test Helpers

**Always use helpers from `tests/unit/common.rs`** - Never hardcode configuration structures!

See `tests/unit/common.rs` for available test helpers.

### Requirements for New Tests

1. **Place tests in correct location:**
   - **Unit tests:** MUST be in `tests/unit/` directory, NOT in `src/` files
   - **Functional tests:** MUST be in `tests/functional/` directory
   - **Never** use `#[cfg(test)] mod tests` in source files - this violates UT1 requirement
   - All unit tests must be in separate files under `tests/unit/` organized by functional area

2. **Document requirements covered:**
   ```rust
   /// # Requirements: F2, F3
   ```

3. **Document test structure:**
   - Precondition
   - Action
   - Expected behavior

4. **Use test helpers** from `tests/unit/common.rs`

5. **Check for tests in wrong location:**
   ```bash
   # Verify no tests are in src/ files (should be empty)
   grep -r "#\[cfg(test)\]" src/
   grep -r "#\[test\]" src/
   grep -r "mod tests" src/
   
   # If you find tests in src/, move them to tests/unit/ directory
   ```

6. **Check for duplication and hardcoded configs:**
   ```bash
   # Find hardcoded configs (should be empty or minimal)
   # Note: Some tests may need to hardcode configs for testing invalid values
   grep -r "Config {" tests/unit/ | grep -v "test_config\|test_server_config\|Config::default"
   grep -r "ServerConfig {" tests/unit/ | grep -v "test_server_config"
   grep -r "UpstreamEntry {" tests/unit/ | grep -v "test_upstream_entry"
   grep -r "ApiKeysConfig {" tests/unit/ | grep -v "test_api_keys_config"
   
   # If you find hardcoded configs, replace them with helpers from tests/unit/common.rs
   ```

7. **Verify functional tests are documented:**
   ```bash
   # Verify all functional tests are mentioned in tables (FT6 requirement)
   # Extract test names from code
   grep -E '^fn |^async fn ' tests/functional/*.rs | grep -v '//' | sed 's/.*fn //' | sed 's/async fn //' | sed 's/(.*//' | grep -vE '^(assert_|capture_|spawn_|help_|logging_|ignores_|run_with|unknown_|active_connections|new_requests|reload_|requests_during|reload_with|simple_|create_|current_|allocate_|run_async|reload_socket)' | sort -u > /tmp/code_tests.txt
   # Extract test names from documentation tables
   grep -E '^\| `[a-z_]' docs/development/requirements/04-testing.md | awk -F'`' '{print $2}' | sort -u > /tmp/doc_tests.txt
   # Compare
   comm -23 /tmp/code_tests.txt /tmp/doc_tests.txt
   # Should be empty - all tests must be in tables
   ```

8. **Verify coverage:**
   ```bash
   make validate-requirements-coverage
   ```

---

## How to Validate Changes

There are **two types of validation** with different purposes:

### 1. Quick Validation (`make validate`)

**Purpose:** Fast validation for intermediate checks during development.

**When to use:**
- During development for quick feedback
- After making code changes to verify basic correctness
- Before committing intermediate work

**What it includes:**
- Code formatting (`cargo fmt`)
- Compilation check (`cargo check`)
- Requirements validation (`make validate-requirements`)
- Linting (`cargo clippy`)
- Unit tests (`cargo test --test unit`)

**What it does NOT include:**
- Functional tests (these require Docker and take longer)

**Command:**
```bash
make validate
```

### 2. Full Validation (`make full-validate`)

**Purpose:** Complete validation including all tests for final verification.

**When to use:**
- **Before completing work** - final check before marking work as done
- When you need to verify end-to-end functionality
- Before submitting changes for review

**What it includes:**
- Everything from `make validate` (formatting, compilation, requirements, linting, unit tests)
- **Plus:** Functional tests in Docker (`./run-tests-docker.sh`)

**Command:**
```bash
make full-validate
```

**Note:** Full validation takes longer because it builds a Docker image and runs functional tests, but provides complete coverage.

### Requirements Validation

**Automated:**
```bash
# Quality: completeness, consistency, cross-references
make validate-requirements-quality

# Coverage: test coverage and code references
make validate-requirements-coverage

# Both
make validate-requirements
```

### Manual Validation Steps

1. **Review related requirements:**
   ```bash
   # Find all related requirements using tags
   cargo run --bin find-requirement -- --tag authentication
   ```

2. **Check test coverage:**
   ```bash
   # Find tests for requirement
   grep -r "# Requirements.*F2" tests/
   ```

3. **Verify code references:**
   ```bash
   # Find code references
   grep -r "Requirement.*F2" src/
   ```

4. **Check documentation:**
   - Update README.md if behavior changes (keep it focused on selling points)
   - Update user documentation in `docs/user/` if changes affect:
     - Configuration (`docs/user/configuration.md`)
     - Authentication (`docs/user/configuration.md#client-api-keys`)
     - Logging (`docs/user/logging.md`)
   - Update feature docs in `docs/development/features/` if requirements change
   - Verify examples are accurate

---

## Automated and Manual Checks

### Before Starting Work

**Automated:**
```bash
# Find related requirements
cargo run --bin find-requirement -- --tag <area>

# Check current implementation
grep -r "Requirement.*<REQ_ID>" src/ tests/
```

**Manual:**
- Read requirement and "Related Requirements" section
- Review feature documentation
- Understand current implementation

### During Development

**Automated:**
```bash
# Quick validation (unit tests only) - use for intermediate checks
make validate

# Or run individual checks:
# Check compilation
cargo check

# Run specific tests
cargo test --test unit test_name

# Format code
cargo fmt
```

**Manual:**
- Reference requirements in code: `// Requirement: F2`
- Reference requirements in tests: `/// # Requirements: F2, F3`
- Use test helpers from `tests/unit/common.rs`

### Before Completing Work

**Automated (run all):**
```bash
# Final validation - includes functional tests
make full-validate
```

**Note:** Use `make validate` for intermediate checks during development. Use `make full-validate` for final verification before completing work.

**Manual checklist:**
- [ ] All related requirements reviewed
- [ ] Requirements referenced in code
- [ ] Requirements referenced in tests
- [ ] Tests updated/added
- [ ] All functional tests are documented in tables (FT6 requirement)
- [ ] User documentation updated (if changes affect user-facing behavior):
  - [ ] README.md (root) - updated for high-level changes
  - [ ] docs/user/configuration.md - updated for configuration changes
  - [ ] docs/user/configuration.md - updated for authentication changes
  - [ ] docs/user/logging.md - updated for logging/observability changes
- [ ] No keys/secrets in code or examples
- [ ] Security requirements checked (if applicable)
- [ ] Performance requirements checked (if applicable)

### After Completing Work

**Automated:**
```bash
# Final validation (includes functional tests)
make full-validate

# Check coverage
make validate-requirements-coverage
```

**Manual:**
- Review checklist in this file
- Verify all items are checked
- Ensure documentation is accurate

---

## Quick Reference

### Essential Commands

```bash
# Find requirement by ID
make find-requirement REQ=F2

# Find requirements by tag
make find-requirement TAG=authentication

# Quick validation (unit tests only) - use during development
make validate

# Full validation (unit + functional tests) - use before completing work
make full-validate

# Requirements validation
make validate-requirements
```

### Key File Locations

- **Requirements:** `docs/development/requirements/`
- **Test helpers:** `tests/unit/common.rs`
- **Feature docs:** `docs/development/features/`

For detailed commands and workflows, see the sections above.

---

**Remember: Always start with this README when working with requirements!**
