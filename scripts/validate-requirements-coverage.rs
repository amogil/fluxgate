//! Unified script to validate requirements coverage and reference validity.
//!
//! This script performs:
//! - Coverage validation: Checks that all requirements are covered by code/tests
//! - Reference validation: Validates that all requirement references in code are valid
//!
//! Usage: cargo run --bin validate-requirements-coverage

use std::collections::HashSet;
use std::fs;
use std::path::Path;

fn main() {
    let requirements_dir = Path::new("docs/development/requirements");
    let tests_dir = Path::new("tests");
    let src_dir = Path::new("src");

    println!("🔍 Validating requirements coverage and references...\n");

    // Parse all requirements
    let requirements = parse_requirements(requirements_dir);
    println!("📋 Found {} requirements\n", requirements.len());

    // Find requirement references in code and tests
    let (code_refs, code_refs_detailed) = find_requirement_references(src_dir);
    let (test_refs, test_refs_detailed) = find_requirement_references(tests_dir);

    println!(
        "💻 Found {} requirement references in code",
        code_refs.len()
    );
    println!(
        "🧪 Found {} requirement references in tests\n",
        test_refs.len()
    );

    // Check reference validity
    let mut invalid_refs = Vec::new();
    let mut valid_refs = Vec::new();

    for (file, line, req_id) in code_refs_detailed.iter().chain(test_refs_detailed.iter()) {
        if requirements.contains(req_id) {
            valid_refs.push((file.clone(), *line, req_id.clone()));
        } else {
            invalid_refs.push((file.clone(), *line, req_id.clone()));
        }
    }

    // Report reference validity
    if !invalid_refs.is_empty() {
        println!("❌ Invalid references: {}", invalid_refs.len());
        for (file, line, req_id) in &invalid_refs {
            println!("  - {}:{} -> {} (not found)", file, line, req_id);
        }
    } else {
        println!("✅ All references are valid");
    }

    // Meta-requirements that don't need code references
    let meta_requirements: HashSet<&str> = [
        "G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "G9",
        "G10", // General principles (documentation, formatting, structure)
        "T1", "T2", // Testing requirements (covered by test structure)
        "UT1", "UT2", "UT3", "UT4", // Unit test requirements (covered by test structure)
        "FT1", "FT2", "FT3", "FT4", "FT5", "FT6",
        "FT7", // Functional test requirements (covered by test structure)
        "OP3", // Docker image requirement (covered by Dockerfile)
    ]
    .iter()
    .cloned()
    .collect();

    // Check coverage
    let mut uncovered = Vec::new();
    let mut covered = Vec::new();

    for req_id in &requirements {
        // Skip meta-requirements
        if meta_requirements.contains(req_id.as_str()) {
            continue;
        }

        let in_code = code_refs.contains(req_id);
        let in_tests = test_refs.contains(req_id);

        if in_code || in_tests {
            covered.push((req_id.clone(), in_code, in_tests));
        } else {
            uncovered.push(req_id.clone());
        }
    }

    // Report coverage
    println!("\n✅ Covered requirements: {}", covered.len());
    for (req_id, in_code, in_tests) in &covered {
        let mut sources = Vec::new();
        if *in_code {
            sources.push("code");
        }
        if *in_tests {
            sources.push("tests");
        }
        println!("  - {} ({})", req_id, sources.join(", "));
    }

    // Final result
    println!("\n{}", "=".repeat(60));
    if invalid_refs.is_empty() && uncovered.is_empty() {
        println!("✅ ALL VALIDATIONS PASSED");
        println!("   - All references are valid");
        println!("   - All requirements are covered");
        std::process::exit(0);
    } else {
        if !invalid_refs.is_empty() {
            println!("❌ Invalid references found: {}", invalid_refs.len());
        }
        if !uncovered.is_empty() {
            println!("❌ Uncovered requirements: {}", uncovered.len());
            for req_id in &uncovered {
                println!("  - {}", req_id);
            }
        }
        std::process::exit(1);
    }
}

fn parse_requirements(dir: &Path) -> HashSet<String> {
    let mut requirements = HashSet::new();

    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("md") {
            let content = fs::read_to_string(&path).unwrap();
            // Extract requirement IDs (G1, P1, F1, C1, etc.)
            for line in content.lines() {
                let chars: Vec<char> = line.chars().collect();
                let mut i = 0;
                while i < chars.len() {
                    // Check for single-letter prefixes (G, P, F, C, T, O)
                    if i + 1 < chars.len()
                        && matches!(chars[i], 'G' | 'P' | 'F' | 'C' | 'T' | 'O')
                        && chars[i + 1].is_ascii_digit()
                    {
                        // Skip 'T' if it's part of an ISO 8601 date/time (e.g., "1970-01-01T00:00:00Z")
                        // Check if 'T' is preceded by a date pattern (digits-dash-digits-dash-digits-T)
                        // or followed by time pattern (T + digits + colon)
                        if chars[i] == 'T' {
                            // Check if T is part of ISO 8601 date/time format
                            let is_iso_date = i >= 10
                                && chars[i - 1].is_ascii_digit()
                                && chars[i - 2] == '-'
                                && chars[i - 3].is_ascii_digit()
                                && chars[i - 4].is_ascii_digit()
                                && chars[i - 5] == '-'
                                && chars[i - 6].is_ascii_digit()
                                && chars[i - 7].is_ascii_digit()
                                && chars[i - 8].is_ascii_digit()
                                && chars[i - 9].is_ascii_digit();

                            // Check if T is followed by time pattern (digits + colon)
                            let mut num_end = i + 1;
                            while num_end < chars.len() && chars[num_end].is_ascii_digit() {
                                num_end += 1;
                            }
                            let is_iso_time = num_end < chars.len() && chars[num_end] == ':';

                            if is_iso_date || is_iso_time {
                                i += 1;
                                continue;
                            }
                        }

                        let mut num_end = i + 1;
                        while num_end < chars.len() && chars[num_end].is_ascii_digit() {
                            num_end += 1;
                        }
                        if num_end > i + 1 {
                            let req_id: String = chars[i..num_end].iter().collect();
                            requirements.insert(req_id);
                            i = num_end;
                            continue;
                        }
                    }

                    // Check for multi-letter prefixes (CLI, UT, FT, OP)
                    if i + 3 < chars.len() {
                        let prefix3: String = chars[i..i + 3].iter().collect();
                        if matches!(prefix3.as_str(), "CLI" | "UT" | "FT" | "OP")
                            && chars[i + 3].is_ascii_digit()
                        {
                            let mut num_end = i + 3;
                            while num_end < chars.len() && chars[num_end].is_ascii_digit() {
                                num_end += 1;
                            }
                            if num_end > i + 3 {
                                let req_id: String = chars[i..num_end].iter().collect();
                                requirements.insert(req_id);
                                i = num_end;
                                continue;
                            }
                        }
                    }

                    if i + 2 < chars.len() {
                        let prefix2: String = chars[i..i + 2].iter().collect();
                        if matches!(prefix2.as_str(), "UT" | "FT" | "OP")
                            && chars[i + 2].is_ascii_digit()
                        {
                            let mut num_end = i + 2;
                            while num_end < chars.len() && chars[num_end].is_ascii_digit() {
                                num_end += 1;
                            }
                            if num_end > i + 2 {
                                let req_id: String = chars[i..num_end].iter().collect();
                                requirements.insert(req_id);
                                i = num_end;
                                continue;
                            }
                        }
                    }
                    i += 1;
                }
            }
        }
    }

    requirements
}

fn find_requirement_references(dir: &Path) -> (HashSet<String>, Vec<(String, usize, String)>) {
    let mut references = HashSet::new();
    let mut detailed_refs = Vec::new();

    fn walk_dir(
        dir: &Path,
        references: &mut HashSet<String>,
        detailed_refs: &mut Vec<(String, usize, String)>,
    ) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();

            if path.is_dir() {
                walk_dir(&path, references, detailed_refs);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                let content = fs::read_to_string(&path).unwrap();
                let file_path = path.to_string_lossy().to_string();

                for (line_num, line) in content.lines().enumerate() {
                    if line.contains("Requirement") {
                        // Extract requirement IDs from lines like "// Requirement: F2" or "/// # Requirements: F1, F2"
                        let line_to_parse = if line.contains("# Requirements:") {
                            line.split("# Requirements:").nth(1).unwrap_or("")
                        } else if line.contains("Requirement:") {
                            line.split("Requirement:").nth(1).unwrap_or("")
                        } else {
                            continue;
                        };

                        let reqs_part = line_to_parse.trim();
                        if !reqs_part.is_empty() {
                            // Split by comma and extract IDs
                            for req_str in reqs_part.split(',') {
                                let req_str = req_str.trim();
                                // Extract ID pattern using char-based parsing
                                let chars: Vec<char> = req_str.chars().collect();
                                if chars.len() >= 2
                                    && matches!(chars[0], 'G' | 'P' | 'F' | 'C' | 'T' | 'O')
                                    && chars[1].is_ascii_digit()
                                {
                                    let mut num_end = 1;
                                    while num_end < chars.len() && chars[num_end].is_ascii_digit() {
                                        num_end += 1;
                                    }
                                    if num_end > 1 {
                                        let req_id: String = chars[..num_end].iter().collect();
                                        references.insert(req_id.clone());
                                        detailed_refs.push((
                                            file_path.clone(),
                                            line_num + 1,
                                            req_id,
                                        ));
                                    }
                                }
                                // Multi-letter prefixes
                                if chars.len() >= 3 {
                                    let prefix3: String = chars[..3].iter().collect();
                                    if matches!(prefix3.as_str(), "CLI" | "UT" | "FT" | "OP")
                                        && chars[3].is_ascii_digit()
                                    {
                                        let mut num_end = 3;
                                        while num_end < chars.len()
                                            && chars[num_end].is_ascii_digit()
                                        {
                                            num_end += 1;
                                        }
                                        if num_end > 3 {
                                            let req_id: String = chars[..num_end].iter().collect();
                                            references.insert(req_id.clone());
                                            detailed_refs.push((
                                                file_path.clone(),
                                                line_num + 1,
                                                req_id,
                                            ));
                                        }
                                    }
                                }
                                if chars.len() >= 2 {
                                    let prefix2: String = chars[..2].iter().collect();
                                    if matches!(prefix2.as_str(), "UT" | "FT" | "OP")
                                        && chars[2].is_ascii_digit()
                                    {
                                        let mut num_end = 2;
                                        while num_end < chars.len()
                                            && chars[num_end].is_ascii_digit()
                                        {
                                            num_end += 1;
                                        }
                                        if num_end > 2 {
                                            let req_id: String = chars[..num_end].iter().collect();
                                            references.insert(req_id.clone());
                                            detailed_refs.push((
                                                file_path.clone(),
                                                line_num + 1,
                                                req_id,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    walk_dir(dir, &mut references, &mut detailed_refs);
    (references, detailed_refs)
}
