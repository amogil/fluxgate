//! Script to find requirements by ID or tag.
//!
//! Usage:
//!   cargo run --bin find-requirement F2
//!   cargo run --bin find-requirement -- --tag authentication
//!   cargo run --bin find-requirement -- --tag security --show-code

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  cargo run --bin find-requirement <REQUIREMENT_ID>");
        eprintln!("  cargo run --bin find-requirement -- --tag <TAG> [--show-code]");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  cargo run --bin find-requirement F2");
        eprintln!("  cargo run --bin find-requirement -- --tag authentication");
        eprintln!("  cargo run --bin find-requirement -- --tag security --show-code");
        std::process::exit(1);
    }

    let requirements_dir = Path::new("docs/development/requirements");

    if args[1] == "--tag" {
        if args.len() < 3 {
            eprintln!("Error: --tag requires a tag name");
            std::process::exit(1);
        }
        let tag = &args[2];
        let show_code = args.contains(&"--show-code".to_string());
        find_by_tag(requirements_dir, tag, show_code);
    } else {
        let req_id = &args[1];
        find_by_id(requirements_dir, req_id);
    }
}

fn find_by_id(requirements_dir: &Path, req_id: &str) {
    println!("🔍 Searching for requirement: {}\n", req_id);

    let files = vec![
        "00-general.md",
        "01-performance.md",
        "02-functional.md",
        "03-configuration.md",
        "04-testing.md",
        "05-cli.md",
        "06-operational.md",
        "07-observability.md",
    ];

    for file in files {
        let path = requirements_dir.join(file);
        if !path.exists() {
            continue;
        }

        let content = fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = content.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if line.contains(&format!("**{}.**", req_id))
                || line.contains(&format!("{}.", req_id))
                || line.contains(&format!("**{}**", req_id))
            {
                println!("📄 Found in: {}\n", file);
                println!("{}", line);

                // Print next few lines for context
                let end = (i + 20).min(lines.len());
                for (j, line) in lines.iter().enumerate().skip(i + 1).take(end - i - 1) {
                    if line.trim().is_empty() && j > i + 5 {
                        break;
                    }
                    println!("{}", line);
                }

                // Find code references
                println!("\n💻 Code references:");
                find_code_references(req_id);

                return;
            }
        }
    }

    println!("❌ Requirement {} not found", req_id);
}

fn find_by_tag(requirements_dir: &Path, tag: &str, show_code: bool) {
    println!("🔍 Searching for requirements with tag: {}\n", tag);

    let files = vec![
        "00-general.md",
        "01-performance.md",
        "02-functional.md",
        "03-configuration.md",
        "04-testing.md",
        "05-cli.md",
        "06-operational.md",
        "07-observability.md",
    ];

    let mut found = false;

    for file in files {
        let path = requirements_dir.join(file);
        if !path.exists() {
            continue;
        }

        let content = fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = content.lines().collect();

        let mut current_req: Option<String> = None;
        let mut in_tags = false;

        for line in lines.iter() {
            // Detect requirement ID (starts with ** and contains requirement pattern, but not Tags)
            if line.starts_with("**") && !line.contains("Tags:") {
                if let Some(id) = extract_req_id(line) {
                    current_req = Some(id);
                    in_tags = false;
                }
            }

            // Check for tags line
            if line.contains("**Tags:**") {
                in_tags = true;
                // Tags are on the same line or next line, check this line
                if line.contains(&format!("`{}`", tag)) {
                    if let Some(ref req_id) = current_req {
                        found = true;
                        println!("📋 {} - {}", req_id, file);
                        if show_code {
                            find_code_references(req_id);
                            println!();
                        }
                    }
                }
            } else if in_tags {
                // Check if this line contains the tag we're looking for
                if line.contains(&format!("`{}`", tag)) {
                    if let Some(ref req_id) = current_req {
                        found = true;
                        println!("📋 {} - {}", req_id, file);
                        if show_code {
                            find_code_references(req_id);
                            println!();
                        }
                    }
                }
                // Reset in_tags if we hit an empty line or next requirement
                if line.trim().is_empty() || (line.starts_with("**") && !line.contains("Tags:")) {
                    in_tags = false;
                }
            }
        }
    }

    if !found {
        println!("❌ No requirements found with tag: {}", tag);
    }
}

fn extract_req_id(line: &str) -> Option<String> {
    // Match patterns like **F2.** or **C16.1.** or F2. or T1.
    if let Some(start) = line.find("**") {
        let after_start = &line[start + 2..];
        if let Some(end) = after_start.find(".**") {
            return Some(after_start[..end].to_string());
        }
        if let Some(end) = after_start.find("**") {
            return Some(after_start[..end].to_string());
        }
    }

    // Match patterns like F2. or T1. (without **)
    for prefix in &["F", "C", "G", "P", "T", "UT", "FT", "CLI", "OP", "O"] {
        if line.starts_with(prefix) {
            if let Some(end) = line.find(".") {
                let id = &line[..end];
                if id.chars().all(|c| c.is_alphanumeric() || c == '.') {
                    return Some(id.to_string());
                }
            }
        }
    }

    None
}

fn find_code_references(req_id: &str) {
    let src_dir = Path::new("src");
    let tests_dir = Path::new("tests");

    // Search in source code
    if src_dir.exists() {
        search_in_dir(src_dir, req_id, "💻");
    }

    // Search in tests
    if tests_dir.exists() {
        search_in_dir(tests_dir, req_id, "🧪");
    }
}

fn search_in_dir(dir: &Path, req_id: &str, emoji: &str) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                search_in_dir(&path, req_id, emoji);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                if let Ok(content) = fs::read_to_string(&path) {
                    for (line_num, line) in content.lines().enumerate() {
                        if line.contains("Requirement") && line.contains(req_id) {
                            println!(
                                "  {} {}:{} - {}",
                                emoji,
                                path.display(),
                                line_num + 1,
                                line.trim()
                            );
                        }
                    }
                }
            }
        }
    }
}
