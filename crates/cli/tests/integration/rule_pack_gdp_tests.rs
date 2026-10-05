use std::path::Path;

use serde_json::json;

use crate::common::{parse_json, run_fallow_in_root};

fn write_gdp_project(root: &Path) {
    std::fs::create_dir_all(root.join("src/auth")).expect("create auth directory");
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"gdp-policy-fixture","main":"src/index.ts","dependencies":{"@gdp-ts/core":"*"}}"#,
    )
    .expect("write package");
    std::fs::write(
        root.join(".fallowrc.json"),
        r#"{"rulePacks":["gdp-policy.json"],"rules":{"policy-violation":"warn"}}"#,
    )
    .expect("write config");
    std::fs::write(
        root.join("gdp-policy.json"),
        r#"{
  "version": 1,
  "name": "gdp",
  "rules": [
    {
      "id": "trusted-producers",
      "kind": "gdp-proof-producer",
      "allowedFiles": ["src/auth/**"]
    },
    {
      "id": "delete-owner",
      "kind": "gdp-proof-producer",
      "allowedFiles": ["src/auth/project.ts"],
      "proofKinds": ["CanDeleteProject"],
      "severity": "error"
    }
  ]
}"#,
    )
    .expect("write policy");
    for (path, source) in [
        (
            "src/index.ts",
            "import { defineProof as make } from '@gdp-ts/core';\nmake('CanDeleteProject');\nmake('CanReadProject');\n",
        ),
        (
            "src/hidden.ts",
            "import { make } from './factory';\nmake('CanDeleteProject');\n",
        ),
        (
            "src/factory.ts",
            "export { defineProof as make } from '@gdp-ts/core';\n",
        ),
        (
            "src/auth/project.ts",
            "import { defineProof } from '@gdp-ts/core';\nexport const owner = defineProof('CanDeleteProject');\n",
        ),
        (
            "src/auth/other.ts",
            "import { defineProof } from '@gdp-ts/core';\nexport const other = defineProof('CanDeleteProject');\n",
        ),
    ] {
        std::fs::write(root.join(path), source).expect("write source");
    }
}

#[test]
fn gdp_rule_pack_test_reports_independent_rules_and_unreachable_producers() {
    let dir = tempfile::tempdir().expect("create fixture");
    write_gdp_project(dir.path());
    let output = run_fallow_in_root(
        "rule-pack",
        dir.path(),
        &["test", "--format", "json", "--quiet", "--no-cache"],
    );
    assert_eq!(output.code, 0, "stderr: {}", output.stderr);
    let report = parse_json(&output);
    assert_eq!(report["kind"], "rule-pack-test");
    assert_eq!(
        report["rules"],
        json!([
            {"pack":"gdp","rule_id":"trusted-producers","kind":"gdp-proof-producer","severity":"warn","findings":3},
            {"pack":"gdp","rule_id":"delete-owner","kind":"gdp-proof-producer","severity":"error","findings":3}
        ])
    );
    let findings = report["findings"].as_array().expect("findings array");
    let mut locations: Vec<(&str, &str, u64, &str)> = findings
        .iter()
        .map(|finding| {
            (
                finding["path"].as_str().expect("path"),
                finding["rule_id"].as_str().expect("rule ID"),
                finding["line"].as_u64().expect("line"),
                finding["severity"].as_str().expect("severity"),
            )
        })
        .collect();
    locations.sort_unstable();
    assert_eq!(
        locations,
        [
            ("src/auth/other.ts", "delete-owner", 2, "error"),
            ("src/hidden.ts", "delete-owner", 2, "error"),
            ("src/hidden.ts", "trusted-producers", 2, "warn"),
            ("src/index.ts", "delete-owner", 2, "error"),
            ("src/index.ts", "trusted-producers", 2, "warn"),
            ("src/index.ts", "trusted-producers", 3, "warn"),
        ]
    );
}

#[test]
fn gdp_list_and_guard_expose_allowed_producers_and_proof_kind_filters() {
    let dir = tempfile::tempdir().expect("create fixture");
    write_gdp_project(dir.path());
    let listed = run_fallow_in_root(
        "rule-pack",
        dir.path(),
        &["list", "--format", "json", "--quiet"],
    );
    assert_eq!(listed.code, 0, "stderr: {}", listed.stderr);
    let list = parse_json(&listed);
    let owner = &list["packs"][0]["rules"][1];
    assert_eq!(owner["kind"], "gdp-proof-producer");
    assert_eq!(owner["allowedFiles"], json!(["src/auth/project.ts"]));
    assert_eq!(owner["proofKinds"], json!(["CanDeleteProject"]));
    assert_eq!(owner["patterns"], json!(["@gdp-ts/core.defineProof"]));
    assert_eq!(owner["severity"], "error");
    let guarded = run_fallow_in_root(
        "guard",
        dir.path(),
        &["src/index.ts", "--format", "json", "--quiet"],
    );
    assert_eq!(guarded.code, 0, "stderr: {}", guarded.stderr);
    let guard = parse_json(&guarded);
    let owner = &guard["files"][0]["policy_rules"][1];
    assert_eq!(owner["kind"], "gdp-proof-producer");
    assert_eq!(owner["allowed_files"], json!(["src/auth/project.ts"]));
    assert_eq!(owner["proof_kinds"], json!(["CanDeleteProject"]));
    assert_eq!(owner["suppress_token"], "policy-violation:gdp/delete-owner");
    assert_eq!(owner["severity"], "error");
    for (command, args) in [
        ("rule-pack", vec!["list", "--quiet"]),
        ("guard", vec!["src/index.ts", "--quiet"]),
    ] {
        let output = run_fallow_in_root(command, dir.path(), &args);
        assert_eq!(output.code, 0, "stderr: {}", output.stderr);
        assert!(output.stdout.contains("src/auth/project.ts"));
        assert!(output.stdout.contains("CanDeleteProject"));
        assert!(
            output.stdout.contains("gdp/delete-owner") || output.stdout.contains("delete-owner")
        );
    }
}

#[test]
fn gdp_scoped_suppression_keeps_other_rules_and_finding_id_filter() {
    let dir = tempfile::tempdir().expect("create fixture");
    write_gdp_project(dir.path());
    std::fs::write(
        dir.path().join("src/index.ts"),
        "import { defineProof as make } from '@gdp-ts/core';\n\
         // fallow-ignore-next-line policy-violation:gdp/delete-owner -- caller is checked\n\
         make('CanDeleteProject');\nmake('CanReadProject');\n",
    )
    .expect("write scoped suppression");
    let output = run_fallow_in_root(
        "dead-code",
        dir.path(),
        &[
            "--policy-violations",
            "--format",
            "json",
            "--quiet",
            "--no-cache",
        ],
    );
    assert_eq!(output.code, 1, "error rule must fail CI: {}", output.stderr);
    let report = parse_json(&output);
    let findings = report["policy_violations"]
        .as_array()
        .expect("policy findings");
    let mut identities: Vec<(&str, &str, u64)> = findings
        .iter()
        .map(|finding| {
            (
                finding["path"].as_str().expect("path"),
                finding["rule_id"].as_str().expect("rule ID"),
                finding["line"].as_u64().expect("line"),
            )
        })
        .collect();
    identities.sort_unstable();
    assert_eq!(
        identities,
        [
            ("src/auth/other.ts", "delete-owner", 2),
            ("src/hidden.ts", "delete-owner", 2),
            ("src/hidden.ts", "trusted-producers", 2),
            ("src/index.ts", "trusted-producers", 3),
            ("src/index.ts", "trusted-producers", 4),
        ]
    );
    let retained = findings
        .iter()
        .find(|finding| finding["path"] == "src/index.ts" && finding["line"] == 3)
        .expect("independent global rule remains");
    assert_eq!(retained["severity"], "warn");
    let id = retained["finding_id"].as_str().expect("finding ID");
    let filtered = run_fallow_in_root(
        "dead-code",
        dir.path(),
        &[
            "--policy-violations",
            "--format",
            "json",
            "--quiet",
            "--finding-id",
            id,
        ],
    );
    assert_eq!(
        filtered.code, 0,
        "warn-only filtered output: {}",
        filtered.stderr
    );
    let filtered = parse_json(&filtered);
    assert_eq!(filtered["policy_violations"], json!([retained]));
}

#[test]
fn gdp_findings_offer_producer_relocation_and_human_remediation() {
    let dir = tempfile::tempdir().expect("create fixture");
    write_gdp_project(dir.path());
    let output = run_fallow_in_root(
        "dead-code",
        dir.path(),
        &[
            "--policy-violations",
            "--format",
            "json",
            "--quiet",
            "--no-cache",
        ],
    );
    assert_eq!(output.code, 1, "stderr: {}", output.stderr);
    let report = parse_json(&output);
    let owner = report["policy_violations"]
        .as_array()
        .expect("policy findings")
        .iter()
        .find(|finding| finding["rule_id"] == "delete-owner")
        .expect("owner violation");
    assert!(
        owner["matched"]
            .as_str()
            .expect("matched call")
            .contains("CanDeleteProject")
    );
    assert!(
        owner["message"]
            .as_str()
            .expect("default remediation")
            .contains("src/auth/project.ts")
    );
    let fix = owner["actions"]
        .as_array()
        .expect("actions")
        .iter()
        .find(|action| action["type"] == "resolve-policy-violation")
        .expect("fix action");
    assert_eq!(fix["type"], "resolve-policy-violation");
    assert_eq!(fix["auto_fixable"], false);
    assert!(
        fix["description"]
            .as_str()
            .expect("description")
            .contains("src/auth/project.ts")
    );
    let human = run_fallow_in_root("dead-code", dir.path(), &["--policy-violations", "--quiet"]);
    assert_eq!(human.code, 1, "stderr: {}", human.stderr);
    assert!(human.stdout.contains("gdp/delete-owner"));
    assert!(human.stdout.contains("CanDeleteProject"));
    assert!(human.stdout.contains("src/auth/project.ts"));
}
