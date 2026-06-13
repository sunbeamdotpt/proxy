// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Weight export: converts trained models into standalone Rust `const` arrays
//! and optionally Lean 4 definitions.
//!
//! The generated Rust source is meant to be placed in
//! `src/ensemble/gen/{scanner,ddos}_weights.rs` so the inference side can use
//! compile-time weight constants with zero runtime cost.

use anyhow::Result;
use std::fmt::Write as FmtWrite;
use std::path::Path;

/// All data needed to emit a standalone inference source file.
pub struct ExportedModel {
    /// Module name used in generated code comments and Lean defs.
    pub model_name: String,
    /// Number of input features.
    pub input_dim: usize,
    /// Hidden layer width (always 32 in the current ensemble).
    pub hidden_dim: usize,
    /// Weight matrix for layer 1: `hidden_dim x input_dim`.
    pub w1: Vec<Vec<f32>>,
    /// Bias vector for layer 1: length `hidden_dim`.
    pub b1: Vec<f32>,
    /// Weight vector for layer 2: length `hidden_dim`.
    pub w2: Vec<f32>,
    /// Bias scalar for layer 2.
    pub b2: f32,
    /// Packed decision tree nodes.
    pub tree_nodes: Vec<(u8, f32, u16, u16)>,
    /// MLP classification threshold.
    pub threshold: f32,
    /// Per-feature normalization minimums.
    pub norm_mins: Vec<f32>,
    /// Per-feature normalization maximums.
    pub norm_maxs: Vec<f32>,
}

/// Generate a Rust source file with `const` arrays for all model weights.
pub fn generate_rust_source(model: &ExportedModel) -> String {
    let mut s = String::with_capacity(8192);

    writeln!(
        s,
        "//! Auto-generated weights for the {} ensemble.",
        model.model_name
    )
    .unwrap();
    writeln!(
        s,
        "//! DO NOT EDIT — regenerate with `cargo run --features training -- train-{}-mlp`.",
        model.model_name.to_ascii_lowercase()
    )
    .unwrap();
    writeln!(s).unwrap();

    // Threshold.
    writeln!(
        s,
        "pub const THRESHOLD: f32 = {:.8};",
        sanitize(model.threshold)
    )
    .unwrap();
    writeln!(s).unwrap();

    // Normalization params.
    write_f32_array(&mut s, "NORM_MINS", &model.norm_mins);
    write_f32_array(&mut s, "NORM_MAXS", &model.norm_maxs);

    // W1: hidden_dim x input_dim.
    writeln!(
        s,
        "pub const W1: [[f32; {}]; {}] = [",
        model.input_dim, model.hidden_dim
    )
    .unwrap();
    for row in &model.w1 {
        write!(s, "    [").unwrap();
        for (i, v) in row.iter().enumerate() {
            if i > 0 {
                write!(s, ", ").unwrap();
            }
            write!(s, "{:.8}", sanitize(*v)).unwrap();
        }
        writeln!(s, "],").unwrap();
    }
    writeln!(s, "];").unwrap();
    writeln!(s).unwrap();

    // B1.
    write_f32_array(&mut s, "B1", &model.b1);

    // W2.
    write_f32_array(&mut s, "W2", &model.w2);

    // B2.
    writeln!(s, "pub const B2: f32 = {:.8};", sanitize(model.b2)).unwrap();
    writeln!(s).unwrap();

    // Tree nodes.
    writeln!(
        s,
        "pub const TREE_NODES: [(u8, f32, u16, u16); {}] = [",
        model.tree_nodes.len()
    )
    .unwrap();
    for &(feat, thresh, left, right) in &model.tree_nodes {
        writeln!(s, "    ({}, {:.8}, {}, {}),", feat, thresh, left, right).unwrap();
    }
    writeln!(s, "];").unwrap();

    s
}

/// Generate Lean 4 definitions for formal verification.
pub fn generate_lean_source(model: &ExportedModel) -> String {
    let mut s = String::with_capacity(8192);

    writeln!(
        s,
        "-- Auto-generated Lean 4 definitions for {} ensemble.",
        model.model_name
    )
    .unwrap();
    writeln!(s, "-- DO NOT EDIT — regenerate with the training pipeline.").unwrap();
    writeln!(s).unwrap();

    writeln!(
        s,
        "namespace Sunbeam.Ensemble.{}",
        capitalize(&model.model_name)
    )
    .unwrap();
    writeln!(s).unwrap();

    writeln!(s, "def inputDim : Nat := {}", model.input_dim).unwrap();
    writeln!(s, "def hiddenDim : Nat := {}", model.hidden_dim).unwrap();
    writeln!(s, "def threshold : Float := {:.8}", model.threshold).unwrap();
    writeln!(s, "def b2 : Float := {:.8}", model.b2).unwrap();
    writeln!(s).unwrap();

    write_lean_float_list(&mut s, "normMins", &model.norm_mins);
    write_lean_float_list(&mut s, "normMaxs", &model.norm_maxs);
    write_lean_float_list(&mut s, "b1", &model.b1);
    write_lean_float_list(&mut s, "w2", &model.w2);

    // W1 as list of lists.
    writeln!(s, "def w1 : List (List Float) := [").unwrap();
    for (i, row) in model.w1.iter().enumerate() {
        let comma = if i + 1 < model.w1.len() { "," } else { "" };
        write!(s, "  [").unwrap();
        for (j, v) in row.iter().enumerate() {
            if j > 0 {
                write!(s, ", ").unwrap();
            }
            write!(s, "{:.8}", v).unwrap();
        }
        writeln!(s, "]{}", comma).unwrap();
    }
    writeln!(s, "]").unwrap();
    writeln!(s).unwrap();

    // Tree nodes as list of tuples.
    writeln!(s, "def treeNodes : List (Nat × Float × Nat × Nat) := [").unwrap();
    for (i, &(feat, thresh, left, right)) in model.tree_nodes.iter().enumerate() {
        let comma = if i + 1 < model.tree_nodes.len() {
            ","
        } else {
            ""
        };
        writeln!(
            s,
            "  ({}, {:.8}, {}, {}){}",
            feat, thresh, left, right, comma
        )
        .unwrap();
    }
    writeln!(s, "]").unwrap();
    writeln!(s).unwrap();

    writeln!(s, "end Sunbeam.Ensemble.{}", capitalize(&model.model_name)).unwrap();

    s
}

/// Write the generated Rust source to a file.
pub fn export_to_file(model: &ExportedModel, path: &Path) -> Result<()> {
    let source = generate_rust_source(model);
    std::fs::write(path, source.as_bytes())
        .map_err(|e| anyhow::anyhow!("writing export to {}: {}", path.display(), e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sanitize a float for Rust source: replace NaN/Inf with 0.0.
fn sanitize(v: f32) -> f32 {
    if v.is_finite() {
        v
    } else {
        0.0
    }
}

fn write_f32_array(s: &mut String, name: &str, values: &[f32]) {
    writeln!(s, "pub const {}: [f32; {}] = [", name, values.len()).unwrap();
    write!(s, "    ").unwrap();
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            write!(s, ", ").unwrap();
        }
        // Line-wrap every 8 values for readability.
        if i > 0 && i % 8 == 0 {
            write!(s, "\n    ").unwrap();
        }
        write!(s, "{:.8}", sanitize(*v)).unwrap();
    }
    writeln!(s, "\n];").unwrap();
    writeln!(s).unwrap();
}

fn write_lean_float_list(s: &mut String, name: &str, values: &[f32]) {
    write!(s, "def {} : List Float := [", name).unwrap();
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            write!(s, ", ").unwrap();
        }
        write!(s, "{:.8}", v).unwrap();
    }
    writeln!(s, "]").unwrap();
    writeln!(s).unwrap();
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().to_string() + c.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_model() -> ExportedModel {
        ExportedModel {
            model_name: "scanner".to_string(),
            input_dim: 2,
            hidden_dim: 2,
            w1: vec![vec![0.1, 0.2], vec![0.3, 0.4]],
            b1: vec![0.01, 0.02],
            w2: vec![0.5, 0.6],
            b2: -0.1,
            tree_nodes: vec![(0, 0.5, 1, 2), (255, 0.0, 0, 0), (255, 1.0, 0, 0)],
            threshold: 0.5,
            norm_mins: vec![0.0, 0.0],
            norm_maxs: vec![1.0, 10.0],
        }
    }

    #[test]
    fn test_rust_source_contains_consts() {
        let model = make_test_model();
        let src = generate_rust_source(&model);

        assert!(
            src.contains("pub const THRESHOLD: f32 ="),
            "missing THRESHOLD"
        );
        assert!(src.contains("pub const NORM_MINS:"), "missing NORM_MINS");
        assert!(src.contains("pub const NORM_MAXS:"), "missing NORM_MAXS");
        assert!(src.contains("pub const W1:"), "missing W1");
        assert!(src.contains("pub const B1:"), "missing B1");
        assert!(src.contains("pub const W2:"), "missing W2");
        assert!(src.contains("pub const B2: f32 ="), "missing B2");
        assert!(src.contains("pub const TREE_NODES:"), "missing TREE_NODES");
    }

    #[test]
    fn test_rust_source_array_dims() {
        let model = make_test_model();
        let src = generate_rust_source(&model);

        // W1 should be [f32; 2]; 2]
        assert!(src.contains("[[f32; 2]; 2]"), "W1 dimensions wrong");
        // B1 should be [f32; 2]
        assert!(src.contains("B1: [f32; 2]"), "B1 dimensions wrong");
        // W2 should be [f32; 2]
        assert!(src.contains("W2: [f32; 2]"), "W2 dimensions wrong");
        // TREE_NODES should have 3 entries
        assert!(
            src.contains("[(u8, f32, u16, u16); 3]"),
            "TREE_NODES count wrong"
        );
    }

    #[test]
    fn test_weight_values_roundtrip() {
        let model = make_test_model();
        let src = generate_rust_source(&model);

        // The threshold should appear with reasonable precision.
        assert!(src.contains("0.50000000"), "threshold value missing");
        // B2 value.
        assert!(src.contains("-0.10000000"), "b2 value missing");
    }

    #[test]
    fn test_lean_source_structure() {
        let model = make_test_model();
        let src = generate_lean_source(&model);

        assert!(src.contains("namespace Sunbeam.Ensemble.Scanner"));
        assert!(src.contains("def inputDim : Nat := 2"));
        assert!(src.contains("def hiddenDim : Nat := 2"));
        assert!(src.contains("def threshold : Float :="));
        assert!(src.contains("def normMins : List Float :="));
        assert!(src.contains("def w1 : List (List Float) :="));
        assert!(src.contains("def treeNodes :"));
        assert!(src.contains("end Sunbeam.Ensemble.Scanner"));
    }

    #[test]
    fn test_export_to_file() {
        let model = make_test_model();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_weights.rs");

        export_to_file(&model, &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("pub const THRESHOLD:"));
        assert!(content.contains("pub const W1:"));
    }
}
