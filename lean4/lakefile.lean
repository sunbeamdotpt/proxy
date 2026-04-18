import Lake
open Lake DSL

package «sunbeam» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib «Sunbeam» where
  srcDir := "."
