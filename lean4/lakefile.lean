import Lake
open Lake DSL

require TorchLean from git
  "https://github.com/lean-dojo/TorchLean.git" @ "411682f6c3d913e5cdbc27d4546b3ab7ac0e3e9c"

package «sunbeam» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib «Sunbeam» where
  srcDir := "."
