namespace Sunbeam

/-- Decisions that a model component can output. -/
inductive Decision where
  | block : Decision
  | allow : Decision
  | defer : Decision
  deriving Repr, DecidableEq

/-- A fixed-size vector of floats. -/
def FloatVec (n : Nat) := Fin n → Float

/-- Dot product of two float vectors. -/
def dot {n : Nat} (a b : FloatVec n) : Float :=
  (List.finRange n).foldl (fun acc i => acc + a i * b i) 0.0

/-- Matrix-vector product. Matrix is row-major: m rows × n cols. -/
def matVecMul {m n : Nat} (mat : Fin m → FloatVec n) (v : FloatVec n) : FloatVec m :=
  fun i => dot (mat i) v

/-- Vector addition. -/
def vecAdd {n : Nat} (a b : FloatVec n) : FloatVec n :=
  fun i => a i + b i

end Sunbeam
