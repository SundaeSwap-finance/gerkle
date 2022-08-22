# Gerkle

A go library for working with merkle trees.

To build the merkle tree:

```golang
// Build a merkle tree out of raw bytes, using 0x31 as a separator
// leaves is an array of Stringers, the result of which is hashed using hasher
tree, err := gerkle.Build(hash, false, 0x31, leaves)

// Build a merkle tree out of hexidecimal strings separated by ':', using sha256
// For example, this may be more user-friendly if someone is comparing proofs
tree, err := gerkle.Build(sha256.New(), true, ':', leaves)
```

To enumerate the leaves
```golang
tree.EnumerateLeaves(func(t *MerkleTree) bool { return true })
tree.EnumerateWithProofs(func(t *MerkleTree, p []MerkleStep) (bool, error) { return true, nil })
```

To get a proof for a specific leaf, and validate that proof
```golang
steps, err := tree.FindProofFor(leaf)
if err := tree.CheckProof(steps); err != nil {
  fmt.Printf("proof invalid: %w", err)
}
```