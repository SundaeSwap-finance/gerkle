package gerkle

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"hash"
)

type MerkleTree struct {
	hasher    hash.Hash
	hex       bool
	separator byte

	Hash   []byte
	Leaf   fmt.Stringer
	Parent *MerkleTree
	Left   *MerkleTree
	Right  *MerkleTree
}

type MerkleStep struct {
	Type string
	Hash []byte
}

func writeChained(prev error, h hash.Hash, data []byte) error {
	if prev != nil {
		return prev
	}
	_, err := h.Write(data)
	return err
}

func Build(hash hash.Hash, useHex bool, separator byte, leaves []fmt.Stringer) (*MerkleTree, error) {
	if len(leaves) == 0 {
		b := hash.Sum(nil)
		hash.Reset()
		return &MerkleTree{
			hasher:    hash,
			hex:       useHex,
			separator: separator,
			Hash:      b,
			Leaf:      nil,
			Right:     nil,
		}, nil
	}
	if len(leaves) == 1 {
		_, err := hash.Write([]byte(leaves[0].String()))
		if err != nil {
			return nil, fmt.Errorf("failed to compute hash: %w", err)
		}
		b := hash.Sum(nil)
		hash.Reset()
		return &MerkleTree{
			hasher:    hash,
			hex:       useHex,
			separator: separator,
			Hash:      b,
			Leaf:      leaves[0],
			Left:      nil,
			Right:     nil,
		}, nil
	}
	// Make sure the midpoint biases the tree to the left
	midpoint := len(leaves)/2 + len(leaves)%2
	left, err := Build(hash, useHex, separator, leaves[:midpoint])
	if err != nil {
		return nil, err
	}
	right, err := Build(hash, useHex, separator, leaves[midpoint:])
	if err != nil {
		return nil, err
	}

	if useHex {
		leftHex := hex.EncodeToString(left.Hash)
		rightHex := hex.EncodeToString(right.Hash)
		err = writeChained(err, hash, []byte(leftHex))
		err = writeChained(err, hash, []byte{separator})
		err = writeChained(err, hash, []byte(rightHex))
	} else {
		err = writeChained(err, hash, left.Hash)
		err = writeChained(err, hash, []byte{separator})
		err = writeChained(err, hash, right.Hash)
	}
	if err != nil {
		return nil, fmt.Errorf("failed computing hash: %w", err)
	}

	interiorHash := hash.Sum(nil)
	hash.Reset()
	interior := MerkleTree{
		hasher:    hash,
		hex:       useHex,
		separator: separator,
		Hash:      interiorHash,
		Left:      left,
		Right:     right,
	}
	left.Parent = &interior
	right.Parent = &interior
	return &interior, nil
}

func (tree *MerkleTree) EnumerateLeaves(callback func(*MerkleTree) bool) bool {
	if tree.Leaf != nil {
		return callback(tree)
	} else {
		if tree.Left != nil {
			if !tree.Left.EnumerateLeaves(callback) {
				return false
			}
		}
		if tree.Right != nil {
			if !tree.Right.EnumerateLeaves(callback) {
				return false
			}
		}
		return true
	}
}

func _enumerateWithProofs(tree *MerkleTree, ancestors []MerkleStep, callback func(*MerkleTree, []MerkleStep) (bool, error)) (bool, error) {
	if tree.Leaf != nil {
		proof := append([]MerkleStep{{Type: "Leaf", Hash: tree.Hash}}, ancestors...)
		return callback(tree, proof)
	}
	leftProof := append([]MerkleStep{{Type: "Right", Hash: tree.Right.Hash}}, ancestors...)
	cont, err := _enumerateWithProofs(tree.Left, leftProof, callback)
	if !cont || err != nil {
		return cont, err
	}
	rightProof := append([]MerkleStep{{Type: "Left", Hash: tree.Left.Hash}}, ancestors...)
	return _enumerateWithProofs(tree.Right, rightProof, callback)
}

func (tree *MerkleTree) EnumerateWithProofs(callback func(*MerkleTree, []MerkleStep) (bool, error)) (bool, error) {
	return _enumerateWithProofs(tree, []MerkleStep{{Type: "Root", Hash: tree.Hash}}, callback)
}

func (tree *MerkleTree) FindProofFor(leaf fmt.Stringer) ([]MerkleStep, error) {
	var treeLeaf *MerkleTree
	tree.EnumerateLeaves(func(m *MerkleTree) bool {
		if m.Leaf.String() == leaf.String() {
			treeLeaf = m
			return false
		}
		return true
	})

	if treeLeaf == nil {
		return nil, fmt.Errorf("unable to find leaf %v", leaf.String())
	}

	_, err := tree.hasher.Write([]byte(leaf.String()))
	if err != nil {
		return nil, fmt.Errorf("unable to compute hash: %w", err)
	}
	b := tree.hasher.Sum(nil)
	tree.hasher.Reset()

	var steps []MerkleStep
	steps = append(steps, MerkleStep{Type: "Leaf", Hash: b})

	current := treeLeaf
	for current.Parent != nil {
		if current.Parent.Left == current {
			steps = append(steps, MerkleStep{Type: "Right", Hash: current.Parent.Right.Hash})
		} else {
			steps = append(steps, MerkleStep{Type: "Left", Hash: current.Parent.Left.Hash})
		}
		current = current.Parent
	}

	steps = append(steps, MerkleStep{Type: "Root", Hash: current.Hash})

	return steps, nil
}

func (tree *MerkleTree) CheckProof(steps []MerkleStep) error {
	first, last := 0, len(steps)-1
	if steps[first].Type != "Leaf" {
		return fmt.Errorf("first entry must be a hash of the leaf node")
	}
	if steps[last].Type != "Root" {
		return fmt.Errorf("last entry must be the hash of the leaf node")
	}

	hash := []byte{}
	for idx, step := range steps {
		if idx == first {
			hash = step.Hash
		} else if idx == last {
			if !bytes.Equal(hash, step.Hash) {
				return fmt.Errorf("proof steps don't produce the same root hash as in the proof")
			}
			if !bytes.Equal(hash, tree.Hash) {
				return fmt.Errorf("proof root hash doesn't match the tree root hash")
			}
			return nil
		} else {
			var err error
			if tree.hex {
				if step.Type == "Left" {
					err = writeChained(err, tree.hasher, []byte(hex.EncodeToString(step.Hash)))
					err = writeChained(err, tree.hasher, []byte{tree.separator})
					err = writeChained(err, tree.hasher, []byte(hex.EncodeToString(hash)))
				} else if step.Type == "Right" {
					err = writeChained(err, tree.hasher, []byte(hex.EncodeToString(hash)))
					err = writeChained(err, tree.hasher, []byte{tree.separator})
					err = writeChained(err, tree.hasher, []byte(hex.EncodeToString(step.Hash)))
				}
			} else {
				if step.Type == "Left" {
					err = writeChained(err, tree.hasher, step.Hash)
					err = writeChained(err, tree.hasher, []byte{tree.separator})
					err = writeChained(err, tree.hasher, hash)
				} else if step.Type == "Right" {
					err = writeChained(err, tree.hasher, hash)
					err = writeChained(err, tree.hasher, []byte{tree.separator})
					err = writeChained(err, tree.hasher, step.Hash)
				}
			}
			if err != nil {
				return fmt.Errorf("unable to compute hash: %w", err)
			}
			hash = tree.hasher.Sum(nil)
			tree.hasher.Reset()
		}
	}
	return fmt.Errorf("unreachable code")
}

func (tree *MerkleTree) Print(indent int) {
	for i := 0; i < indent; i++ {
		fmt.Printf("  ")
	}
	fmt.Printf("- %v", hex.EncodeToString(tree.Hash))
	if tree.Leaf != nil {
		fmt.Printf(" (%v)\n", tree.Leaf.String())
	} else if tree.Left != nil || tree.Right != nil {
		fmt.Printf(":\n")
		if tree.Left != nil {
			tree.Left.Print(indent + 1)
		}
		if tree.Right != nil {
			tree.Right.Print(indent + 1)
		}
	}
}
