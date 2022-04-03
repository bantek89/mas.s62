package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func main() {

	// Define your message
	textString := "1"
	fmt.Printf("%s\n", textString)

	// convert message into a block
	m := GetMessageFromString(textString)
	fmt.Printf("%x\n", m[:])

	// generate keys
	sec, pub, err := GenerateKey()
	if err != nil {
		panic(err)
	}

	// print pubkey.
	fmt.Printf("pub:\n%s\n", pub.ToHex())

	// sign message
	sig1 := Sign(m, sec)
	fmt.Printf("sig1:\n%s\n", sig1.ToHex())

	// verify signature
	worked := Verify(m, pub, sig1)

	// done
	fmt.Printf("Verify worked? %v\n", worked)

	// Forge signature
	msgString, sig, err := Forge()
	if err != nil {
		panic(err)
	}

	fmt.Printf("forged msg: %s sig: %s\n", msgString, sig.ToHex())

	return
}

// Signature systems have 3 functions: GenerateKey(), Sign(), and Verify().
// We'll also define the data types: SecretKey, PublicKey, Message, Signature.

// --- Types

// A block of data is always 32 bytes long; we're using sha256 and this
// is the size of both the output (defined by the hash function) and our inputs
type Block [32]byte

type SecretKey struct {
	ZeroPre [256]Block
	OnePre  [256]Block
}

type PublicKey struct {
	ZeroHash [256]Block
	OneHash  [256]Block
}

// --- Methods on PublicKey type

// ToHex gives a hex string for a PublicKey. no newline at the end
func (self PublicKey) ToHex() string {
	// format is zerohash 0...255, onehash 0...255
	var s string
	for _, zero := range self.ZeroHash {
		s += zero.ToHex()
	}
	for _, one := range self.OneHash {
		s += one.ToHex()
	}
	return s
}

// HexToPubkey takes a string from PublicKey.ToHex() and turns it into a pubkey
// will return an error if there are non hex characters or if the lenght is wrong.
func HexToPubkey(s string) (PublicKey, error) {
	var p PublicKey

	expectedLength := 256 * 2 * 64 // 256 blocks long, 2 rows, 64 hex char per block

	// first, make sure hex string is of correct length
	if len(s) != expectedLength {
		return p, fmt.Errorf(
			"Pubkey string %d characters, expect %d", len(s), expectedLength)
	}

	// decode from hex to a byte slice
	bts, err := hex.DecodeString(s)
	if err != nil {
		return p, err
	}
	// we already checked the length of the hex string so don't need to re-check
	buf := bytes.NewBuffer(bts)

	for i, _ := range p.ZeroHash {
		p.ZeroHash[i] = BlockFromByteSlice(buf.Next(32))
	}
	for i, _ := range p.OneHash {
		p.OneHash[i] = BlockFromByteSlice(buf.Next(32))
	}

	return p, nil
}

// A message to be signed is just a block.
type Message Block

// --- Methods on the Block type

// ToHex returns a hex encoded string of the block data, with no newlines.
func (self Block) ToHex() string {
	return fmt.Sprintf("%064x", self[:])
}

// Hash returns the sha256 hash of the block.
func (self Block) Hash() Block {
	return sha256.Sum256(self[:])
}

// IsPreimage returns true if the block is a preimage of the argument.
// For example, if Y = hash(X), then X.IsPreimage(Y) will return true,
// and Y.IsPreimage(X) will return false.
func (self Block) IsPreimage(arg Block) bool {
	return self.Hash() == arg
}

// BlockFromByteSlice returns a block from a variable length byte slice.
// Watch out!  Silently ignores potential errors like the slice being too
// long or too short!
func BlockFromByteSlice(by []byte) Block {
	var bl Block
	copy(bl[:], by)
	return bl
}

// A signature consists of 32 blocks.  It's a selective reveal of the private
// key, according to the bits of the message.
type Signature struct {
	Preimage [256]Block
}

// ToHex returns a hex string of a signature
func (self Signature) ToHex() string {
	var s string
	for _, b := range self.Preimage {
		s += b.ToHex()
	}

	return s
}

// HexToSignature is the same idea as HexToPubkey, but half as big.  Format is just
// every block of the signature in sequence.
func HexToSignature(s string) (Signature, error) {
	var sig Signature

	expectedLength := 256 * 64 // 256 blocks long, 1 row, 64 hex char per block

	// first, make sure hex string is of correct length
	if len(s) != expectedLength {
		return sig, fmt.Errorf(
			"Pubkey string %d characters, expect %d", len(s), expectedLength)
	}

	// decode from hex to a byte slice
	bts, err := hex.DecodeString(s)
	if err != nil {
		return sig, err
	}
	// we already checked the length of the hex string so don't need to re-check
	buf := bytes.NewBuffer(bts)

	for i, _ := range sig.Preimage {
		sig.Preimage[i] = BlockFromByteSlice(buf.Next(32))
	}
	return sig, nil
}

// GetMessageFromString returns a Message which is the hash of the given string.
func GetMessageFromString(s string) Message {
	return sha256.Sum256([]byte(s))
}

// --- Functions

// GenerateKey takes no arguments, and returns a keypair and potentially an
// error.  It gets randomness from the OS via crypto/rand
// This can return an error if there is a problem with reading random bytes
func GenerateKey() (SecretKey, PublicKey, error) {
	// initialize SecretKey variable 'sec'.  Starts with all 00 bytes.
	var sec SecretKey
	var pub PublicKey

	// Your code here
	// ===

	a := make([]byte, 32)
	b := make([]byte, 32)

	for i := range sec.ZeroPre {
		rand.Read(a)
		sec.ZeroPre[i] = BlockFromByteSlice(a)
		pub.ZeroHash[i] = sec.ZeroPre[i].Hash()
	}

	for i := range sec.OnePre {
		rand.Read(b)
		sec.OnePre[i] = BlockFromByteSlice(b)
		pub.OneHash[i] = sec.OnePre[i].Hash()
	}

	// ===

	return sec, pub, nil
}

// func CheckError(e error) {
// 	if e != nil {
// 		fmt.Println(e)
// 	}
// }

// Sign takes a message and secret key, and returns a signature.
func Sign(msg Message, sec SecretKey) Signature {
	var sig Signature

	// Your code here
	// ===

	// Loop over all bits in the uint.
	// for _, b := range msgHash {
	// 	for i := 0; i < 8; i++ {
	// 		bit += 1

	// 		if b&(1<<uint(i)) == 0 {
	// 			sig.Preimage[bit-1] = sec.ZeroPre[bit-1]
	// 			// fmt.Print("b:", b, " (1 << uint(i)):", (1 << uint(i)), " i:", i, " TRUE", "\n")
	// 		} else {
	// 			sig.Preimage[bit-1] = sec.OnePre[bit-1]
	// 			// fmt.Print("b:", b, " (1 << uint(i)):", (1 << uint(i)), " i:", i, "\n")
	// 		}
	// 	}
	// }

	for i := range [256]int{} {
		if (msg[i/8]>>(7-(i%8)))&0x01 == 0 {
			sig.Preimage[i] = sec.ZeroPre[i]
		} else {
			sig.Preimage[i] = sec.OnePre[i]
		}
	}

	// ===
	return sig
}

func contains(s [256]bool) bool {
	for _, v := range s {
		if v == false {
			return false
		}
	}

	return true
}

// Verify takes a message, public key and signature, and returns a boolean
// describing the validity of the signature.
func Verify(msg Message, pub PublicKey, sig Signature) bool {

	// Your code here
	// ===

	var verify [256]bool

	// for _, b := range hash {
	// 	for i := 0; i < 8; i++ {
	// 		bit += 1
	// 		hashedSig := sha256.Sum256(sig.Preimage[bit-1][:])
	// 		if b&(1<<uint(i)) == 0 {
	// 			if hashedSig == pub.ZeroHash[bit-1] {
	// 				verify[bit-1] = true
	// 			}
	// 		} else {
	// 			if hashedSig == pub.OneHash[bit-1] {
	// 				verify[bit-1] = true
	// 			}
	// 		}
	// 	}
	// }

	for i := range [256]int{} {
		hashedSig := sig.Preimage[i].Hash()
		if (msg[i/8]>>(7-(i%8)))&0x01 == 0 {
			if hashedSig == pub.ZeroHash[i] {
				verify[i] = true
			}
		} else {
			if hashedSig == pub.OneHash[i] {
				verify[i] = true
			}
		}

	}

	// ===

	return contains(verify)
}
