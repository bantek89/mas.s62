package main

import (
	"fmt"
)

func Forge() (string, Signature, error) {
	// decode pubkey, all 4 signatures into usable structures from hex strings
	pub, err := HexToPubkey(hexPubkey1)
	if err != nil {
		panic(err)
	}

	sig1, err := HexToSignature(hexSignature1)
	if err != nil {
		panic(err)
	}
	sig2, err := HexToSignature(hexSignature2)
	if err != nil {
		panic(err)
	}
	sig3, err := HexToSignature(hexSignature3)
	if err != nil {
		panic(err)
	}
	sig4, err := HexToSignature(hexSignature4)
	if err != nil {
		panic(err)
	}

	var sigslice []Signature
	sigslice = append(sigslice, sig1)
	sigslice = append(sigslice, sig2)
	sigslice = append(sigslice, sig3)
	sigslice = append(sigslice, sig4)

	var msgslice []Message

	msgslice = append(msgslice, GetMessageFromString("1"))
	msgslice = append(msgslice, GetMessageFromString("2"))
	msgslice = append(msgslice, GetMessageFromString("3"))
	msgslice = append(msgslice, GetMessageFromString("4"))

	fmt.Printf("ok 1: %v\n", Verify(msgslice[0], pub, sig1))
	fmt.Printf("ok 2: %v\n", Verify(msgslice[1], pub, sig2))
	fmt.Printf("ok 3: %v\n", Verify(msgslice[2], pub, sig3))
	fmt.Printf("ok 4: %v\n", Verify(msgslice[3], pub, sig4))

	msgStringTemplate := "forgery banna "
	var msgString string
	var msg Message
	var sig Signature

	var sec SecretKey

	for _, msg := range msgslice {
		for i := range [256]int{} {
			if (msg[i/8]>>(7-(i%8)))&0x01 == 0 {
				for _, sig := range sigslice {
					if sig.Preimage[i].IsPreimage(pub.ZeroHash[i]) {
						sec.ZeroPre[i] = sig.Preimage[i]
					}
				}
			} else {
				for _, sig := range sigslice {
					if sig.Preimage[i].IsPreimage(pub.OneHash[i]) {
						sec.OnePre[i] = sig.Preimage[i]
					}
				}
			}
		}
	}

	for i := 0; ; i++ {
		msgString = msgStringTemplate + fmt.Sprint(i)
		msg = GetMessageFromString(msgString)
		sig = Sign(msg, sec)
		if Verify(msg, pub, sig) {
			break
		}
	}

	return msgString, sig, nil

}

// hint:
// arr[i/8]>>(7-(i%8)))&0x01
