package main

import (
	"fmt"
	"math/rand"
	"runtime"
	"strconv"
	"time"
)

// This file is for the mining code.
// Note that "targetBits" for this assignment, at least initially, is 33.
// This could change during the assignment duration!  I will post if it does.

// Mine mines a block by varying the nonce until the hash has targetBits 0s in
// the beginning.  Could take forever if targetBits is too high.
// Modifies a block in place by using a pointer receiver.

func (self *Block) Mine(targetBits uint8, found chan int) {

	fmt.Println(runtime.NumGoroutine())
	var block Block
	block.PrevHash = self.Hash()
	block.Name = "Banna"

	start := time.Now()
	for {
		block.Nonce = strconv.FormatInt(rand.Int63(), 10)
		if CheckWork(block, targetBits) {
			fmt.Println(block)
			SendBlockToServer(block)
			found <- 0
			break
		}
		if time.Since(start).Seconds() > 5 {
			break
		}
	}

}

// CheckWork checks if there's enough work
func CheckWork(bl Block, targetBits uint8) bool {
	h := bl.Hash()

	for i := uint8(0); i < targetBits; i++ {

		if (h[i/8]>>(7-(i%8)))&0x01 == 1 {
			return false
		}
	}

	return true
}
