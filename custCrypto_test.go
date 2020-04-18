package main

import (
	"fmt"
	"math/rand"
	"testing"
)

func randomBytes(size int64, seed int64) []byte {
	r := make([]byte, size)
	rng := rand.New(rand.NewSource(seed))
	rng.Read(r)
	return r
}

func TestEncDec(t *testing.T) {
	c := newCustCrypto("hoge")
	for num := 0; num < 100; num++ {
		src := randomBytes(c.blockSize(), int64(num))
		enc := c.encrypt(src, num)
		dec := c.decrypt(enc, num)
		if fmt.Sprint(src) != fmt.Sprint(dec) {
			t.Errorf("actual: %v  expected:%v, num=%v", dec, src, num)
		}
	}
}
