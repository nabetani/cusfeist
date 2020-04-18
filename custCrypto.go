package main

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/bits"
)

type xoroshiro struct {
	s [2]uint64
}

func newXoroshiro(seed []uint64) *xoroshiro {
	read := func(v uint64) uint64 {
		if v == 0 {
			return 17071688163355054097
		}
		return v
	}
	s0 := read(seed[0])
	s1 := read(seed[1])
	return &xoroshiro{
		s: [2]uint64{s0, s1},
	}
}

func (x *xoroshiro) next() uint64 {
	s0 := x.s[0]
	s1 := x.s[1]

	r := bits.RotateLeft64(s0+s1, 17) + s0
	s1 ^= s0
	x.s[0] = bits.RotateLeft64(s0, 49) ^ s1 ^ (s1 << 21) // a, b
	x.s[1] = bits.RotateLeft64(s1, 28)                   // c
	return r
}

type innerState struct {
	rng *xoroshiro
	v   uint64
	rot int
}

func (i *innerState) modify(x uint64) uint64 {
	return bits.RotateLeft64(x^i.v, i.rot)
}

func (i *innerState) progress() {
	i.v = i.rng.next()
	i.rot = int(i.rng.next() & 63)
}

func newInnerState(seed []uint64) *innerState {
	rng := newXoroshiro(seed)
	r := &innerState{rng: rng}
	r.progress()
	return r
}

type custCrypto struct {
	pw []uint64
	is *innerState
}

func (c *custCrypto) blockSize() int64 {
	return 16
}

func (c *custCrypto) rot1(x, num uint64) uint64 {
	s := int((num + c.pw[num%uint64(len(c.pw))]) % 64)
	return bits.RotateLeft64(x, s)
}

func (c *custCrypto) rot2(x, num uint64) uint64 {
	return c.rot1(x*733687, num*5996329)
}

func (c *custCrypto) shuffles() []func(x, num uint64) uint64 {
	return []func(x, num uint64) uint64{
		func(x, num uint64) uint64 { return c.rot1(x, num) },
		func(x, num uint64) uint64 { return c.rot2(x, num) },
	}
}

func (c *custCrypto) decrypt(b []byte, num int64) []byte {
	split := func(src []byte) (uint64, uint64) {
		return binary.LittleEndian.Uint64(src[0:8]), binary.LittleEndian.Uint64(src[8:16])
	}
	merge := func(x, y uint64) []byte {
		r := make([]byte, 16)
		binary.LittleEndian.PutUint64(r, x)
		binary.LittleEndian.PutUint64(r[8:16], y)
		return r
	}
	x, y := split(b)
	shuffles := c.shuffles()
	num64 := uint64(num)
	for i := len(shuffles)/2 - 1; 0 <= i; i-- {
		y ^= c.is.modify(shuffles[i*2+1](x, num64))
		x ^= c.is.modify(shuffles[i*2](y, num64))
	}
	c.is.progress()
	return merge(x, y)
}

func (c *custCrypto) encrypt(b []byte, num int64) []byte {
	split := func(src []byte) (uint64, uint64) {
		return binary.LittleEndian.Uint64(src[0:8]), binary.LittleEndian.Uint64(src[8:16])
	}
	merge := func(x, y uint64) []byte {
		r := make([]byte, 16)
		binary.LittleEndian.PutUint64(r, x)
		binary.LittleEndian.PutUint64(r[8:16], y)
		return r
	}
	x, y := split(b)
	shuffles := c.shuffles()
	num64 := uint64(num)
	for i := 0; i < len(shuffles)/2; i++ {
		x ^= c.is.modify(shuffles[i*2](y, num64))
		y ^= c.is.modify(shuffles[i*2+1](x, num64))
	}
	c.is.progress()
	return merge(x, y)
}

func newCustCrypto(pw string) *custCrypto {
	makePw := func() []uint64 {
		h := sha1.New()
		h.Write([]byte("salt of custCrypto algorithm"))
		pwBytes := []byte{}
		for i := uint8(0); i < uint8(64); i++ {
			h.Write([]byte(pw))
			h.Write([]byte{i})
			pwBytes = h.Sum(pwBytes)
			fmt.Printf("pwBytes(%d): %v\n", i, pwBytes)
		}
		pw := []uint64{}
		for {
			pw = append(pw, binary.LittleEndian.Uint64(pwBytes))
			pwBytes = pwBytes[8:]
			if 0 == len(pwBytes) {
				break
			}
		}
		return pw
	}
	pw64 := makePw()
	c := custCrypto{
		pw: pw64,
		is: newInnerState(pw64),
	}
	return &c
}
