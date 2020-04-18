package main

import (
	"crypto/sha1"
	"encoding/binary"
	"math/bits"
)

type custCrypto struct {
	pw []uint64
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
		y ^= shuffles[i*2+1](x, num64)
		x ^= shuffles[i*2](y, num64)
	}
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
		x ^= shuffles[i*2](y, num64)
		y ^= shuffles[i*2+1](x, num64)
	}
	return merge(x, y)
}

func newCustCrypto(pw string) *custCrypto {
	makePw := func() []uint64 {
		h := sha1.New()
		h.Write([]byte("salt of custCrypto algorithm"))
		pwBytes := []byte{}
		for i := uint8(0); i < uint8(64); i++ {
			h.Write([]byte(pwBytes))
			h.Write([]byte{i})
			pwBytes = h.Sum(pwBytes)
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
	c := custCrypto{
		pw: makePw(),
	}
	return &c
}
