package main

type cryptography interface {
	encrypt(b []byte, num int) []byte
	blockSize() int64
}
