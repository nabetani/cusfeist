package main

type cryptography interface {
	encrypt(b []byte, num int64) []byte
	decrypt(b []byte, num int64) []byte
	blockSize() int64
}
