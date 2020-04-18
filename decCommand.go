package main

import (
	"encoding/binary"
	"io"
	"io/ioutil"
	"log"
	"os"
)

type decCommand struct {
}

func (c *decCommand) name() string {
	return "dec"
}

func encrypt(b []byte, pw []byte, num int) []byte {
	return b
}

func (c *decCommand) decodeOne(pw string, size, offset int64, src io.ReadSeeker, dest io.WriteSeeker) error {
	var crypto cryptography = newCustCrypto(pw)
	blockSize := crypto.blockSize()
	count := (size + blockSize - 1) / blockSize
	for num := count - 1; 0 <= num; num-- {
		b := make([]byte, blockSize)
		dest.Seek((count-num-1)*blockSize, io.SeekStart)
		src.Seek(offset+num*blockSize, io.SeekStart)
		sizeRead, err := src.Read(b)
		if sizeRead == 0 {
			break
		}
		if err != nil {
			return err
		}
		e := crypto.decrypt(b, num)
		_, err = dest.Write(e)
		if err != nil {
			return err
		}
	}
	return nil
}

func readSize(src io.Reader) int64 {
	b := make([]byte, 8)
	_, err := src.Read(b)
	if err != nil {
		panic(err)
	}
	return int64(binary.LittleEndian.Uint64(b))
}

func (c *decCommand) run() {
	opts := getEncOpts()
	fSrc, err := os.Open(opts.src)
	if err != nil {
		panic(err)
	}
	defer fSrc.Close()
	fDest, err := os.Create(opts.dest)
	if err != nil {
		panic(err)
	}
	defer fDest.Close()

	fTmp, err := ioutil.TempFile(".", "tmp")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		fTmp.Close()
		os.Remove(fTmp.Name())
	}()

	destSize := readSize(fSrc)

	err = fTmp.Truncate(destSize)
	if err != nil {
		panic(err)
	}
	err = c.decodeOne(opts.pw+":2nd", destSize, 8, fSrc, fTmp)
	if err != nil {
		panic(err)
	}
	err = fDest.Truncate(destSize)
	if err != nil {
		panic(err)
	}
	err = c.decodeOne(opts.pw+":1st", destSize, 0, fTmp, fDest)
	if err != nil {
		panic(err)
	}
	fDest.Truncate(destSize)
}
