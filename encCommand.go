package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

type encOpts struct {
	src  string
	dest string
	pw   string
}

var errNoSrc error = errors.New(`"-src" is required but missing`)
var errNoDest error = errors.New(`"-dest" is required but missing`)
var errNoPw error = errors.New(`"-pw" is required but missing`)
var errPwHasInvalidChar error = errors.New("password should be 7bit-clean characters")

func (o *encOpts) validate() error {
	if o.src == "" {
		return errNoSrc
	}
	if o.dest == "" {
		return errNoDest
	}
	if 0 == len(o.pw) {
		return errNoPw
	}
	for _, b := range o.pw {
		if b < 0x20 || 0x7e < b {
			return errPwHasInvalidChar
		}
	}
	return nil
}

type encCommand struct {
}

func (c *encCommand) name() string {
	return "enc"
}

func getEncOpts() encOpts {
	f := flag.NewFlagSet("custfeist enc", flag.ExitOnError)
	o := encOpts{}
	f.StringVar(&o.src, "src", "", "name of a file to read to encode")
	f.StringVar(&o.dest, "dest", "", "name of a file to write the result")
	f.StringVar(&o.pw, "pw", "", "password")
	err := f.Parse(os.Args[2:])
	if err != nil {
		panic(err)
	}
	if 0 < len(f.Args()) {
		fmt.Println("extra parameter exists.")
		f.Usage()
		os.Exit(1)
	}
	if err = o.validate(); err != nil {
		fmt.Println(err)
		f.Usage()
		os.Exit(1)
	}
	return o
}

func writeSize(dest io.Writer, size int64) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(size))
	_, err := dest.Write(b)
	if err != nil {
		panic(err)
	}
}

func (c *encCommand) encodeOne(pw string, size int64, src io.ReadSeeker, dest io.WriteSeeker) error {
	var crypto cryptography = newCustCrypto(pw)
	blockSize := crypto.blockSize()
	count := (size + blockSize - 1) / blockSize
	for num := int64(0); num < count; num++ {
		b := make([]byte, blockSize)
		src.Seek((count-num-1)*blockSize, io.SeekStart)
		sizeRead, err := src.Read(b)
		if sizeRead == 0 {
			break
		}
		if err != nil {
			return err
		}
		e := crypto.encrypt(b, num)
		_, err = dest.Write(e)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *encCommand) run() {
	opts := getEncOpts()
	fSrc, err := os.Open(opts.src)
	if err != nil {
		panic(err)
	}
	defer fSrc.Close()
	srcInfo, err := fSrc.Stat()
	if err != nil {
		panic(err)
	}
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

	err = c.encodeOne(opts.pw+":1st", srcInfo.Size(), fSrc, fTmp)
	if err != nil {
		panic(err)
	}
	writeSize(fDest, srcInfo.Size())
	err = c.encodeOne(opts.pw+":2nd", srcInfo.Size(), fTmp, fDest)
	if err != nil {
		panic(err)
	}
}
