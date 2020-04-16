package main

import (
	"errors"
	"flag"
	"fmt"
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

func (o *encOpts) validate() error {
	if o.src == "" {
		return errNoSrc
	}
	if o.dest == "" {
		return errNoDest
	}
	if o.pw == "" {
		return errNoPw
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
func (c *encCommand) run() {
	fmt.Println(getEncOpts())
}
