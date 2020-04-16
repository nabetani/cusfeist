package main

type subCommand interface {
	name() string
	run()
}
