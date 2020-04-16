package main

import (
	"fmt"
	"os"
)

type decCommand struct {
}

func (c *decCommand) run() {
	fmt.Println("run dec")
}

func (c *decCommand) name() string {
	return "dec"
}

type helpCommand struct {
}

func (c *helpCommand) run() {
	fmt.Println("run help")
}

func (c *helpCommand) name() string {
	return "help"
}

func subCommands() []subCommand {
	return []subCommand{
		&encCommand{},
		&decCommand{},
		&helpCommand{},
	}
}

func showCommands() {
	fmt.Println(
		"usage : cusfeist <subcommand> [options] [args]\n" +
			"Type 'cusfeist help <subcommand>' for help on a specific subcommand.\n" +
			"\nAvailable subcommands:")
	for _, cmd := range subCommands() {
		fmt.Println("  ", cmd.name())
	}
}

func main() {
	if 1 < len(os.Args) {
		for _, cmd := range subCommands() {
			if cmd.name() == os.Args[1] {
				cmd.run()
				return
			}
		}
	}
	showCommands()
	return
}
