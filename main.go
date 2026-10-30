package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := execute(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Tower Agent:", err)
		os.Exit(1)
	}
}

func execute(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("use: tower-agent install --url HTTPS_ORIGIN --id UUID | run | version")
	}
	a := newAgent()
	switch args[0] {
	case "version", "--version":
		fmt.Println("Tower Agent " + version + " (protocol 4)")
		return nil
	case "install":
		flags := flag.NewFlagSet("install", flag.ContinueOnError)
		url := flags.String("url", "", "HTTPS origin of the Tower Panel")
		id := flags.String("id", "", "Agent ID from the panel")
		if err := flags.Parse(args[1:]); err != nil {
			return fmt.Errorf("invalid install arguments")
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected install arguments")
		}
		return a.install(ctx, *url, *id)
	case "run":
		if len(args) != 1 {
			return fmt.Errorf("run does not accept arguments")
		}
		return a.serve(ctx)
	default:
		return fmt.Errorf("unknown command; use install, run or version")
	}
}
