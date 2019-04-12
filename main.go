package main

import (
	"flag"
	"github.com/AliyunContainerService/ack-kms-plugin/cmd"

	"fmt"
	"github.com/spf13/pflag"
	"os"
)

// Run creates and executes kms plugin command
func Run() error {
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	pflag.Set("logtostderr", "true")
	pflag.CommandLine.MarkHidden("logtostderr")

	cmd := cmd.NewRootCommand()
	return cmd.Execute()
}

func main() {
	if err := Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
