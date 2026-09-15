// ack-kms-plugin serves the Kubernetes KMS gRPC interface for encryption at
// rest of secrets backed by Alibaba Cloud KMS.
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

	if err := pflag.Set("logtostderr", "true"); err != nil {
		return err
	}
	if err := pflag.CommandLine.MarkHidden("logtostderr"); err != nil {
		return err
	}

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
