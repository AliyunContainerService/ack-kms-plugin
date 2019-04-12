package cmd

import (
	"flag"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"fmt"
	"github.com/AliyunContainerService/ack-kms-plugin/plugin"
	"github.com/golang/glog"
	"strconv"
)

// NewRootCommand provides the method to start the kms server.
func NewRootCommand() *cobra.Command {
	var (
		glogLevel        int // --gloglevel
		keyID            string
		pathToUnixSocket string
	)

	var command = cobra.Command{
		Use:   "k8s-ali-kms",
		Short: "k8s-ali-kms enable encryption at rest of Kubernetes secret in etcd with Alibaba Cloud KMS",
		RunE: func(c *cobra.Command, args []string) error {
			_ = flag.CommandLine.Parse([]string{})
			_ = flag.Lookup("logtostderr").Value.Set("true")
			_ = flag.Lookup("v").Value.Set(strconv.Itoa(glogLevel))

			mustValidateFlags(pathToUnixSocket)
			signals := make(chan os.Signal, 1)
			signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

			p, err := plugin.New(pathToUnixSocket, keyID)
			if err != nil {
				glog.Fatalf("failed to init kmsPlugin, %v", err)
			}
			//start kms gRPC service
			gRPCSrv, kmsErrorChan := p.StartRPCServer()
			defer gRPCSrv.GracefulStop()

			for {
				select {
				case sig := <-signals:
					return fmt.Errorf("captured %v, shutting down", sig)
				case kmsError := <-kmsErrorChan:
					return kmsError
				}
			}

			return nil
		},
	}

	command.AddCommand(newCmdHealth())
	command.Flags().IntVar(&glogLevel, "gloglevel", 0, "Set the glog logging level")
	command.Flags().StringVar(&keyID, "key-id", "", "key id from alibaba cloud KMS.")
	command.Flags().StringVar(&pathToUnixSocket, "path-to-unix-socket", "/var/run/kmsplugin/socket.sock", "Full path to Unix socket that is used for communicating with KubeAPI Server, or Linux socket namespace object - must start with @")

	return &command
}

func mustValidateFlags(pathToUnixSocket string) {
	// Using an actual socket file instead of in-memory Linux socket namespace object.
	glog.Infof("Checking socket path %s", pathToUnixSocket)
	if !strings.HasPrefix(pathToUnixSocket, "@") {
		socketDir := filepath.Dir(pathToUnixSocket)
		_, err := os.Stat(socketDir)
		glog.Infof("Unix Socket directory is %s", socketDir)
		if err != nil && os.IsNotExist(err) {
			glog.Fatalf(" Directory %s portion of path-to-unix-socket flag:%s does not exist.", socketDir, pathToUnixSocket)
		}
	}
	glog.Infof("Communication between KUBE API and KMS Plugin containers will be via %s", pathToUnixSocket)
}
