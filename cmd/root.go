package cmd

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/AliyunContainerService/ack-kms-plugin/plugin"
	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"

	kmsv1beta1 "k8s.io/kms/apis/v1beta1"
	kmsv2 "k8s.io/kms/apis/v2"
)

// NewRootCommand provides the method to start the kms server.
func NewRootCommand() *cobra.Command {
	var (
		glogLevel        int // --gloglevel
		keyID            string
		pathToUnixSocket string
		enableKMSV1      bool
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

			// Create the shared KMS client used by both v1 and v2 services.
			kmsClient, err := plugin.NewKMSClient(keyID)
			if err != nil {
				glog.Fatalf("failed to create kms client, %v", err)
			}

			// Clean up stale socket.
			if err := unix.Unlink(pathToUnixSocket); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to delete socket file: %w", err)
			}

			listener, err := net.Listen("unix", pathToUnixSocket)
			if err != nil {
				return fmt.Errorf("failed to listen addr %s: %w", pathToUnixSocket, err)
			}
			glog.Infof("Listening for connections, addr %s", listener.Addr().String())

			server := grpc.NewServer()

			// Always register v2.
			kmsv2.RegisterKeyManagementServiceServer(server, plugin.NewKMSV2Server(kmsClient, keyID, ""))
			glog.Infof("registered KMS v2 service")

			// Optionally register v1beta1 for legacy clusters.
			if enableKMSV1 {
				kmsv1beta1.RegisterKeyManagementServiceServer(server, plugin.New(kmsClient))
				glog.Infof("registered KMS v1beta1 service")
			}

			go func() {
				if err := server.Serve(listener); err != nil {
					glog.Fatalf("failed to serve kms server: %v", err)
				}
			}()

			select {
			case sig := <-signals:
				glog.Infof("captured %v, shutting down", sig)
			}

			server.GracefulStop()
			return nil
		},
	}

	command.AddCommand(newCmdHealth())
	command.Flags().IntVar(&glogLevel, "gloglevel", 0, "Set the glog logging level")
	command.Flags().StringVar(&keyID, "key-id", "", "key id from alibaba cloud KMS.")
	command.Flags().StringVar(&pathToUnixSocket, "path-to-unix-socket", "/var/run/kmsplugin/socket.sock", "Full path to Unix socket that is used for communicating with KubeAPI Server, or Linux socket namespace object - must start with @")
	command.Flags().BoolVar(&enableKMSV1, "enable-kms-v1", false, "Register both v1beta1 and v2 KMS services. When disabled, only v2 is registered.")

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
