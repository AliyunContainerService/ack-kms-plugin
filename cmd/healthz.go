package cmd

import (
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	k8spb "github.com/AliyunContainerService/ack-kms-plugin/v1beta1"
)

// newCmdHealth provides healthcheck method for kms server.
func newCmdHealth() *cobra.Command {
	var (
		unixSocketPath string
	)

	var command = &cobra.Command{
		Use:   "health",
		Short: "Checking kms-plugin healthy",
		Run: func(cmd *cobra.Command, args []string) {
			_ = flag.CommandLine.Parse([]string{})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			connection, err := dialUnix(unixSocketPath)
			if err != nil {
				glog.Fatalf("Exit cause unhealthy socket connection")

			}
			defer connection.Close()

			c := k8spb.NewKeyManagementServiceClient(connection)

			if err := pingRPC(ctx, c, unixSocketPath); err != nil {
				glog.Fatalf("Exit cause unhealthy rpc connection")
			}
		},
	}
	command.Flags().StringVar(&unixSocketPath, "path-to-unix-socket", "/var/run/kmsplugin/socket.sock", "Full path to Unix socket that is used for communicating with KubeAPI Server, or Linux socket namespace object - must start with @")

	return command
}

func pingRPC(ctx context.Context, c k8spb.KeyManagementServiceClient, unixSocketPath string) error {
	fmt.Printf("test gRPC ping...")

	r := &k8spb.VersionRequest{Version: "v1beta1"}
	if _, err := c.Version(ctx, r); err != nil {
		fmt.Printf("failed to retrieve version from gRPC endpoint:%s, error: %v", unixSocketPath, err)

		return fmt.Errorf("failed to retrieve version from gRPC endpoint:%s, error: %v", unixSocketPath, err)
	}

	glog.V(4).Infof("Successfully pinged gRPC via %s", unixSocketPath)
	return nil
}

func dialUnix(unixSocketPath string) (*grpc.ClientConn, error) {
	protocol, addr := "unix", unixSocketPath
	dialer := func(addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(protocol, addr, timeout)
	}
	return grpc.Dial(addr, grpc.WithInsecure(), grpc.WithDialer(dialer))
}
