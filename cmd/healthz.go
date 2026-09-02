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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	kmsv1beta1 "k8s.io/kms/apis/v1beta1"
	kmsv2 "k8s.io/kms/apis/v2"
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

			if err := pingRPC(ctx, connection, unixSocketPath); err != nil {
				glog.Fatalf("Exit cause unhealthy rpc connection")
			}
		},
	}
	command.Flags().StringVar(&unixSocketPath, "path-to-unix-socket", "/var/run/kmsplugin/socket.sock", "Full path to Unix socket that is used for communicating with KubeAPI Server, or Linux socket namespace object - must start with @")

	return command
}

// pingRPC checks server health via the v2 Status RPC, falling back to the
// v1beta1 Version RPC for legacy servers that only serve v1beta1.
func pingRPC(ctx context.Context, connection *grpc.ClientConn, unixSocketPath string) error {
	fmt.Printf("test gRPC ping...")

	err := pingRPCV2(ctx, kmsv2.NewKeyManagementServiceClient(connection), unixSocketPath)
	if err == nil {
		glog.V(4).Infof("Successfully pinged gRPC via %s", unixSocketPath)
		return nil
	}
	if status.Code(err) != codes.Unimplemented {
		fmt.Printf("failed to retrieve status from gRPC endpoint:%s, error: %v", unixSocketPath, err)
		return fmt.Errorf("failed to retrieve status from gRPC endpoint:%s, error: %v", unixSocketPath, err)
	}

	// The server does not implement v2; fall back to v1beta1.
	return pingRPCV1(ctx, kmsv1beta1.NewKeyManagementServiceClient(connection), unixSocketPath)
}

func pingRPCV2(ctx context.Context, c kmsv2.KeyManagementServiceClient, unixSocketPath string) error {
	r := &kmsv2.StatusRequest{}
	if _, err := c.Status(ctx, r); err != nil {
		// Return the raw error so callers can inspect the gRPC status code.
		return err
	}
	return nil
}

func pingRPCV1(ctx context.Context, c kmsv1beta1.KeyManagementServiceClient, unixSocketPath string) error {
	r := &kmsv1beta1.VersionRequest{Version: "v1beta1"}
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
