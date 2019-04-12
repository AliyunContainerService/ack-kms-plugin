package cmd

import (
	"context"
	"flag"
	"fmt"
	"github.com/spf13/cobra"

	"net"
	"time"

	"github.com/golang/glog"

	"github.com/AliyunContainerService/ack-kms-plugin/plugin"
	k8spb "github.com/AliyunContainerService/ack-kms-plugin/v1beta1"
	"google.golang.org/grpc"
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

			if err := pingKMS(ctx, c); err != nil {
				glog.Fatalf("Exit cause unhealthy kms service")
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

func pingKMS(ctx context.Context, c k8spb.KeyManagementServiceClient) error {
	glog.V(4).Infof("test kms service ping...")

	plainText := []byte("secret")

	encryptRequest := k8spb.EncryptRequest{Version: plugin.Version, Plain: plainText}
	encryptResponse, err := c.Encrypt(ctx, &encryptRequest)
	if err != nil {
		return fmt.Errorf("failed to ping KMS: %v", err)
	}

	decryptRequest := k8spb.DecryptRequest{Version: plugin.Version, Cipher: encryptResponse.Cipher}
	_, err = c.Decrypt(context.Background(), &decryptRequest)
	if err != nil {
		return fmt.Errorf("failed to ping KMS: %v", err)
	}

	return nil
}

func dialUnix(unixSocketPath string) (*grpc.ClientConn, error) {
	protocol, addr := "unix", unixSocketPath
	dialer := func(addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(protocol, addr, timeout)
	}
	return grpc.Dial(addr, grpc.WithInsecure(), grpc.WithDialer(dialer))
}
