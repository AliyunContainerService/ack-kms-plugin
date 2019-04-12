package test

import (
	"testing"

	"fmt"
	"net"
	"time"

	k8spb "github.com/AliyunContainerService/ack-kms-plugin/v1beta1"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	netProtocol      = "unix"
	pathToUnixSocket = "/var/run/kmsplugin/grpc.sock"
	version          = "v1beta1"
)

var (
	client     k8spb.KeyManagementServiceClient
	connection *grpc.ClientConn
	err        error
)

func setupTestCase(t *testing.T) func(t *testing.T) {
	t.Log("setup test case")
	connection, err = dialUnix(pathToUnixSocket)
	if err != nil {
		fmt.Printf("%s", err)
	}
	client = k8spb.NewKeyManagementServiceClient(connection)
	return func(t *testing.T) {
		t.Log("teardown test case")
		connection.Close()
	}
}

func TestEncryptDecrypt(t *testing.T) {
	cases := []struct {
		name     string
		want     []byte
		expected []byte
	}{
		{"text", []byte("test-data"), []byte("test-data")},
		{"number", []byte("zxc1234"), []byte("zxc1234")},
		{"special", []byte("!@#$%^&*()_+"), []byte("!@#$%^&*()_+")},
	}

	teardownTestCase := setupTestCase(t)
	defer teardownTestCase(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encryptRequest := k8spb.EncryptRequest{Version: version, Plain: tc.want}
			encryptResponse, err := client.Encrypt(context.Background(), &encryptRequest)
			if err != nil {
				t.Fatalf("failed encrypt from remote KMS provider: %v", err)
			}
			decryptRequest := k8spb.DecryptRequest{Version: version, Cipher: encryptResponse.Cipher}
			decryptResponse, err := client.Decrypt(context.Background(), &decryptRequest)
			if err != nil {
				t.Fatalf("failed decrypt from remote KMS provider: %v", err)
			}
			if string(decryptResponse.Plain) != string(tc.want) {
				t.Fatalf("Expected secret, but got %s - %v", string(decryptResponse.Plain), err)
			}
		})
	}
}

// Verify the KMS plugin version.
func TestVersion(t *testing.T) {
	cases := []struct {
		name     string
		want     string
		expected string
	}{
		{"v1beta1", "v1beta1", "v1beta1"},
	}

	teardownTestCase := setupTestCase(t)
	defer teardownTestCase(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {

			request := &k8spb.VersionRequest{Version: tc.want}
			response, err := client.Version(context.Background(), request)
			if err != nil {
				t.Fatalf("failed get version from remote KMS provider: %v", err)
			}
			if response.Version != tc.want {
				t.Fatalf("KMS provider api version %s is not supported, only %s is supported now", tc.want, version)
			}
		})
	}
}

func dialUnix(unixSocketPath string) (*grpc.ClientConn, error) {
	protocol, addr := "unix", unixSocketPath
	dialer := func(addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(protocol, addr, timeout)
	}
	return grpc.Dial(addr, grpc.WithInsecure(), grpc.WithDialer(dialer))
}
