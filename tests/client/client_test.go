package test

import (
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	kmsv1beta1 "k8s.io/kms/apis/v1beta1"
	kmsv2 "k8s.io/kms/apis/v2"
)

const (
	netProtocol      = "unix"
	pathToUnixSocket = "/var/run/kmsplugin/grpc.sock"
)

var (
	connection *grpc.ClientConn
	err        error
)

func setupTestCase(t *testing.T) func(t *testing.T) {
	t.Log("setup test case")
	connection, err = dialUnix(pathToUnixSocket)
	if err != nil {
		fmt.Printf("%s", err)
	}
	return func(t *testing.T) {
		t.Log("teardown test case")
		_ = connection.Close()
	}
}

// TestEncryptDecryptV2 exercises the v2 encrypt/decrypt round trip against a
// running kms plugin.
func TestEncryptDecryptV2(t *testing.T) {
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

	client := kmsv2.NewKeyManagementServiceClient(connection)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encryptRequest := kmsv2.EncryptRequest{Plaintext: tc.want}
			encryptResponse, err := client.Encrypt(context.Background(), &encryptRequest)
			if err != nil {
				t.Fatalf("failed encrypt from remote KMS provider: %v", err)
			}
			decryptRequest := kmsv2.DecryptRequest{Ciphertext: encryptResponse.Ciphertext}
			decryptResponse, err := client.Decrypt(context.Background(), &decryptRequest)
			if err != nil {
				t.Fatalf("failed decrypt from remote KMS provider: %v", err)
			}
			if string(decryptResponse.Plaintext) != string(tc.want) {
				t.Fatalf("Expected secret, but got %s - %v", string(decryptResponse.Plaintext), err)
			}
		})
	}
}

// TestEncryptDecryptV1 exercises the v1beta1 encrypt/decrypt round trip
// against a running kms plugin started with --enable-kms-v1.
func TestEncryptDecryptV1(t *testing.T) {
	cases := []struct {
		name     string
		want     []byte
		expected []byte
	}{
		{"text", []byte("test-data"), []byte("test-data")},
	}

	teardownTestCase := setupTestCase(t)
	defer teardownTestCase(t)

	client := kmsv1beta1.NewKeyManagementServiceClient(connection)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encryptRequest := kmsv1beta1.EncryptRequest{Version: "v1beta1", Plain: tc.want}
			encryptResponse, err := client.Encrypt(context.Background(), &encryptRequest)
			if err != nil {
				t.Fatalf("failed encrypt from remote KMS provider: %v", err)
			}
			decryptRequest := kmsv1beta1.DecryptRequest{Version: "v1beta1", Cipher: encryptResponse.Cipher}
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

func dialUnix(unixSocketPath string) (*grpc.ClientConn, error) {
	protocol, addr := "unix", unixSocketPath
	dialer := func(addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(protocol, addr, timeout)
	}
	return grpc.Dial(addr, grpc.WithInsecure(), grpc.WithDialer(dialer))
}
