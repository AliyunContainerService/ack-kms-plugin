package cmd

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/AliyunContainerService/ack-kms-plugin/tests/grpc/mock"

	kmsv1beta1 "k8s.io/kms/apis/v1beta1"
	kmsv2 "k8s.io/kms/apis/v2"
)

func serve(t *testing.T, register func(*grpc.Server)) string {
	t.Helper()
	tmpDir := t.TempDir()
	socketPath := tmpDir + "/kms.sock"
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	server := grpc.NewServer()
	register(server)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(server.Stop)
	return socketPath
}

func dial(t *testing.T, socketPath string) *grpc.ClientConn {
	t.Helper()
	connection, err := dialUnix(socketPath)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	// dialUnix is lazy; force the connection to be established.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !connection.WaitForStateChange(ctx, connection.GetState()) {
		t.Fatal("connection state change timeout")
	}
	return connection
}

func TestPingRPC_V2OnlyServer(t *testing.T) {
	socketPath := serve(t, func(s *grpc.Server) {
		kmsv2.RegisterKeyManagementServiceServer(s, mock.NewV2Mock())
	})
	connection := dial(t, socketPath)

	if err := pingRPC(context.Background(), connection, socketPath); err != nil {
		t.Fatalf("expected healthy against v2-only server, got: %v", err)
	}
}

func TestPingRPC_V1OnlyServer(t *testing.T) {
	socketPath := serve(t, func(s *grpc.Server) {
		kmsv1beta1.RegisterKeyManagementServiceServer(s, mock.NewV1Mock())
	})
	connection := dial(t, socketPath)

	if err := pingRPC(context.Background(), connection, socketPath); err != nil {
		t.Fatalf("expected healthy against v1beta1-only server via fallback, got: %v", err)
	}
}

func TestPingRPC_V1V2Server(t *testing.T) {
	socketPath := serve(t, func(s *grpc.Server) {
		kmsv2.RegisterKeyManagementServiceServer(s, mock.NewV2Mock())
		kmsv1beta1.RegisterKeyManagementServiceServer(s, mock.NewV1Mock())
	})
	connection := dial(t, socketPath)

	if err := pingRPC(context.Background(), connection, socketPath); err != nil {
		t.Fatalf("expected healthy against v1+v2 server, got: %v", err)
	}
}
