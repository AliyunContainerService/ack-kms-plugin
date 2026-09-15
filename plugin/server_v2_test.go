package plugin

import (
	"context"
	"errors"
	"testing"

	kmsv2 "k8s.io/kms/apis/v2"
	"k8s.io/kms/pkg/service"
)

type fakeClient struct {
	encryptFunc func([]byte) (*service.EncryptResponse, error)
	decryptFunc func([]byte) ([]byte, error)
}

func (f *fakeClient) Encrypt(plain []byte) (*service.EncryptResponse, error) {
	return f.encryptFunc(plain)
}

func (f *fakeClient) Decrypt(cipher []byte) ([]byte, error) {
	return f.decryptFunc(cipher)
}

func TestKMSV2Server_Status_OK(t *testing.T) {
	server := NewKMSV2Server(&fakeClient{
		encryptFunc: func(plain []byte) (*service.EncryptResponse, error) {
			return &service.EncryptResponse{
				Ciphertext: []byte("cipher"),
				KeyID:      "key-123",
				Annotations: map[string][]byte{
					"x-acs-kms-key-version-id.ack.alibabacloud.com": []byte("v1"),
				},
			}, nil
		},
		decryptFunc: func(cipher []byte) ([]byte, error) {
			return []byte(healthCheckText), nil
		},
	}, "key-123", "kms-vpc.cn-hangzhou.aliyuncs.com")

	resp, err := server.Status(context.Background(), &kmsv2.StatusRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Version != KMSv2APIVersion {
		t.Errorf("expected version %q, got %q", KMSv2APIVersion, resp.Version)
	}
	if resp.Healthz != "ok" {
		t.Errorf("expected healthz ok, got %q", resp.Healthz)
	}
	if resp.KeyId != "key-123" {
		t.Errorf("expected keyId key-123, got %q", resp.KeyId)
	}
}

func TestKMSV2Server_Status_DecryptMismatch(t *testing.T) {
	server := NewKMSV2Server(&fakeClient{
		encryptFunc: func(plain []byte) (*service.EncryptResponse, error) {
			return &service.EncryptResponse{Ciphertext: []byte("cipher")}, nil
		},
		decryptFunc: func(cipher []byte) ([]byte, error) {
			return []byte("wrong"), nil
		},
	}, "key-123", "")

	_, err := server.Status(context.Background(), &kmsv2.StatusRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestKMSV2Server_Encrypt(t *testing.T) {
	server := NewKMSV2Server(&fakeClient{
		encryptFunc: func(plain []byte) (*service.EncryptResponse, error) {
			return &service.EncryptResponse{
				Ciphertext: []byte("cipher"),
				KeyID:      "key-123",
				Annotations: map[string][]byte{
					"x-acs-request-id.ack.alibabacloud.com": []byte("req-1"),
				},
			}, nil
		},
	}, "key-123", "")

	resp, err := server.Encrypt(context.Background(), &kmsv2.EncryptRequest{Plaintext: []byte("hello")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Ciphertext) != "cipher" {
		t.Errorf("expected ciphertext cipher, got %s", resp.Ciphertext)
	}
	if resp.KeyId != "key-123" {
		t.Errorf("expected keyId key-123, got %s", resp.KeyId)
	}
	if string(resp.Annotations["x-acs-request-id.ack.alibabacloud.com"]) != "req-1" {
		t.Errorf("expected annotation req-1")
	}
}

func TestKMSV2Server_Decrypt(t *testing.T) {
	server := NewKMSV2Server(&fakeClient{
		decryptFunc: func(cipher []byte) ([]byte, error) {
			return []byte("hello"), nil
		},
	}, "key-123", "")

	resp, err := server.Decrypt(context.Background(), &kmsv2.DecryptRequest{Ciphertext: []byte("cipher")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Plaintext) != "hello" {
		t.Errorf("expected plaintext hello, got %s", resp.Plaintext)
	}
}

func TestKMSV2Server_EncryptError(t *testing.T) {
	server := NewKMSV2Server(&fakeClient{
		encryptFunc: func(plain []byte) (*service.EncryptResponse, error) {
			return nil, errors.New("boom")
		},
	}, "key-123", "")

	_, err := server.Encrypt(context.Background(), &kmsv2.EncryptRequest{Plaintext: []byte("hello")})
	if err == nil {
		t.Fatal("expected error")
	}
}
