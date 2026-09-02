package plugin

import (
	"context"
	"errors"
	"testing"

	k8spb "k8s.io/kms/apis/v1beta1"
	"k8s.io/kms/pkg/service"
)

func TestKMSServer_Version(t *testing.T) {
	s := &KMSServer{client: &fakeClient{}}
	resp, err := s.Version(context.Background(), &k8spb.VersionRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Version != Version {
		t.Errorf("expected version %q, got %q", Version, resp.Version)
	}
	if resp.RuntimeName != runtime {
		t.Errorf("expected runtime %q, got %q", runtime, resp.RuntimeName)
	}
}

func TestKMSServer_Encrypt(t *testing.T) {
	s := &KMSServer{client: &fakeClient{
		encryptFunc: func(plain []byte) (*service.EncryptResponse, error) {
			return &service.EncryptResponse{Ciphertext: []byte("cipher")}, nil
		},
	}}
	resp, err := s.Encrypt(context.Background(), &k8spb.EncryptRequest{Plain: []byte("hello")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Cipher) != "cipher" {
		t.Errorf("expected cipher cipher, got %s", resp.Cipher)
	}
}

func TestKMSServer_Decrypt(t *testing.T) {
	s := &KMSServer{client: &fakeClient{
		decryptFunc: func(cipher []byte) ([]byte, error) {
			return []byte("hello"), nil
		},
	}}
	resp, err := s.Decrypt(context.Background(), &k8spb.DecryptRequest{Cipher: []byte("cipher")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Plain) != "hello" {
		t.Errorf("expected plain hello, got %s", resp.Plain)
	}
}

func TestKMSServer_EncryptError(t *testing.T) {
	s := &KMSServer{client: &fakeClient{
		encryptFunc: func(plain []byte) (*service.EncryptResponse, error) {
			return nil, errors.New("boom")
		},
	}}
	_, err := s.Encrypt(context.Background(), &k8spb.EncryptRequest{Plain: []byte("hello")})
	if err == nil {
		t.Fatal("expected error")
	}
}
