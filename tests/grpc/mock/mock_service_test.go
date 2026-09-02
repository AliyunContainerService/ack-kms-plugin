package mock

import (
	"context"
	"testing"

	kmsv1beta1 "k8s.io/kms/apis/v1beta1"
	kmsv2 "k8s.io/kms/apis/v2"
)

func TestV1Mock(t *testing.T) {
	m := NewV1Mock()

	v, err := m.Version(context.Background(), &kmsv1beta1.VersionRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Version != "v1beta1" {
		t.Errorf("expected version v1beta1, got %q", v.Version)
	}

	enc, err := m.Encrypt(context.Background(), &kmsv1beta1.EncryptRequest{Plain: []byte("data")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(enc.Cipher) != "data" {
		t.Errorf("expected cipher data, got %s", enc.Cipher)
	}

	dec, err := m.Decrypt(context.Background(), &kmsv1beta1.DecryptRequest{Cipher: []byte("data")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(dec.Plain) != "data" {
		t.Errorf("expected plain data, got %s", dec.Plain)
	}
}

func TestV2Mock(t *testing.T) {
	m := NewV2Mock()

	st, err := m.Status(context.Background(), &kmsv2.StatusRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.Version != "v2" || st.Healthz != "ok" || st.KeyId != "mock-key" {
		t.Errorf("unexpected status response: %+v", st)
	}

	enc, err := m.Encrypt(context.Background(), &kmsv2.EncryptRequest{Plaintext: []byte("data")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(enc.Ciphertext) != "data" || enc.KeyId != "mock-key" {
		t.Errorf("unexpected encrypt response: %+v", enc)
	}

	dec, err := m.Decrypt(context.Background(), &kmsv2.DecryptRequest{Ciphertext: []byte("data")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(dec.Plaintext) != "data" {
		t.Errorf("expected plaintext data, got %s", dec.Plaintext)
	}
}
