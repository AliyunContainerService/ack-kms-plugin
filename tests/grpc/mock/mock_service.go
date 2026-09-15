// Package mock provides hand-written mocks of the Kubernetes KMS v1beta1
// and v2 KeyManagementService gRPC interfaces used in tests.
package mock

import (
	"context"

	kmsv1beta1 "k8s.io/kms/apis/v1beta1"
	kmsv2 "k8s.io/kms/apis/v2"
)

// V1Mock is a mock of the v1beta1 KeyManagementServiceServer interface.
type V1Mock struct{}

// NewV1Mock creates a new V1Mock.
func NewV1Mock() *V1Mock {
	return &V1Mock{}
}

// Version mocks the v1beta1 Version call.
func (m *V1Mock) Version(ctx context.Context, req *kmsv1beta1.VersionRequest) (*kmsv1beta1.VersionResponse, error) {
	return &kmsv1beta1.VersionResponse{Version: "v1beta1"}, nil
}

// Encrypt mocks the v1beta1 Encrypt call.
func (m *V1Mock) Encrypt(ctx context.Context, req *kmsv1beta1.EncryptRequest) (*kmsv1beta1.EncryptResponse, error) {
	return &kmsv1beta1.EncryptResponse{Cipher: req.Plain}, nil
}

// Decrypt mocks the v1beta1 Decrypt call.
func (m *V1Mock) Decrypt(ctx context.Context, req *kmsv1beta1.DecryptRequest) (*kmsv1beta1.DecryptResponse, error) {
	return &kmsv1beta1.DecryptResponse{Plain: req.Cipher}, nil
}

// V2Mock is a mock of the v2 KeyManagementServiceServer interface.
type V2Mock struct{}

// NewV2Mock creates a new V2Mock.
func NewV2Mock() *V2Mock {
	return &V2Mock{}
}

// Status mocks the v2 Status call.
func (m *V2Mock) Status(ctx context.Context, req *kmsv2.StatusRequest) (*kmsv2.StatusResponse, error) {
	return &kmsv2.StatusResponse{Version: "v2", Healthz: "ok", KeyId: "mock-key"}, nil
}

// Encrypt mocks the v2 Encrypt call.
func (m *V2Mock) Encrypt(ctx context.Context, req *kmsv2.EncryptRequest) (*kmsv2.EncryptResponse, error) {
	return &kmsv2.EncryptResponse{Ciphertext: req.Plaintext, KeyId: "mock-key"}, nil
}

// Decrypt mocks the v2 Decrypt call.
func (m *V2Mock) Decrypt(ctx context.Context, req *kmsv2.DecryptRequest) (*kmsv2.DecryptResponse, error) {
	return &kmsv2.DecryptResponse{Plaintext: req.Ciphertext}, nil
}
