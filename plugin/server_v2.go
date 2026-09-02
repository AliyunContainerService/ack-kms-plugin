package plugin

import (
	"context"
	"fmt"

	"github.com/golang/glog"
	kmsv2 "k8s.io/kms/apis/v2"
)

const (
	KMSv2APIVersion = "v2"
	healthCheckText = "healthcheck"
)

// KMSV2Server implements k8s.io/kms/apis/v2.KeyManagementServiceServer.
type KMSV2Server struct {
	client Client
	keyID  string
	domain string
}

// NewKMSV2Server creates a v2 KMS server.
func NewKMSV2Server(client Client, keyID, domain string) *KMSV2Server {
	return &KMSV2Server{
		client: client,
		keyID:  keyID,
		domain: domain,
	}
}

// Status performs a health check by encrypting and decrypting a fixed plaintext.
func (s *KMSV2Server) Status(ctx context.Context, req *kmsv2.StatusRequest) (*kmsv2.StatusResponse, error) {
	encResp, err := s.client.Encrypt([]byte(healthCheckText))
	if err != nil {
		glog.Errorf("failed to encrypt healthcheck call, err: %v", err)
		return nil, err
	}

	plain, err := s.client.Decrypt(encResp.Ciphertext)
	if err != nil {
		glog.Errorf("failed to decrypt healthcheck call, err: %v", err)
		return nil, err
	}
	if string(plain) != healthCheckText {
		err := fmt.Errorf("decrypted text does not match")
		glog.Errorf("healthcheck failed, err: %v", err)
		return nil, err
	}

	return &kmsv2.StatusResponse{
		Version: KMSv2APIVersion,
		Healthz: "ok",
		KeyId:   encResp.KeyID,
	}, nil
}

// Encrypt encrypts plaintext using the KMS key.
func (s *KMSV2Server) Encrypt(ctx context.Context, req *kmsv2.EncryptRequest) (*kmsv2.EncryptResponse, error) {
	glog.V(4).Infof("v2 encrypt request started, uid: %s", req.Uid)

	encResp, err := s.client.Encrypt(req.Plaintext)
	if err != nil {
		glog.Errorf("failed to encrypt, uid %s, err: %v", req.Uid, err)
		return &kmsv2.EncryptResponse{}, err
	}

	glog.V(4).Infof("v2 encrypt request complete, uid: %s", req.Uid)
	return &kmsv2.EncryptResponse{
		Ciphertext:  encResp.Ciphertext,
		KeyId:       encResp.KeyID,
		Annotations: encResp.Annotations,
	}, nil
}

// Decrypt decrypts ciphertext.
func (s *KMSV2Server) Decrypt(ctx context.Context, req *kmsv2.DecryptRequest) (*kmsv2.DecryptResponse, error) {
	glog.V(4).Infof("v2 decrypt request started, uid: %s", req.Uid)

	plain, err := s.client.Decrypt(req.Ciphertext)
	if err != nil {
		glog.Errorf("failed to decrypt, uid %s, err: %v", req.Uid, err)
		return &kmsv2.DecryptResponse{}, err
	}

	return &kmsv2.DecryptResponse{Plaintext: plain}, nil
}
