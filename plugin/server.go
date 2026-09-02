package plugin

import (
	"context"

	"github.com/golang/glog"

	k8spb "k8s.io/kms/apis/v1beta1"
)

const (
	Version        = "v1beta1"
	runtime        = "Alibaba Cloud KMS"
	runtimeVersion = "0.1.0"
)

// KMSServer is the v1beta1 Cloud KMS plugin server.
type KMSServer struct {
	client Client
	stopCh chan struct{}
}

// New creates an instance of the v1beta1 KMS Service Server.
func New(client Client) *KMSServer {
	return &KMSServer{
		client: client,
		stopCh: make(chan struct{}),
	}
}

// Version returns the current API version.
func (s *KMSServer) Version(ctx context.Context, request *k8spb.VersionRequest) (*k8spb.VersionResponse, error) {
	glog.V(4).Infoln(Version)
	return &k8spb.VersionResponse{Version: Version, RuntimeName: runtime, RuntimeVersion: runtimeVersion}, nil
}

// Encrypt executes encryption operation.
func (s *KMSServer) Encrypt(ctx context.Context, request *k8spb.EncryptRequest) (*k8spb.EncryptResponse, error) {
	glog.V(4).Infoln("Processing v1 EncryptRequest")

	encResp, err := s.client.Encrypt(request.Plain)
	if err != nil {
		glog.Errorf("Failed to encrypt, error: %v", err)
		return &k8spb.EncryptResponse{}, err
	}

	glog.V(4).Infof("v1 Encrypt request finish")
	return &k8spb.EncryptResponse{Cipher: encResp.Ciphertext}, nil
}

// Decrypt executes decryption operation.
func (s *KMSServer) Decrypt(ctx context.Context, request *k8spb.DecryptRequest) (*k8spb.DecryptResponse, error) {
	glog.V(4).Infoln("Processing v1 DecryptRequest")

	plain, err := s.client.Decrypt(request.Cipher)
	if err != nil {
		glog.Errorf("failed to decrypt, error: %v", err)
		return &k8spb.DecryptResponse{}, err
	}

	return &k8spb.DecryptResponse{Plain: plain}, nil
}
