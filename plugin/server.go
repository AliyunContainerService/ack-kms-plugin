package plugin

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
	"github.com/golang/glog"
	"golang.org/x/net/context"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"

	k8spb "github.com/AliyunContainerService/ack-kms-plugin/v1beta1"
)

const (
	// Unix Domain Socket
	netProtocol = "unix"
	// Version is the current kms api version
	Version        = "v1beta1"
	runtime        = "Alibaba Cloud KMS"
	runtimeVersion = "0.1.0"
	// REGION is region id env
	REGION = "REGION"
	//KEY_USAGE_ENCRYPT_DECRYPT is the usage of kms key
	KEY_USAGE_ENCRYPT_DECRYPT = "ENCRYPT/DECRYPT"
	// HTTPS protocol
	HTTPS = "https"
)

// KMSServer is t CloudKMS plugin for K8S.
type KMSServer struct {
	client           *kms.Client
	domain           string //kms domain
	keyID            string // *kms.KeyMetadata
	pathToUnixSocket string
	net.Listener
	*grpc.Server
}

// New creates an instance of the KMS Service Server.
func New(pathToUnixSocketFile, keyID string) (*KMSServer, error) {
	KMSServer := new(KMSServer)
	KMSServer.pathToUnixSocket = pathToUnixSocketFile
	KMSServer.keyID = keyID
	region := GetMetaData(RegionID)
	if region == "" {
		return nil, fmt.Errorf("empty region set in env")
	}
	KMSServer.domain = fmt.Sprintf("kms-vpc.%s.aliyuncs.com", region)

	//TODO init kms client with sts token
	accessKey := os.Getenv("ACCESS_KEY_ID")
	accessSecret := os.Getenv("ACCESS_KEY_SECRET")
	if accessKey == "" || accessSecret == "" {
		return nil, fmt.Errorf("empty AK env set in env")
	}
	client, err := kms.NewClientWithAccessKey(region, accessKey, accessSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to init kms client, err: %v", client)
	}
	KMSServer.client = client
	return KMSServer, nil
}

//generate alibaba cloud kms key
func (s *KMSServer) getKey(client *kms.Client) (string, error) {
	args := &kms.CreateKeyRequest{
		KeyUsage:    KEY_USAGE_ENCRYPT_DECRYPT,
		Description: fmt.Sprintf("kms-plugin-%d", time.Now().Unix()),
	}
	//args.Domain = s.domain
	args.SetScheme(HTTPS)
	response, err := client.CreateKey(args)
	if err != nil {
		glog.Errorf("Failed to generate kms key, err: %++v", err)
		return "", err
	}
	glog.V(4).Infof("Success generate kms key = %++v", response)
	return response.KeyMetadata.KeyId, nil

}

func (s *KMSServer) setupRPCServer() error {
	if err := s.cleanSockFile(); err != nil {
		return err
	}

	listener, err := net.Listen(netProtocol, s.pathToUnixSocket)
	if err != nil {
		return fmt.Errorf("failed to start listener, error: %v", err)
	}
	s.Listener = listener
	glog.Infof("register unix domain socket: %s", s.pathToUnixSocket)
	server := grpc.NewServer()
	k8spb.RegisterKeyManagementServiceServer(server, s)
	s.Server = server

	return nil
}

// StartRPCServer starts gRPC server or dies.
func (s *KMSServer) StartRPCServer() (*grpc.Server, chan error) {
	errorChan := make(chan error, 1)
	if err := s.setupRPCServer(); err != nil {
		errorChan <- err
		close(errorChan)
		return nil, errorChan
	}

	go func() {
		defer close(errorChan)
		errorChan <- s.Serve(s.Listener)
	}()
	glog.V(4).Infof("kms server started successfully.")

	return s.Server, errorChan
}

//Version return the current api version
func (s *KMSServer) Version(ctx context.Context, request *k8spb.VersionRequest) (*k8spb.VersionResponse, error) {
	glog.V(4).Infoln(Version)
	return &k8spb.VersionResponse{Version: Version, RuntimeName: runtime, RuntimeVersion: runtimeVersion}, nil
}

//Encrypt execute encryption operation in KMS provider.
func (s *KMSServer) Encrypt(ctx context.Context, request *k8spb.EncryptRequest) (*k8spb.EncryptResponse, error) {
	glog.V(4).Infoln("Processing EncryptRequest: ")
	if s.keyID == "" {
		key, err := s.getKey(s.client)
		if err != nil {
			return nil, err
		}
		s.keyID = key
	}

	glog.V(4).Infof("domain %s , key %s", s.domain, s.keyID)

	encReq := kms.CreateEncryptRequest()
	encReq.KeyId = s.keyID
	encReq.Plaintext = base64.StdEncoding.EncodeToString(request.Plain)
	encReq.Domain = s.domain
	encReq.SetScheme(HTTPS)
	encReq.SetHTTPSInsecure(true)
	response, err := s.client.Encrypt(encReq)
	if err != nil {
		glog.Errorf("Failed to encrypt, error: %v", err)
		return &k8spb.EncryptResponse{}, err
	}

	//cipher, err := base64.StdEncoding.DecodeString(response.CiphertextBlob)
	//if err != nil {
	//	return nil, err
	//}
	glog.V(4).Infof("Encrypt request %s finish", response.RequestId)

	return &k8spb.EncryptResponse{Cipher: []byte(response.CiphertextBlob)}, nil
}

//Decrypt execute decryption operation in KMS provider.
func (s *KMSServer) Decrypt(ctx context.Context, request *k8spb.DecryptRequest) (*k8spb.DecryptResponse, error) {
	glog.V(4).Infoln("Processing DecryptRequest: ")

	if s.keyID == "" {
		glog.Errorf("Empty key found to decrypt...")
		return &k8spb.DecryptResponse{}, fmt.Errorf("empty key found to decrypt")
	}

	if s.keyID == "" {
		key, err := s.getKey(s.client)
		if err != nil {
			return nil, err
		}
		s.keyID = key
	}
	decReq := kms.CreateDecryptRequest()
	decReq.CiphertextBlob = string(request.Cipher)
	decReq.Domain = s.domain
	decReq.SetScheme(HTTPS)
	decReq.SetHTTPSInsecure(true)

	response, err := s.client.Decrypt(decReq)
	if err != nil {
		glog.Errorf("failed to decrypt, error: %v", err)
		return &k8spb.DecryptResponse{}, err
	}

	plain, err := base64.RawURLEncoding.DecodeString(response.Plaintext)
	if err != nil {
		glog.Errorf("failed to decode plain text, error: %v", err)
		return &k8spb.DecryptResponse{}, err
	}
	return &k8spb.DecryptResponse{Plain: plain}, nil
}

func (s *KMSServer) cleanSockFile() error {
	err := unix.Unlink(s.pathToUnixSocket)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete socket file, error: %v", err)
	}
	return nil
}
