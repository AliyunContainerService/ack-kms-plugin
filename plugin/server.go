package plugin

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	aliCloudAuth "github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials/providers"
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
	// envRegion is region id env
	envRegion = "ACK_KMS_REGION_ID"
	// envKmsDomain is kms domain env
	envKmsDomain     = "ACK_KMS_DOMAIN"
	defaultKmsDomain = "kms-vpc.%s.aliyuncs.com"
	// KeyUsageEncryptDecrypt is the usage of kms key
	keyUsageEncryptDecrypt = "ENCRYPT/DECRYPT"
	// HTTPS protocol
	HTTPS = "https"
	// credential from meta server would expire every 8 mins
	defaultCredCheckFreqSeconds = 480
)

// KMSServer is t CloudKMS plugin for K8S.
type KMSServer struct {
	client           *kms.Client
	domain           string //kms domain
	region           string //kms region id
	keyID            string // *kms.KeyMetadata
	pathToUnixSocket string
	net.Listener
	*grpc.Server
	credLock  sync.RWMutex //share the latest credentials across goroutines.
	lastCreds aliCloudAuth.Credential
	stopCh    chan struct{} // Detects if the kms server is closing.
}

// New creates an instance of the KMS Service Server.
func New(pathToUnixSocketFile, keyID string) (*KMSServer, error) {
	kMSServer := &KMSServer{
		stopCh: make(chan struct{}),
	}
	kMSServer.pathToUnixSocket = pathToUnixSocketFile
	kMSServer.keyID = keyID
	region := os.Getenv(envRegion)
	if region == "" {
		region = GetMetaData(RegionID)
	}
	if region == "" {
		return nil, fmt.Errorf("empty region set in env")
	}
	domain := os.Getenv(envKmsDomain)
	if domain == "" {
		domain = defaultKmsDomain
	}
	if strings.Contains(domain, "%s") {
		domain = fmt.Sprintf(domain, region)
	}
	kMSServer.region = region
	kMSServer.domain = domain
	// Check for an optional custom frequency at which we should poll for creds.
	credCheckFreqSec := defaultCredCheckFreqSeconds
	checkFreqSecRaw := os.Getenv("CREDENTIAL_INTERVAL")
	if checkFreqSecRaw != "" {
		glog.V(4).Infof("use customized credential pull interval %s", checkFreqSecRaw)
		checkFreqSecInt, err := strconv.Atoi(checkFreqSecRaw)
		if err != nil {
			return nil, fmt.Errorf("could not convert 'CREDENTIAL_INTERVAL' value to int")
		}
		// should less than 30 minutes
		if checkFreqSecInt >= 1800 {
			return nil, fmt.Errorf("the value of 'CREDENTIAL_INTERVAL' should less than 1800")
		}
		credCheckFreqSec = checkFreqSecInt
	}

	credConfig := &providers.Configuration{}
	credConfig.AccessKeyID = os.Getenv("ACCESS_KEY_ID")
	credConfig.AccessKeySecret = os.Getenv("ACCESS_KEY_SECRET")
	credentialChain := []providers.Provider{
		providers.NewConfigurationCredentialProvider(credConfig),
		providers.NewInstanceMetadataProvider(),
	}
	credProvider := providers.NewChainProvider(credentialChain)

	// Do an initial population of the creds because we want to err right away if we can't
	// even get a first set.
	lastCreds, err := credProvider.Retrieve()
	if err != nil {
		return nil, err
	}
	clientConfig := sdk.NewConfig()
	clientConfig.Scheme = "https"
	client, err := kms.NewClientWithOptions(region, clientConfig, lastCreds)
	if err != nil {
		return nil, fmt.Errorf("failed to init kms client, err: %v", err)
	}
	kMSServer.lastCreds = lastCreds
	kMSServer.client = client
	//loop to refresh the client credential
	if credConfig.AccessKeyID == "" || credConfig.AccessKeySecret == "" {
		go kMSServer.pullForCreds(credProvider, credCheckFreqSec)
	}
	return kMSServer, nil
}

//refresh the client credential if ak not set
func (s *KMSServer) pullForCreds(credProvider providers.Provider, frequencySeconds int) {
	ticker := time.NewTicker(time.Duration(frequencySeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			glog.Warningf("stopping the pulling channel")
			return
		case <-ticker.C:
			if err := s.checkCredentials(credProvider); err != nil {
				glog.Warningf("unable to retrieve current credentials, error: %v", err)
			}
		}
	}
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
		defer func() {
			close(errorChan)
			close(s.stopCh)
		}()
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

//Encrypt execute encryption operation in KMS providers.
func (s *KMSServer) Encrypt(ctx context.Context, request *k8spb.EncryptRequest) (*k8spb.EncryptResponse, error) {
	glog.V(4).Infoln("Processing EncryptRequest: ")
	if s.keyID == "" {
		glog.Errorf("Empty key found to encrypt...")
		return &k8spb.EncryptResponse{}, fmt.Errorf("empty key found to encrypt")
	}
	glog.V(4).Infof("domain %s , key %s", s.domain, s.keyID)

	encReq := kms.CreateEncryptRequest()
	encReq.KeyId = s.keyID
	encReq.Plaintext = base64.StdEncoding.EncodeToString(request.Plain)
	encReq.Domain = s.domain
	encReq.SetScheme(HTTPS)

	s.credLock.RLock()
	client := *s.client
	s.credLock.RUnlock()

	response, err := client.Encrypt(encReq)
	if err != nil {
		glog.Errorf("Failed to encrypt, error: %v", err)
		return &k8spb.EncryptResponse{}, err
	}
	if !response.IsSuccess() || response.CiphertextBlob == "" {
		glog.Errorf("failed to encrypt, unexpected response: %s", response.GetHttpContentString())
		return &k8spb.EncryptResponse{}, fmt.Errorf(
			"failed to encrypt, unexpected response: %s", response.GetHttpContentString())
	}

	glog.V(4).Infof("Encrypt request %s finish", response.RequestId)

	return &k8spb.EncryptResponse{Cipher: []byte(response.CiphertextBlob)}, nil
}

//Decrypt execute decryption operation in KMS providers.
func (s *KMSServer) Decrypt(ctx context.Context, request *k8spb.DecryptRequest) (*k8spb.DecryptResponse, error) {
	glog.V(4).Infoln("Processing DecryptRequest: ")

	if s.keyID == "" {
		glog.Errorf("Empty key found to decrypt...")
		return &k8spb.DecryptResponse{}, fmt.Errorf("empty key found to decrypt")
	}

	decReq := kms.CreateDecryptRequest()
	decReq.CiphertextBlob = string(request.Cipher)
	decReq.Domain = s.domain
	decReq.SetScheme(HTTPS)

	s.credLock.RLock()
	client := *s.client
	s.credLock.RUnlock()

	response, err := client.Decrypt(decReq)
	if err != nil {
		glog.Errorf("failed to decrypt, error: %v", err)
		return &k8spb.DecryptResponse{}, err
	}
	if !response.IsSuccess() || response.Plaintext == "" {
		glog.Errorf("failed to decrypt, unexpected response: %s", response.GetHttpContentString())
		return &k8spb.DecryptResponse{}, fmt.Errorf(
			"failed to decrypt, unexpected response: %s", response.GetHttpContentString())
	}

	plain, err := base64.StdEncoding.DecodeString(response.Plaintext)
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

func (s *KMSServer) checkCredentials(credProvider providers.Provider) error {
	glog.V(6).Infoln("checking for new credentials")
	currentCreds, err := credProvider.Retrieve()
	if err != nil {
		return err
	}
	// need DeepEqual for refresh lastCreds
	if reflect.DeepEqual(currentCreds, s.lastCreds) {
		return nil
	}
	glog.V(6).Infoln("credentials rotate")

	clientConfig := sdk.NewConfig()
	clientConfig.Scheme = "https"
	client, err := kms.NewClientWithOptions(s.region, clientConfig, currentCreds)
	if err != nil {
		return fmt.Errorf("failed to init kms client, err: %v", err)
	}

	s.credLock.Lock()
	defer s.credLock.Unlock()

	s.lastCreds = currentCreds
	s.client = client
	return nil
}
