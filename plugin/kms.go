package plugin

import (
	"encoding/base64"
	"fmt"
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
	"k8s.io/kms/pkg/service"
)

const (
	defaultKmsDomain            = "kms-vpc.%s.aliyuncs.com"
	envRegion                   = "ACK_KMS_REGION_ID"
	envKmsDomain                = "ACK_KMS_DOMAIN"
	defaultCredCheckFreqSeconds = 480

	requestIDAnnotationValue = "x-acs-request-id.ack.alibabacloud.com"
	kmsRegionAnnotationValue = "x-acs-kms-region-id.ack.alibabacloud.com"
	kmsKeyIdAnnotationValue  = "x-acs-kms-key-version-id.ack.alibabacloud.com"
)

// Client is the KMS cryptographic client used by v1 and v2 gRPC servers.
type Client interface {
	Encrypt(plain []byte) (*service.EncryptResponse, error)
	Decrypt(cipher []byte) ([]byte, error)
}

// KMSClient implements Client using Alibaba Cloud KMS SDK.
type KMSClient struct {
	client *kms.Client
	domain string
	region string
	keyID  string

	credLock  sync.RWMutex
	lastCreds aliCloudAuth.Credential
	stopCh    chan struct{}
}

// NewKMSClient creates a new KMSClient with auto credential refresh.
func NewKMSClient(keyID string) (Client, error) {
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

	credCheckFreqSec := defaultCredCheckFreqSeconds
	if raw := os.Getenv("CREDENTIAL_INTERVAL"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("could not convert 'CREDENTIAL_INTERVAL' value to int")
		}
		if v >= 1800 {
			return nil, fmt.Errorf("the value of 'CREDENTIAL_INTERVAL' should less than 1800")
		}
		credCheckFreqSec = v
	}

	credConfig := &providers.Configuration{}
	credConfig.AccessKeyID = os.Getenv("ACCESS_KEY_ID")
	credConfig.AccessKeySecret = os.Getenv("ACCESS_KEY_SECRET")
	credentialChain := []providers.Provider{
		providers.NewConfigurationCredentialProvider(credConfig),
		providers.NewInstanceMetadataProvider(),
	}
	credProvider := providers.NewChainProvider(credentialChain)

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

	kc := &KMSClient{
		client:    client,
		region:    region,
		domain:    domain,
		keyID:     keyID,
		lastCreds: lastCreds,
		stopCh:    make(chan struct{}),
	}

	if credConfig.AccessKeyID == "" || credConfig.AccessKeySecret == "" {
		go kc.pullForCreds(credProvider, credCheckFreqSec)
	}
	return kc, nil
}

func (kc *KMSClient) pullForCreds(credProvider providers.Provider, frequencySeconds int) {
	ticker := time.NewTicker(time.Duration(frequencySeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-kc.stopCh:
			glog.Warningf("stopping the pulling channel")
			return
		case <-ticker.C:
			if err := kc.checkCredentials(credProvider); err != nil {
				glog.Warningf("unable to retrieve current credentials, error: %v", err)
			}
		}
	}
}

func (kc *KMSClient) checkCredentials(credProvider providers.Provider) error {
	glog.V(6).Infoln("checking for new credentials")
	currentCreds, err := credProvider.Retrieve()
	if err != nil {
		return err
	}
	if reflect.DeepEqual(currentCreds, kc.lastCreds) {
		return nil
	}
	glog.V(6).Infoln("credentials rotate")

	clientConfig := sdk.NewConfig()
	clientConfig.Scheme = "https"
	client, err := kms.NewClientWithOptions(kc.region, clientConfig, currentCreds)
	if err != nil {
		return fmt.Errorf("failed to init kms client, err: %v", err)
	}

	kc.credLock.Lock()
	defer kc.credLock.Unlock()
	kc.lastCreds = currentCreds
	kc.client = client
	return nil
}

// Encrypt encrypts plain text with the configured KMS key.
func (kc *KMSClient) Encrypt(plain []byte) (*service.EncryptResponse, error) {
	if kc.keyID == "" {
		return nil, fmt.Errorf("empty key found to encrypt")
	}

	kc.credLock.RLock()
	client := *kc.client
	kc.credLock.RUnlock()

	encReq := kms.CreateEncryptRequest()
	encReq.KeyId = kc.keyID
	encReq.Plaintext = base64.StdEncoding.EncodeToString(plain)
	encReq.Domain = kc.domain
	encReq.SetScheme("https")

	response, err := client.Encrypt(encReq)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt, error: %v", err)
	}
	if !response.IsSuccess() || response.CiphertextBlob == "" {
		return nil, fmt.Errorf("failed to encrypt, unexpected response: %s", response.GetHttpContentString())
	}

	annotations := map[string][]byte{
		requestIDAnnotationValue: []byte(response.RequestId),
		kmsKeyIdAnnotationValue:  []byte(response.KeyVersionId),
		kmsRegionAnnotationValue: []byte(kc.region),
	}
	return &service.EncryptResponse{
		Ciphertext:  []byte(response.CiphertextBlob),
		KeyID:       kc.keyID,
		Annotations: annotations,
	}, nil
}

// Decrypt decrypts cipher text.
func (kc *KMSClient) Decrypt(cipher []byte) ([]byte, error) {
	if kc.keyID == "" {
		return nil, fmt.Errorf("empty key found to decrypt")
	}

	kc.credLock.RLock()
	client := *kc.client
	kc.credLock.RUnlock()

	decReq := kms.CreateDecryptRequest()
	decReq.CiphertextBlob = string(cipher)
	decReq.Domain = kc.domain
	decReq.SetScheme("https")

	response, err := client.Decrypt(decReq)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt, error: %v", err)
	}
	if !response.IsSuccess() || response.Plaintext == "" {
		return nil, fmt.Errorf("failed to decrypt, unexpected response: %s", response.GetHttpContentString())
	}

	plain, err := base64.StdEncoding.DecodeString(response.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode plain text, error: %v", err)
	}
	return plain, nil
}
