package mock

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	v1beta1 "github.com/AliyunContainerService/ack-kms-plugin/v1beta1"
	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
)

var (
	version = "v1beta1"
)

// func setup(t *testing.T) (*gomock.Controller, kmscmock.MockKeyManagementServiceClient) {
// 	ctrl := gomock.NewController(t)
// 	return nil, kmscmock.NewMockKeyManagementServiceClient(&ctrl)

// }

// rpcMsg implements the gomock.Matcher interface
type rpcMsg struct {
	msg proto.Message
}

func (r *rpcMsg) Matches(msg interface{}) bool {
	m, ok := msg.(proto.Message)
	if !ok {
		return false
	}
	return proto.Equal(m, r.msg)
}

func (r *rpcMsg) String() string {
	return fmt.Sprintf("is %s", r.msg)
}

//Version
func TestVersion(t *testing.T) {
	//ctrl, mockKeyManagementServiceClient := setup(t)
	ctrl := gomock.NewController(t)
	mockKeyManagementServiceClient := NewMockKeyManagementServiceClient(ctrl)
	defer ctrl.Finish()
	req := &v1beta1.VersionRequest{Version: version}
	mockKeyManagementServiceClient.EXPECT().Version(
		gomock.Any(),
		&rpcMsg{msg: req},
	).Return(&v1beta1.VersionResponse{Version: version}, nil)
	exp := "v1beta1"
	r, _ := mockKeyManagementServiceClient.Version(context.Background(), &v1beta1.VersionRequest{Version: exp})
	if r != nil {
		t.Logf("test passed, expect: %s  result: %s", version, exp)
	}
}

func TestBadVersion(t *testing.T) {
	//ctrl, mockKeyManagementServiceClient := setup(t)
	ctrl := gomock.NewController(t)
	mockKeyManagementServiceClient := NewMockKeyManagementServiceClient(ctrl)
	defer ctrl.Finish()
	mockKeyManagementServiceClient.EXPECT().Version(
		gomock.Any(),
		gomock.Any(),
	).Return(&v1beta1.VersionResponse{Version: version}, errors.New("invalid version"))
	exp := "v1beta2"
	_, err := mockKeyManagementServiceClient.Version(context.Background(), &v1beta1.VersionRequest{Version: exp})
	if err != nil {
		t.Logf(err.Error())
	}
}

//Encrypt
func TestEncrypt(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	genPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	genPublicKey := &genPrivateKey.PublicKey
	message := base64.RawURLEncoding.EncodeToString([]byte("my-data"))
	ciphertext, _ := rsa.EncryptPKCS1v15(rand.Reader, genPublicKey, []byte(message))

	mockKeyManagementServiceClient := NewMockKeyManagementServiceClient(ctrl)
	mockKeyManagementServiceClient.EXPECT().Encrypt(
		gomock.Any(),
		gomock.Any(),
	).Return(&v1beta1.EncryptResponse{Cipher: ciphertext}, nil)
	_, err := mockKeyManagementServiceClient.Encrypt(context.Background(), &v1beta1.EncryptRequest{Version: "v1beta1", Plain: []byte("my-data")})
	if err != nil {
		t.Errorf("test encrypt failed")
	}
	t.Logf("test passed")
}

// Decrypt
func TestDecrypt(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	plainText := []byte("my-data")
	mockKeyManagementServiceClient := NewMockKeyManagementServiceClient(ctrl)
	mockKeyManagementServiceClient.EXPECT().Decrypt(
		gomock.Any(),
		gomock.Any(),
	).Return(&v1beta1.DecryptResponse{Plain: plainText}, nil)

	genPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	genPublicKey := &genPrivateKey.PublicKey
	message := base64.RawURLEncoding.EncodeToString([]byte("my-data"))
	ciphertext, _ := rsa.EncryptPKCS1v15(rand.Reader, genPublicKey, []byte(message))

	_, err := mockKeyManagementServiceClient.Decrypt(context.Background(), &v1beta1.DecryptRequest{Version: "v1beta1", Cipher: ciphertext})
	if err != nil {
		t.Errorf("test decrypt failed")
	}
	t.Logf("test passed")
}
