package plugin

import (
	"os"
	"strings"
	"testing"
)

func TestNew_CREDENTIAL_INTERVAL_invalid(t *testing.T) {
	type args struct {
		pathToUnixSocketFile string
		keyID                string
	}
	tests := []struct {
		name   string
		value  string
		errmsg string
	}{
		{
			name:   "invalide number",
			value:  "abc",
			errmsg: "could not convert 'CREDENTIAL_INTERVAL' value to int",
		},
		{
			name:   "greater than 1800",
			value:  "1801",
			errmsg: "the value of 'CREDENTIAL_INTERVAL' should less than 1800",
		},
		{
			name:   "equal than 1800",
			value:  "1800",
			errmsg: "the value of 'CREDENTIAL_INTERVAL' should less than 1800",
		},
	}
	os.Setenv("ACCESS_KEY_ID", "<access_key_id>")
	os.Setenv("ACCESS_KEY_SECRET", "<access_key_secret>")
	os.Setenv("ACK_KMS_REGION_ID", "cn-beijing")
	defer func() {
		os.Setenv("ACCESS_KEY_ID", "")
		os.Setenv("ACCESS_KEY_SECRET", "")
		os.Setenv("ACK_KMS_REGION_ID", "")
	}()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("CREDENTIAL_INTERVAL", tt.value)
			_, err := New("/tmp", "kms-id")
			os.Setenv("CREDENTIAL_INTERVAL", "")
			if err == nil {
				t.Errorf("err should not be nil")
			}
			if !strings.Contains(err.Error(), tt.errmsg) {
				t.Errorf("error message(%q) should include %q", err.Error(), tt.errmsg)
			}
		})
	}
}
