package plugin

import (
	"io"
	"net/http"
)

const (
	// MetadataURL is the ECS metadata server addr
	MetadataURL = "http://100.100.100.200/latest/meta-data/"
	// RegionID is the ECS metadata key for the region id
	RegionID = "region-id"
)

// GetMetaData return host regionid, zoneid
func GetMetaData(resource string) string {
	resp, err := http.Get(MetadataURL + resource)
	if err != nil {
		return ""
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}
