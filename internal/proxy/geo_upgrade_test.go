package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadGeoFileSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(make([]byte, 2048))
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "geoip.dat")
	if err := downloadGeoFile(server.URL, path); err != nil {
		t.Fatalf("download should succeed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("output file missing: %v", err)
	}
	if info.Size() != 2048 {
		t.Fatalf("file size = %d, want 2048", info.Size())
	}
}

func TestDownloadGeoFileTooSmall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(make([]byte, 64))
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "geoip.dat")
	if err := downloadGeoFile(server.URL, path); err == nil {
		t.Fatal("too-small file should fail")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("partial file should be removed, got %v", err)
	}
}

func TestDownloadGeoFileHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "geoip.dat")
	if err := downloadGeoFile(server.URL, path); err == nil {
		t.Fatal("HTTP 404 should fail")
	}
}

func TestGeoFilePathUsesPersistentDataDirectory(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("VPNGATE_DATA_DIR", dataDir)
	if got := GeoFilePath("geoip"); got != filepath.Join(dataDir, "geoip.dat") {
		t.Fatalf("geoip path = %q", got)
	}
	if got := GeoFilePath("geosite"); got != filepath.Join(dataDir, "geosite.dat") {
		t.Fatalf("geosite path = %q", got)
	}
}
