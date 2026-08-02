package proxy

import (
	"io"
	"sync/atomic"
	"time"
)

// TrafficStats 是代理流量统计。
type TrafficStats struct {
	DownloadBytes int64   `json:"download_bytes"`
	UploadBytes   int64   `json:"upload_bytes"`
	DownloadBps   float64 `json:"download_bps"`
	UploadBps     float64 `json:"upload_bps"`
	UpdatedAt     int64   `json:"updated_at"`
}

type trafficCounter struct {
	downloadBytes atomic.Int64
	uploadBytes   atomic.Int64
	lastDownload  atomic.Int64
	lastUpload    atomic.Int64
	lastSample    atomic.Int64
	downloadBps   atomic.Uint64
	uploadBps     atomic.Uint64
}

func (counter *trafficCounter) addDownload(bytes int64) {
	counter.downloadBytes.Add(bytes)
	counter.refreshRate()
}

func (counter *trafficCounter) addUpload(bytes int64) {
	counter.uploadBytes.Add(bytes)
	counter.refreshRate()
}

func (counter *trafficCounter) refreshRate() {
	now := time.Now().UnixNano()
	last := counter.lastSample.Load()
	if last == 0 {
		counter.lastSample.Store(now)
		counter.lastDownload.Store(counter.downloadBytes.Load())
		counter.lastUpload.Store(counter.uploadBytes.Load())
		return
	}
	elapsed := time.Duration(now - last)
	if elapsed < 500*time.Millisecond {
		return
	}
	download := counter.downloadBytes.Load()
	upload := counter.uploadBytes.Load()
	counter.downloadBps.Store(uint64(float64(download-counter.lastDownload.Load()) / elapsed.Seconds()))
	counter.uploadBps.Store(uint64(float64(upload-counter.lastUpload.Load()) / elapsed.Seconds()))
	counter.lastSample.Store(now)
	counter.lastDownload.Store(download)
	counter.lastUpload.Store(upload)
}

func (counter *trafficCounter) snapshot() TrafficStats {
	counter.refreshRate()
	return TrafficStats{
		DownloadBytes: counter.downloadBytes.Load(),
		UploadBytes:   counter.uploadBytes.Load(),
		DownloadBps:   float64(counter.downloadBps.Load()),
		UploadBps:     float64(counter.uploadBps.Load()),
		UpdatedAt:     time.Now().Unix(),
	}
}

type countingReader struct {
	reader  io.Reader
	counter func(int64)
}

func (counting *countingReader) Read(buffer []byte) (int, error) {
	read, err := counting.reader.Read(buffer)
	if read > 0 {
		counting.counter(int64(read))
	}
	return read, err
}
