package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWrappersExposeTheUnderlyingWriterForFlushing(t *testing.T) {
	wrappers := map[string]func(http.ResponseWriter) http.ResponseWriter{
		"statusRecorder": func(w http.ResponseWriter) http.ResponseWriter {
			return &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		},
		"noStoreWriter": func(w http.ResponseWriter) http.ResponseWriter {
			return &noStoreWriter{ResponseWriter: w}
		},
	}
	for name, wrap := range wrappers {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			wrapped := wrap(recorder)

			if err := http.NewResponseController(wrapped).Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			if !recorder.Flushed {
				t.Fatal("the flush did not reach the underlying writer")
			}
			unwrapper, ok := wrapped.(interface{ Unwrap() http.ResponseWriter })
			if !ok || unwrapper.Unwrap() != http.ResponseWriter(recorder) {
				t.Fatal("Unwrap does not return the underlying writer")
			}
		})
	}
}
