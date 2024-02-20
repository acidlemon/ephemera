package auth

import (
	"log"
	"net/http"
)

type DebugWriter struct {
	req    *http.Request
	writer http.ResponseWriter
}

func NewDebugWriter(w http.ResponseWriter, r *http.Request) *DebugWriter {
	return &DebugWriter{
		req:    r,
		writer: w,
	}
}

func (w *DebugWriter) Write(p []byte) (int, error) {
	return w.writer.Write(p)
}

func (w *DebugWriter) WriteHeader(statusCode int) {
	log.Println("[Debug] Request", w.req.URL.String())
	log.Println("[Debug] WriteHeader", statusCode)
	log.Println("[Debug] Header", w.writer.Header())
	w.writer.WriteHeader(statusCode)
}

func (w *DebugWriter) Header() http.Header {
	return w.writer.Header()
}
