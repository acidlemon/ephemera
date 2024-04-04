package main

import (
	"io"
	"net/http"
)

type responseDumper struct {
	http.ResponseWriter
	writer io.Writer
}

func (r *responseDumper) Write(b []byte) (int, error) {
	return r.writer.Write(b)
}
