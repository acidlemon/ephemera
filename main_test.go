package main

import "testing"

func TestIsExcludedPath(t *testing.T) {
	tests := []struct {
		name         string
		excludePaths []string
		path         string
		want         bool
	}{
		// exact match (no wildcard)
		{"exact root match", []string{"/"}, "/", true},
		{"exact root no match", []string{"/"}, "/foo", false},
		{"exact path match", []string{"/healthz"}, "/healthz", true},
		{"exact path no match prefix", []string{"/health"}, "/healthz", false},
		{"exact path no match suffix", []string{"/healthz"}, "/healthz/", false},

		// single-level "*" (does not cross "/")
		{"single wildcard match", []string{"/powawa/*/create"}, "/powawa/foo/create", true},
		{"single wildcard no cross slash", []string{"/powawa/*/create"}, "/powawa/a/b/create", false},
		{"single wildcard empty segment", []string{"/powawa/*/create"}, "/powawa//create", true},
		{"single wildcard suffix", []string{"/api/*"}, "/api/users", true},
		{"single wildcard suffix no cross", []string{"/api/*"}, "/api/users/1", false},
		{"single wildcard prefix", []string{"*.css"}, "style.css", true},
		{"single wildcard prefix no cross", []string{"*.css"}, "a/style.css", false},
		{"multiple single wildcards", []string{"/api/*/users/*"}, "/api/v1/users/42", true},
		{"multiple single wildcards no cross", []string{"/api/*/users/*"}, "/api/v1/users/42/edit", false},

		// multi-level "**" (crosses "/")
		{"double wildcard match single level", []string{"/powawa/**/create"}, "/powawa/foo/create", true},
		{"double wildcard match multi level", []string{"/powawa/**/create"}, "/powawa/a/b/create", true},
		{"double wildcard match everything", []string{"/**"}, "/foo/bar/baz", true},
		{"double wildcard root", []string{"/**"}, "/", true},
		{"double wildcard suffix", []string{"/static/**"}, "/static/js/app.js", true},
		{"double wildcard no match different prefix", []string{"/static/**"}, "/assets/app.js", false},

		// multiple patterns
		{"matches second pattern", []string{"/healthz", "/api/*"}, "/api/x", true},
		{"matches none", []string{"/healthz", "/api/*"}, "/web/x", false},

		// empty exclude list
		{"empty list", nil, "/anything", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsExcludedPath(tt.excludePaths, tt.path); got != tt.want {
				t.Errorf("IsExcludedPath(%v, %q) = %v, want %v", tt.excludePaths, tt.path, got, tt.want)
			}
		})
	}
}
