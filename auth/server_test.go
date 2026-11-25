package auth

import "testing"

func TestSanitizeReturnTo(t *testing.T) {
	cases := []struct {
		inSub, inPath     string
		wantSub, wantPath string
	}{
		{"app", "/foo/bar", "app", "/foo/bar"},
		{"my-app1", "/", "my-app1", "/"},
		{"", "", "", "/"},
		{"evil.com/", "/", "", "/"},
		{"evil.com?", "/", "", "/"},
		{"evil.com#", "/", "", "/"},
		{"a.b", "/", "", "/"},
		{"-app", "/", "", "/"},
		{"app", "@evil.com", "app", "/"},
		{"app", "evil.com", "app", "/"},
		{"app", "/\\evil.com", "app", "/"},
		{"app", "/foo\r\nSet-Cookie: x=y", "app", "/"},
		{"app", "//evil.com", "app", "//evil.com"}, // ホストの後ろに付くのでパス扱いで安全
	}
	for _, c := range cases {
		sub, path := sanitizeReturnTo(c.inSub, c.inPath)
		if sub != c.wantSub || path != c.wantPath {
			t.Errorf("sanitizeReturnTo(%q, %q) = (%q, %q), want (%q, %q)", c.inSub, c.inPath, sub, path, c.wantSub, c.wantPath)
		}
	}
}
