package normalizer

import (
	"net/http"
	"testing"
)

func TestNormalizeValueDecodesCommonEncodings(t *testing.T) {
	cases := map[string]string{
		"%253Cscript%253Ealert(1)%253C%252Fscript%253E": "<script>alert(1)</script>",
		"&#x3c;script&#x3e;":                            "<script>",
		`\u003cscript\u003e`:                            "<script>",
		"union/**/select\nfrom users":                   "union select from users",
	}
	for input, want := range cases {
		if got := NormalizeValue(input); got != want {
			t.Fatalf("NormalizeValue(%q)=%q want %q", input, got, want)
		}
	}
}

func TestNormalizePathCleansAndDecodesQuery(t *testing.T) {
	got := NormalizePath("/a/%2e%2e/search?q=un/**/ion%20select")
	if got != "/search?q=union select" {
		t.Fatalf("path=%q", got)
	}
}

func TestRequestCopyNormalizesArgsHeadersBody(t *testing.T) {
	req := Request{Method: "get", URI: "/x", Headers: http.Header{"x-test": {"&#x3c;script&#x3e;"}}, Args: map[string][]string{"Q": {"union/**/select"}}, Body: `%5Cu003cscript%5Cu003e`}
	got := RequestCopy(req)
	if got.Method != http.MethodGet || got.Headers.Get("X-Test") != "<script>" || got.Args["q"][0] != "union select" || got.Body != "<script>" {
		t.Fatalf("normalized request=%#v", got)
	}
}
