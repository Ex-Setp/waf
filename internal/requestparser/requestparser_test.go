package requestparser

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"testing"
)

func TestParseExplainsEncodedXSS(t *testing.T) {
	parsed := Parse("GET", "/search?q=%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E", nil, nil, Options{})
	field := findField(parsed.Fields, "query", "ARGS:q")
	if field == nil {
		t.Fatalf("missing query field ARGS:q: %#v", parsed.Fields)
	}
	if !strings.Contains(field.NormalizedValue, "<script>alert(1)</script>") {
		t.Fatalf("NormalizedValue = %q, want decoded script", field.NormalizedValue)
	}
	if len(field.DecodeSteps) == 0 {
		t.Fatalf("expected decode steps for encoded query")
	}
	if parsed.NormalizedPath != "/search" {
		t.Fatalf("NormalizedPath = %q, want /search", parsed.NormalizedPath)
	}
}

func TestParseJSONNestedField(t *testing.T) {
	body := []byte(`{"profile":{"bio":"%3Cscript%3Ealert(1)%3C/script%3E"}}`)
	headers := http.Header{"Content-Type": []string{"application/json"}}
	parsed := Parse("POST", "/users", headers, body, Options{})
	field := findField(parsed.Fields, "json", "JSON:profile.bio")
	if field == nil {
		t.Fatalf("missing JSON:profile.bio field: %#v", parsed.Fields)
	}
	if field.Name != "profile.bio" {
		t.Fatalf("Name = %q, want profile.bio", field.Name)
	}
	if !strings.Contains(field.NormalizedValue, "<script>") {
		t.Fatalf("NormalizedValue = %q, want decoded script", field.NormalizedValue)
	}
}

func TestParseFormAndMultipartFields(t *testing.T) {
	formHeaders := http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}}
	form := Parse("POST", "/submit", formHeaders, []byte("name=alice&bio=%253Csvg%253E"), Options{})
	if field := findField(form.Fields, "form", "ARGS:bio"); field == nil || field.NormalizedValue != "<svg>" {
		t.Fatalf("form bio field = %#v, want normalized <svg>", field)
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("title", "%3Cb%3Ehello%3C/b%3E")
	part, err := writer.CreateFormFile("avatar", "shell.php")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("file contents must not be exposed"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	mpHeaders := http.Header{"Content-Type": []string{writer.FormDataContentType()}}
	multipartParsed := Parse("POST", "/upload", mpHeaders, buf.Bytes(), Options{})
	if field := findField(multipartParsed.Fields, "multipart", "ARGS:title"); field == nil || field.NormalizedValue != "<b>hello</b>" {
		t.Fatalf("multipart title field = %#v, want normalized html", field)
	}
	fileField := findField(multipartParsed.Fields, "multipart", "FILES:avatar")
	if fileField == nil {
		t.Fatalf("missing multipart file field: %#v", multipartParsed.Fields)
	}
	if fileField.Filename != "shell.php" {
		t.Fatalf("Filename = %q, want shell.php", fileField.Filename)
	}
	if strings.Contains(fileField.RawValue, "file contents") || strings.Contains(fileField.NormalizedValue, "file contents") {
		t.Fatalf("file content leaked in file metadata field: %#v", fileField)
	}
	if field := findField(multipartParsed.Fields, "multipart", "FILES:avatar.extension"); field == nil || field.NormalizedValue != ".php" {
		t.Fatalf("file extension field = %#v, want .php", field)
	}
	if field := findField(multipartParsed.Fields, "multipart", "FILES:avatar.content_type"); field == nil || field.NormalizedValue != "application/octet-stream" {
		t.Fatalf("content type field = %#v", field)
	}
	if field := findField(multipartParsed.Fields, "multipart", "FILES:avatar.snippet"); field == nil || !strings.Contains(field.NormalizedValue, "file contents must not be expose") {
		t.Fatalf("snippet field = %#v", field)
	}
	if field := findField(multipartParsed.Fields, "multipart", "FILES:avatar.risk"); field == nil || field.NormalizedValue != "executable_extension" {
		t.Fatalf("risk field = %#v, want executable_extension", field)
	}
}

func TestParseMultipartFileMetadataSignals(t *testing.T) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("payload", `..\..\shell.jpg.php`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("<?php echo shell_exec($_GET['cmd']); ?>")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	parsed := Parse("POST", "/upload", http.Header{"Content-Type": []string{writer.FormDataContentType()}}, buf.Bytes(), Options{})
	if field := findField(parsed.Fields, "multipart", "FILES:payload"); field == nil || field.NormalizedValue != "shell.jpg.php" {
		t.Fatalf("safe file field = %#v, want shell.jpg.php", field)
	}
	if field := findField(parsed.Fields, "multipart", "FILES:payload.magic"); field == nil || field.NormalizedValue != "php" {
		t.Fatalf("magic field = %#v, want php", field)
	}
	if !hasFieldValue(parsed.Fields, "FILES:payload.risk", "path_traversal") {
		t.Fatalf("missing path traversal risk: %#v", parsed.Fields)
	}
	if !hasFieldValue(parsed.Fields, "FILES:payload.risk", "double_extension") {
		t.Fatalf("missing double extension risk: %#v", parsed.Fields)
	}
	if !hasFieldValue(parsed.Fields, "FILES:payload.risk", "webshell_code") {
		t.Fatalf("missing webshell code risk: %#v", parsed.Fields)
	}
}

func TestParseMultipartMagicMismatch(t *testing.T) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", `form-data; name="upload"; filename="avatar.png"`)
	header.Set("Content-Type", "image/png")
	part, err := writer.CreatePart(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("%PDF-1.5 benign report")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	parsed := Parse("POST", "/upload", http.Header{"Content-Type": []string{writer.FormDataContentType()}}, buf.Bytes(), Options{})
	if field := findField(parsed.Fields, "multipart", "FILES:upload.magic"); field == nil || field.NormalizedValue != "pdf" {
		t.Fatalf("magic field = %#v, want pdf", field)
	}
	if !hasFieldValue(parsed.Fields, "FILES:upload.risk", "content_type_mismatch") {
		t.Fatalf("missing mismatch risk: %#v", parsed.Fields)
	}
}

func TestParseBodyTooLargeModes(t *testing.T) {
	body := []byte("12345")
	for _, tc := range []struct {
		name              string
		failOpen          bool
		inspectionAllowed bool
	}{
		{name: "fail open", failOpen: true, inspectionAllowed: true},
		{name: "fail closed", failOpen: false, inspectionAllowed: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed := Parse("POST", "/submit", http.Header{"Content-Type": []string{"application/json"}}, body, Options{MaxBodySize: 4, FailOpen: tc.failOpen})
			if !parsed.BodyTooLarge {
				t.Fatalf("BodyTooLarge=false, want true")
			}
			if parsed.InspectionAllowed != tc.inspectionAllowed {
				t.Fatalf("InspectionAllowed = %v, want %v", parsed.InspectionAllowed, tc.inspectionAllowed)
			}
			if len(parsed.ParseErrors) != 1 || !parsed.ParseErrors[0].Fatal || parsed.ParseErrors[0].Source != "body" {
				t.Fatalf("ParseErrors = %#v, want one fatal body error", parsed.ParseErrors)
			}
		})
	}
}

func findField(fields []ParsedField, source, variable string) *ParsedField {
	for i := range fields {
		if fields[i].Source == source && fields[i].Variable == variable {
			return &fields[i]
		}
	}
	return nil
}

func hasFieldValue(fields []ParsedField, variable, want string) bool {
	for _, field := range fields {
		if field.Variable == variable && field.NormalizedValue == want {
			return true
		}
	}
	return false
}
