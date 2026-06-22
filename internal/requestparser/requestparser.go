package requestparser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

const defaultMaxDecodePasses = 3

// Options controls request parsing and normalization behavior.
type Options struct {
	MaxBodySize     int64 `json:"maxBodySize"`
	MaxDecodePasses int   `json:"maxDecodePasses"`
	FailOpen        bool  `json:"failOpen"`
}

// ParsedRequest captures raw and normalized request data for WAF inspection and UI explanation.
type ParsedRequest struct {
	Method            string        `json:"method"`
	RawURI            string        `json:"rawUri"`
	NormalizedURI     string        `json:"normalizedUri"`
	Path              string        `json:"path"`
	NormalizedPath    string        `json:"normalizedPath"`
	ContentType       string        `json:"contentType,omitempty"`
	Fields            []ParsedField `json:"fields"`
	DecodeSteps       []DecodeStep  `json:"decodeSteps,omitempty"`
	ParseErrors       []ParseError  `json:"parseErrors,omitempty"`
	BodyTooLarge      bool          `json:"bodyTooLarge"`
	FailOpen          bool          `json:"failOpen"`
	InspectionAllowed bool          `json:"inspectionAllowed"`
}

// ParsedField describes one extracted request variable and how it was normalized.
type ParsedField struct {
	Name            string       `json:"name"`
	Source          string       `json:"source"`
	Variable        string       `json:"variable"`
	RawValue        string       `json:"rawValue"`
	NormalizedValue string       `json:"normalizedValue"`
	ContentType     string       `json:"contentType,omitempty"`
	Filename        string       `json:"filename,omitempty"`
	DecodeSteps     []DecodeStep `json:"decodeSteps,omitempty"`
	ParseErrors     []ParseError `json:"parseErrors,omitempty"`
}

// DecodeStep records one normalization step.
type DecodeStep struct {
	Stage  string `json:"stage"`
	Before string `json:"before"`
	After  string `json:"after"`
	Pass   int    `json:"pass"`
}

// ParseError records a recoverable or fatal parse error.
type ParseError struct {
	Source  string `json:"source"`
	Message string `json:"message"`
	Fatal   bool   `json:"fatal"`
}

// Parse extracts and normalizes request variables for detection and operator explanation.
func Parse(method, requestURI string, headers http.Header, body []byte, opts Options) ParsedRequest {
	passes := opts.MaxDecodePasses
	if passes <= 0 {
		passes = defaultMaxDecodePasses
	}
	mediaType, params := parseContentType(headers.Get("Content-Type"))
	normalizedURI, uriSteps := normalizeValue(requestURI, passes)
	pathPart := requestURI
	if u, err := url.ParseRequestURI(requestURI); err == nil {
		pathPart = u.Path
	} else if before, _, ok := strings.Cut(requestURI, "?"); ok {
		pathPart = before
	}
	normalizedPathRaw, pathSteps := normalizeValue(pathPart, passes)
	normalizedPath := cleanPath(normalizedPathRaw)
	if normalizedPath != normalizedPathRaw {
		pathSteps = append(pathSteps, DecodeStep{Stage: "path-clean", Before: normalizedPathRaw, After: normalizedPath, Pass: len(pathSteps) + 1})
	}
	parsed := ParsedRequest{
		Method:            strings.ToUpper(strings.TrimSpace(method)),
		RawURI:            requestURI,
		NormalizedURI:     normalizedURI,
		Path:              pathPart,
		NormalizedPath:    normalizedPath,
		ContentType:       mediaType,
		Fields:            []ParsedField{},
		DecodeSteps:       append(uriSteps, pathSteps...),
		ParseErrors:       []ParseError{},
		FailOpen:          opts.FailOpen,
		InspectionAllowed: true,
	}

	parseQuery(&parsed, requestURI, passes)
	parseHeaders(&parsed, headers, passes)
	parseCookies(&parsed, headers, passes)

	if opts.MaxBodySize > 0 && int64(len(body)) > opts.MaxBodySize {
		parsed.BodyTooLarge = true
		parsed.InspectionAllowed = opts.FailOpen
		parsed.ParseErrors = append(parsed.ParseErrors, ParseError{Source: "body", Message: "request body exceeds max body size", Fatal: true})
		return parsed
	}
	parseBody(&parsed, mediaType, params, body, passes)
	return parsed
}

func parseQuery(parsed *ParsedRequest, requestURI string, passes int) {
	u, err := url.ParseRequestURI(requestURI)
	if err != nil {
		if idx := strings.Index(requestURI, "?"); idx >= 0 && idx+1 < len(requestURI) {
			parseRawQuery(parsed, requestURI[idx+1:], passes)
		}
		return
	}
	parseRawQuery(parsed, u.RawQuery, passes)
}

func parseRawQuery(parsed *ParsedRequest, rawQuery string, passes int) {
	if rawQuery == "" {
		return
	}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		key, val, _ := strings.Cut(pair, "=")
		name, _ := normalizeName(key, passes)
		addField(parsed, "query", name, "ARGS:"+name, val, "", "", passes)
	}
}

func parseHeaders(parsed *ParsedRequest, headers http.Header, passes int) {
	for key, values := range headers {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(key))
		for _, value := range values {
			addField(parsed, "header", canonical, "REQUEST_HEADERS:"+canonical, value, "", "", passes)
		}
	}
}

func parseCookies(parsed *ParsedRequest, headers http.Header, passes int) {
	for _, raw := range headers.Values("Cookie") {
		for _, part := range strings.Split(raw, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			key, value, _ := strings.Cut(part, "=")
			name, _ := normalizeName(key, passes)
			addField(parsed, "cookie", name, "REQUEST_COOKIES:"+name, value, "", "", passes)
		}
	}
}

func parseBody(parsed *ParsedRequest, mediaType string, params map[string]string, body []byte, passes int) {
	if len(body) == 0 {
		return
	}
	switch mediaType {
	case "application/json":
		parseJSONBody(parsed, body, passes)
	case "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err != nil {
			parsed.ParseErrors = append(parsed.ParseErrors, ParseError{Source: "form", Message: err.Error()})
			return
		}
		for key, items := range values {
			name, _ := normalizeName(key, passes)
			for _, item := range items {
				addField(parsed, "form", name, "ARGS:"+name, item, "", "", passes)
			}
		}
	case "multipart/form-data":
		parseMultipartBody(parsed, params["boundary"], body, passes)
	case "text/plain", "application/octet-stream", "":
		addField(parsed, "body", "body", "REQUEST_BODY", string(body), mediaType, "", passes)
	default:
		addField(parsed, "body", "body", "REQUEST_BODY", string(body), mediaType, "", passes)
	}
}

func parseJSONBody(parsed *ParsedRequest, body []byte, passes int) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		parsed.ParseErrors = append(parsed.ParseErrors, ParseError{Source: "json", Message: err.Error()})
		return
	}
	flattenJSON(parsed, "", value, passes)
}

func flattenJSON(parsed *ParsedRequest, prefix string, value any, passes int) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			name := key
			if prefix != "" {
				name = prefix + "." + key
			}
			flattenJSON(parsed, name, child, passes)
		}
	case []any:
		for i, child := range typed {
			name := fmt.Sprintf("%s[%d]", prefix, i)
			flattenJSON(parsed, name, child, passes)
		}
	case string:
		addField(parsed, "json", prefix, "JSON:"+prefix, typed, "", "", passes)
	case json.Number:
		addField(parsed, "json", prefix, "JSON:"+prefix, typed.String(), "", "", passes)
	case bool:
		addField(parsed, "json", prefix, "JSON:"+prefix, strconv.FormatBool(typed), "", "", passes)
	case nil:
		return
	default:
		addField(parsed, "json", prefix, "JSON:"+prefix, fmt.Sprint(typed), "", "", passes)
	}
}

func parseMultipartBody(parsed *ParsedRequest, boundary string, body []byte, passes int) {
	if strings.TrimSpace(boundary) == "" {
		parsed.ParseErrors = append(parsed.ParseErrors, ParseError{Source: "multipart", Message: "missing boundary"})
		return
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	form, err := reader.ReadForm(1 << 20)
	if err != nil {
		parsed.ParseErrors = append(parsed.ParseErrors, ParseError{Source: "multipart", Message: err.Error()})
		return
	}
	defer form.RemoveAll()
	for key, values := range form.Value {
		name, _ := normalizeName(key, passes)
		for _, value := range values {
			addField(parsed, "multipart", name, "ARGS:"+name, value, "", "", passes)
		}
	}
	for key, files := range form.File {
		name, _ := normalizeName(key, passes)
		for _, file := range files {
			contentType := file.Header.Get("Content-Type")
			field := buildField("multipart", name, "FILES:"+name, file.Filename, contentType, file.Filename, passes)
			parsed.Fields = append(parsed.Fields, field)
		}
	}
}

func addField(parsed *ParsedRequest, source, name, variable, raw, contentType, filename string, passes int) {
	parsed.Fields = append(parsed.Fields, buildField(source, name, variable, raw, contentType, filename, passes))
}

func buildField(source, name, variable, raw, contentType, filename string, passes int) ParsedField {
	normalized, steps := normalizeValue(raw, passes)
	return ParsedField{Name: name, Source: source, Variable: variable, RawValue: raw, NormalizedValue: normalized, ContentType: contentType, Filename: filename, DecodeSteps: steps}
}

func normalizeName(name string, passes int) (string, []DecodeStep) {
	normalized, steps := normalizeValue(name, passes)
	lower := strings.ToLower(strings.TrimSpace(normalized))
	if lower != normalized {
		steps = append(steps, DecodeStep{Stage: "lowercase-name", Before: normalized, After: lower, Pass: len(steps) + 1})
	}
	return lower, steps
}

func normalizeValue(value string, passes int) (string, []DecodeStep) {
	if passes <= 0 {
		passes = defaultMaxDecodePasses
	}
	current := value
	steps := []DecodeStep{}
	for pass := 1; pass <= passes; pass++ {
		changed := false
		if next := html.UnescapeString(current); next != current {
			steps = append(steps, DecodeStep{Stage: "html-entity-decode", Before: current, After: next, Pass: pass})
			current = next
			changed = true
		}
		if next := decodeUnicodeEscapes(current); next != current {
			steps = append(steps, DecodeStep{Stage: "unicode-decode", Before: current, After: next, Pass: pass})
			current = next
			changed = true
		}
		if next, err := url.QueryUnescape(current); err == nil && next != current {
			steps = append(steps, DecodeStep{Stage: "url-decode", Before: current, After: next, Pass: pass})
			current = next
			changed = true
		}
		valid := strings.ToValidUTF8(current, "")
		if valid != current {
			steps = append(steps, DecodeStep{Stage: "utf8-clean", Before: current, After: valid, Pass: pass})
			current = valid
			changed = true
		}
		if !changed {
			break
		}
	}
	trimmed := strings.TrimSpace(current)
	if trimmed != current {
		steps = append(steps, DecodeStep{Stage: "trim", Before: current, After: trimmed, Pass: len(steps) + 1})
		current = trimmed
	}
	return current, steps
}

func decodeUnicodeEscapes(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for i := 0; i < len(value); {
		if i+6 <= len(value) && value[i] == '\\' && value[i+1] == 'u' {
			if r, ok := parseHexRune(value[i+2 : i+6]); ok {
				builder.WriteRune(r)
				i += 6
				continue
			}
		}
		if i+6 <= len(value) && value[i] == '%' && (value[i+1] == 'u' || value[i+1] == 'U') {
			if r, ok := parseHexRune(value[i+2 : i+6]); ok {
				builder.WriteRune(r)
				i += 6
				continue
			}
		}
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			i++
			continue
		}
		builder.WriteRune(r)
		i += size
	}
	return builder.String()
}

func parseHexRune(value string) (rune, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var out rune
	for _, ch := range value {
		out <<= 4
		switch {
		case ch >= '0' && ch <= '9':
			out += ch - '0'
		case ch >= 'a' && ch <= 'f':
			out += ch - 'a' + 10
		case ch >= 'A' && ch <= 'F':
			out += ch - 'A' + 10
		default:
			return 0, false
		}
	}
	return out, true
}

func cleanPath(value string) string {
	if strings.TrimSpace(value) == "" {
		return "/"
	}
	prefix := ""
	if !strings.HasPrefix(value, "/") {
		prefix = "/"
	}
	cleaned := path.Clean(prefix + value)
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

func parseContentType(value string) (string, map[string]string) {
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0])), map[string]string{}
	}
	return strings.ToLower(mediaType), params
}
