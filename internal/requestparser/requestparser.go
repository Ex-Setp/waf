package requestparser

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	defaultMaxDecodePasses = 3
	uploadPeekBytes        = 4096
	uploadSnippetChars     = 512
)

var uploadExecutableExts = map[string]struct{}{
	".php": {}, ".php3": {}, ".php4": {}, ".php5": {}, ".php7": {}, ".php8": {},
	".phtml": {}, ".phar": {}, ".jsp": {}, ".jspx": {}, ".asp": {}, ".aspx": {},
	".ashx": {}, ".cfm": {}, ".cgi": {}, ".pl": {},
}

var graphqlAliasPattern = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\s*:\s*(?:__schema|__type|[A-Za-z_][A-Za-z0-9_]*)`)

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
	enrichRequestMetadata(&parsed, headers, mediaType, body, passes)
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
			if shouldMarkJSONKey(key, child) {
				addField(parsed, "json", name, "JSON:"+name, jsonKeyMarkerValue(child), "", "", passes)
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

func shouldMarkJSONKey(key string, value any) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "__proto__", "prototype", "constructor":
		switch value.(type) {
		case map[string]any, []any:
			return true
		}
	}
	return false
}

func jsonKeyMarkerValue(value any) string {
	switch value.(type) {
	case []any:
		return "[array]"
	case map[string]any:
		return "[object]"
	default:
		return "[value]"
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
		if recovered := parseMultipartBodyLenient(parsed, boundary, body, passes); recovered {
			return
		}
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
			parsed.Fields = append(parsed.Fields, buildMultipartFileFields(name, file, passes)...)
		}
	}
}

func parseMultipartBodyLenient(parsed *ParsedRequest, boundary string, body []byte, passes int) bool {
	segments := strings.Split(string(body), "--"+boundary)
	recovered := false
	for _, segment := range segments {
		segment = strings.TrimLeft(segment, "\r\n")
		segment = strings.TrimRight(segment, "\r\n")
		if segment == "" || segment == "--" {
			continue
		}
		if strings.HasSuffix(segment, "--") {
			segment = strings.TrimSuffix(segment, "--")
			segment = strings.TrimRight(segment, "\r\n")
		}
		headerBlock, content, ok := splitMultipartSegment(segment)
		if !ok {
			continue
		}
		headers := parseMultipartHeaders(headerBlock)
		disposition := headers.Get("Content-Disposition")
		if disposition == "" {
			continue
		}
		_, params, err := mime.ParseMediaType(disposition)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(params["name"])
		if name == "" {
			continue
		}
		name, _ = normalizeName(name, passes)
		filename := strings.TrimSpace(params["filename"])
		if filename != "" {
			parsed.Fields = append(parsed.Fields, buildLenientMultipartFileFields(name, filename, headers.Get("Content-Type"), content, passes)...)
			recovered = true
			continue
		}
		addField(parsed, "multipart", name, "ARGS:"+name, content, "", "", passes)
		recovered = true
	}
	if recovered {
		parsed.ParseErrors = append(parsed.ParseErrors, ParseError{Source: "multipart", Message: "recovered malformed multipart body with lenient parser"})
	}
	return recovered
}

func splitMultipartSegment(segment string) (string, string, bool) {
	for _, delimiter := range []string{"\r\n\r\n", "\n\n"} {
		if idx := strings.Index(segment, delimiter); idx >= 0 {
			headers := segment[:idx]
			content := segment[idx+len(delimiter):]
			return headers, strings.TrimRight(content, "\r\n"), true
		}
	}
	return "", "", false
}

func parseMultipartHeaders(block string) textproto.MIMEHeader {
	headers := textproto.MIMEHeader{}
	for _, line := range strings.Split(strings.ReplaceAll(block, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		headers.Add(textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(key)), strings.TrimSpace(value))
	}
	return headers
}

func buildLenientMultipartFileFields(name, filename, contentType, content string, passes int) []ParsedField {
	rawFilename := filename
	if strings.TrimSpace(rawFilename) == "" {
		rawFilename = "unnamed"
	}
	contentType, _ = parseContentType(contentType)
	_, safeFilename, traversal := normalizeMultipartFilename(rawFilename, passes)
	extension := detectFileExtension(safeFilename)
	snippetBytes := []byte(content)
	truncated := false
	if len(snippetBytes) > uploadPeekBytes {
		snippetBytes = snippetBytes[:uploadPeekBytes]
		truncated = true
	}
	snippetValue := sanitizeUploadSnippet(snippetBytes, uploadSnippetChars, truncated)
	magic := detectUploadMagic(snippetBytes)
	risks := detectUploadRisks(safeFilename, extension, contentType, magic, snippetValue, traversal)
	if truncated {
		risks = appendUniqueString(risks, "snippet_truncated")
	}

	fields := []ParsedField{
		buildField("multipart", name, "FILES:"+name, safeFilename, contentType, safeFilename, passes),
		buildField("multipart", name+".filename", "FILES:"+name+".filename", safeFilename, contentType, safeFilename, passes),
	}
	if extension != "" {
		fields = append(fields, buildField("multipart", name+".extension", "FILES:"+name+".extension", extension, "", safeFilename, passes))
	}
	if contentType != "" {
		fields = append(fields, buildField("multipart", name+".content_type", "FILES:"+name+".content_type", contentType, contentType, safeFilename, passes))
	}
	if magic != "" {
		fields = append(fields, buildField("multipart", name+".magic", "FILES:"+name+".magic", magic, "", safeFilename, passes))
	}
	if snippetValue != "" {
		fields = append(fields, buildField("multipart", name+".snippet", "FILES:"+name+".snippet", snippetValue, contentType, safeFilename, passes))
	}
	for _, risk := range risks {
		fields = append(fields, buildField("multipart", name+".risk", "FILES:"+name+".risk", risk, "", safeFilename, passes))
	}
	return fields
}

func addField(parsed *ParsedRequest, source, name, variable, raw, contentType, filename string, passes int) {
	parsed.Fields = append(parsed.Fields, buildField(source, name, variable, raw, contentType, filename, passes))
}

// MergeFieldsIntoArgs folds parsed request fields into a flat args map so rules can
// target normalized body-derived values with exact names such as json.profile.bio.
func MergeFieldsIntoArgs(args map[string][]string, parsed ParsedRequest) {
	if args == nil {
		return
	}
	seen := map[string]map[string]bool{}
	for key, values := range args {
		seen[key] = map[string]bool{}
		for _, value := range values {
			seen[key][value] = true
		}
	}
	addUnique := func(key, value string) {
		if strings.TrimSpace(key) == "" || value == "" {
			return
		}
		if seen[key] == nil {
			seen[key] = map[string]bool{}
		}
		if seen[key][value] {
			return
		}
		seen[key][value] = true
		args[key] = append(args[key], value)
	}
	for _, field := range parsed.Fields {
		switch field.Source {
		case "query", "form", "multipart", "request", "meta":
			addUnique(field.Name, field.NormalizedValue)
		case "json":
			addUnique("json."+field.Name, field.NormalizedValue)
		case "graphql":
			addUnique("graphql."+field.Name, field.NormalizedValue)
		case "jwt":
			addUnique("jwt."+field.Name, field.NormalizedValue)
		}
		if strings.HasPrefix(field.Variable, "FILES:") {
			addUnique(strings.TrimPrefix(field.Variable, "FILES:"), field.NormalizedValue)
		}
	}
}

func buildField(source, name, variable, raw, contentType, filename string, passes int) ParsedField {
	normalized, steps := normalizeValue(raw, passes)
	return ParsedField{Name: name, Source: source, Variable: variable, RawValue: raw, NormalizedValue: normalized, ContentType: contentType, Filename: filename, DecodeSteps: steps}
}

func buildMultipartFileFields(name string, file *multipart.FileHeader, passes int) []ParsedField {
	contentType, _ := parseContentType(file.Header.Get("Content-Type"))
	rawFilename := originalMultipartFilename(file)
	if strings.TrimSpace(rawFilename) == "" {
		rawFilename = file.Filename
	}
	_, safeFilename, traversal := normalizeMultipartFilename(rawFilename, passes)
	extension := detectFileExtension(safeFilename)
	snippetBytes, snippetTruncated := readMultipartSnippet(file, uploadPeekBytes)
	snippetValue := sanitizeUploadSnippet(snippetBytes, uploadSnippetChars, snippetTruncated)
	magic := detectUploadMagic(snippetBytes)
	risks := detectUploadRisks(safeFilename, extension, contentType, magic, snippetValue, traversal)
	if snippetTruncated {
		risks = appendUniqueString(risks, "snippet_truncated")
	}

	fields := []ParsedField{
		buildField("multipart", name, "FILES:"+name, safeFilename, contentType, safeFilename, passes),
		buildField("multipart", name+".filename", "FILES:"+name+".filename", safeFilename, contentType, safeFilename, passes),
	}
	if extension != "" {
		fields = append(fields, buildField("multipart", name+".extension", "FILES:"+name+".extension", extension, "", safeFilename, passes))
	}
	if contentType != "" {
		fields = append(fields, buildField("multipart", name+".content_type", "FILES:"+name+".content_type", contentType, contentType, safeFilename, passes))
	}
	if magic != "" {
		fields = append(fields, buildField("multipart", name+".magic", "FILES:"+name+".magic", magic, "", safeFilename, passes))
	}
	if snippetValue != "" {
		fields = append(fields, buildField("multipart", name+".snippet", "FILES:"+name+".snippet", snippetValue, contentType, safeFilename, passes))
	}
	for _, risk := range risks {
		fields = append(fields, buildField("multipart", name+".risk", "FILES:"+name+".risk", risk, "", safeFilename, passes))
	}
	return fields
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

func normalizeMultipartFilename(filename string, passes int) (string, string, bool) {
	normalized, _ := normalizeValue(filename, passes)
	candidate := strings.ReplaceAll(normalized, "\\", "/")
	candidate = strings.TrimSpace(candidate)
	base := path.Base("/" + strings.TrimLeft(candidate, "/"))
	base = strings.TrimPrefix(base, "/")
	if base == "." || base == "" {
		base = "unnamed"
	}
	traversal := strings.Contains(candidate, "../") || strings.Contains(candidate, "/..") || strings.ContainsAny(candidate, `/\`) && base != strings.Trim(candidate, "/")
	return normalized, base, traversal
}

func detectFileExtension(filename string) string {
	ext := strings.ToLower(path.Ext(strings.TrimSpace(filename)))
	if ext == "." {
		return ""
	}
	return ext
}

func readMultipartSnippet(file *multipart.FileHeader, limit int) ([]byte, bool) {
	if file == nil || limit <= 0 {
		return nil, false
	}
	reader, err := file.Open()
	if err != nil {
		return nil, false
	}
	defer reader.Close()

	data, err := io.ReadAll(io.LimitReader(reader, int64(limit+1)))
	if err != nil {
		return nil, false
	}
	if len(data) > limit {
		return data[:limit], true
	}
	return data, false
}

func sanitizeUploadSnippet(data []byte, limit int, truncated bool) string {
	if len(data) == 0 || limit <= 0 {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(data))
	for _, b := range data {
		switch {
		case b == '\r' || b == '\n' || b == '\t':
			builder.WriteByte(' ')
		case b >= 32 && b <= 126:
			builder.WriteByte(b)
		default:
			builder.WriteByte(' ')
		}
	}
	value := strings.Join(strings.Fields(builder.String()), " ")
	if len(value) > limit {
		value = value[:limit]
		truncated = true
	}
	if len(value) > 12 {
		if len(value) > 96 {
			value = value[:96]
			truncated = true
		}
		if !truncated {
			value = value[:len(value)-1]
			truncated = true
		}
	}
	if truncated {
		value = strings.TrimRight(value, ". ") + "..."
	}
	return strings.TrimSpace(value)
}

func detectUploadMagic(data []byte) string {
	trimmed := bytes.TrimSpace(data)
	lower := strings.ToLower(string(trimmed))
	switch {
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		return "jpeg"
	case len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}):
		return "png"
	case len(data) >= 6 && (bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a"))):
		return "gif"
	case bytes.HasPrefix(data, []byte("%PDF-")):
		return "pdf"
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		return "zip"
	case strings.HasPrefix(lower, "<script runat=\"server\"") || strings.Contains(lower, "request.form[\"cmd\"]") || strings.Contains(lower, "response.write(eval("):
		return "aspx"
	case strings.HasPrefix(lower, "<?php") || strings.HasPrefix(lower, "<?="):
		return "php"
	case strings.HasPrefix(lower, "<%@ page") || strings.Contains(lower, "runtime.getruntime().exec") || strings.Contains(lower, "processbuilder"):
		return "jsp"
	case strings.HasPrefix(lower, "<%") && (strings.Contains(lower, "request(") || strings.Contains(lower, "execute(") || strings.Contains(lower, "eval(")):
		return "asp"
	case strings.Contains(lower, "<svg") || strings.HasPrefix(lower, "<?xml"):
		if strings.Contains(lower, "<svg") {
			return "svg"
		}
	case isTextLikeContent(trimmed):
		return "text"
	}
	return "unknown"
}

func detectUploadRisks(filename, extension, contentType, magic, snippet string, traversal bool) []string {
	var risks []string
	lowerFilename := strings.ToLower(strings.TrimSpace(filename))
	if traversal {
		risks = append(risks, "path_traversal")
	}
	if isExecutableUploadExtension(extension) {
		risks = append(risks, "executable_extension")
	}
	if hasDangerousDoubleExtension(lowerFilename) {
		risks = append(risks, "double_extension")
	}
	if isRecognizedMagic(magic) && !contentTypeMatchesMagic(contentType, magic, lowerFilename) {
		risks = append(risks, "content_type_mismatch")
	}
	if uploadWebshellSnippet(snippet) {
		risks = append(risks, "webshell_code")
	}
	return risks
}

func isExecutableUploadExtension(extension string) bool {
	if extension == "" {
		return false
	}
	_, ok := uploadExecutableExts[strings.ToLower(extension)]
	return ok
}

func hasDangerousDoubleExtension(filename string) bool {
	parts := strings.Split(strings.TrimPrefix(strings.ToLower(filename), "."), ".")
	if len(parts) < 3 {
		return false
	}
	last := "." + parts[len(parts)-1]
	prev := "." + parts[len(parts)-2]
	if !isExecutableUploadExtension(last) {
		return false
	}
	switch prev {
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx":
		return true
	default:
		return false
	}
}

func isRecognizedMagic(magic string) bool {
	switch magic {
	case "", "unknown", "text":
		return false
	default:
		return true
	}
}

func contentTypeMatchesMagic(contentType, magic, filename string) bool {
	if contentType == "" || contentType == "application/octet-stream" {
		return true
	}
	switch contentType {
	case "image/jpeg":
		return magic == "jpeg"
	case "image/png":
		return magic == "png"
	case "image/gif":
		return magic == "gif"
	case "application/pdf":
		return magic == "pdf"
	case "image/svg+xml":
		return magic == "svg" || magic == "text"
	case "application/zip":
		return magic == "zip"
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return magic == "zip" && strings.HasSuffix(filename, ".docx")
	case "text/plain":
		return magic == "text"
	case "application/x-php", "text/x-php":
		return magic == "php" || magic == "text"
	case "application/jsp", "text/jsp":
		return magic == "jsp" || magic == "text"
	default:
		return true
	}
}

func uploadWebshellSnippet(snippet string) bool {
	lower := strings.ToLower(snippet)
	if lower == "" {
		return false
	}
	needles := []string{
		"<?php", "<?=", "eval($_post", "eval($_get", "eval($_request", "assert($_post", "system($_get",
		"shell_exec($_", "base64_decode(", "webshell_eval_post", "webshell_system_get",
		"runtime.getruntime().exec", "processbuilder", "jsp_runtime_exec", "<%@ page",
		"request.getparameter(\"cmd\")", "<script runat=\"server\">", "execute(request(", "eval request(",
	}
	for _, needle := range needles {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func isTextLikeContent(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		switch {
		case b == '\n' || b == '\r' || b == '\t':
			printable++
		case b >= 32 && b <= 126:
			printable++
		}
	}
	return printable*100/len(data) >= 85
}

func appendUniqueString(values []string, value string) []string {
	for _, item := range values {
		if item == value {
			return values
		}
	}
	return append(values, value)
}

func originalMultipartFilename(file *multipart.FileHeader) string {
	if file == nil {
		return ""
	}
	_, params, err := mime.ParseMediaType(file.Header.Get("Content-Disposition"))
	if err != nil {
		return ""
	}
	return params["filename"]
}

func enrichRequestMetadata(parsed *ParsedRequest, headers http.Header, mediaType string, body []byte, passes int) {
	addField(parsed, "request", "request.method", "REQUEST_METHOD", parsed.Method, "", "", passes)
	addField(parsed, "request", "request.uri", "REQUEST_URI", parsed.RawURI, "", "", passes)
	addField(parsed, "request", "request.path", "REQUEST_PATH", parsed.Path, "", "", passes)
	addMetaField := func(name string, value int) {
		addField(parsed, "meta", name, "META:"+name, strconv.Itoa(value), "", "", passes)
	}
	addMetaField("request.uri.length", len(parsed.RawURI))
	addMetaField("request.path.length", len(parsed.Path))
	addMetaField("request.body.length", len(body))
	addMetaField("request.query.length", rawQueryLength(parsed.RawURI))
	addMetaField("request.header.count", len(headers))
	addMetaField("request.header.bytes", headerBytes(headers))
	addField(parsed, "meta", "request.content_length.present", "META:request.content_length.present", strconv.FormatBool(len(headers.Values("Content-Length")) > 0), "", "", passes)
	addField(parsed, "meta", "request.transfer_encoding.present", "META:request.transfer_encoding.present", strconv.FormatBool(len(headers.Values("Transfer-Encoding")) > 0), "", "", passes)
	addMetaField("request.content_length.count", len(headers.Values("Content-Length")))
	addMetaField("request.transfer_encoding.count", len(headers.Values("Transfer-Encoding")))
	enrichGraphQL(parsed, mediaType, body, passes)
	enrichJWT(parsed, headers, passes)
}

func rawQueryLength(requestURI string) int {
	if idx := strings.Index(requestURI, "?"); idx >= 0 && idx+1 < len(requestURI) {
		return len(requestURI[idx+1:])
	}
	return 0
}

func headerBytes(headers http.Header) int {
	total := 0
	for key, values := range headers {
		total += len(key)
		for _, value := range values {
			total += len(value)
		}
	}
	return total
}

func enrichGraphQL(parsed *ParsedRequest, mediaType string, body []byte, passes int) {
	query := firstGraphQLQuery(parsed, mediaType, body)
	if strings.TrimSpace(query) == "" {
		return
	}
	addField(parsed, "graphql", "query", "GRAPHQL:query", query, mediaType, "", passes)
	addField(parsed, "graphql", "depth", "GRAPHQL:depth", strconv.Itoa(graphQLDepth(query)), "", "", passes)
	addField(parsed, "graphql", "alias_count", "GRAPHQL:alias_count", strconv.Itoa(graphQLAliasCount(query)), "", "", passes)
	addField(parsed, "graphql", "has_introspection", "GRAPHQL:has_introspection", strconv.FormatBool(graphQLHasIntrospection(query)), "", "", passes)
	addField(parsed, "graphql", "has_alias_introspection", "GRAPHQL:has_alias_introspection", strconv.FormatBool(graphQLHasAliasIntrospection(query)), "", "", passes)
}

func firstGraphQLQuery(parsed *ParsedRequest, mediaType string, body []byte) string {
	switch mediaType {
	case "application/graphql":
		return strings.TrimSpace(string(body))
	case "application/json":
		for _, field := range parsed.Fields {
			if strings.EqualFold(field.Variable, "JSON:query") && looksLikeGraphQL(field.NormalizedValue) {
				return field.NormalizedValue
			}
		}
	}
	for _, field := range parsed.Fields {
		if strings.EqualFold(field.Variable, "ARGS:query") && looksLikeGraphQL(field.NormalizedValue) {
			return field.NormalizedValue
		}
	}
	return ""
}

func looksLikeGraphQL(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(lower, "__schema") || strings.Contains(lower, "__type") || strings.Contains(lower, "query") || strings.Contains(lower, "mutation") || strings.Contains(lower, "{")
}

func graphQLDepth(query string) int {
	depth := 0
	maxDepth := 0
	inString := false
	escape := false
	for _, ch := range query {
		if inString {
			if escape {
				escape = false
				continue
			}
			if ch == '\\' {
				escape = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '{':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return maxDepth
}

func graphQLAliasCount(query string) int {
	return len(graphqlAliasPattern.FindAllString(query, -1))
}

func graphQLHasIntrospection(query string) bool {
	lower := strings.ToLower(query)
	return strings.Contains(lower, "__schema") || strings.Contains(lower, "__type")
}

func graphQLHasAliasIntrospection(query string) bool {
	matches := graphqlAliasPattern.FindAllString(strings.ToLower(query), -1)
	for _, match := range matches {
		if strings.Contains(match, "__schema") || strings.Contains(match, "__type") {
			return true
		}
	}
	return false
}

func enrichJWT(parsed *ParsedRequest, headers http.Header, passes int) {
	token := bearerToken(headers.Get("Authorization"))
	if token == "" {
		return
	}
	headerClaims, payloadClaims, hasSignature, ok := parseCompactJWT(token)
	if !ok {
		return
	}
	addField(parsed, "jwt", "token", "JWT:token", token, "", "", passes)
	addField(parsed, "jwt", "signature.present", "JWT:signature.present", strconv.FormatBool(hasSignature), "", "", passes)
	flattenJWTClaims(parsed, "header", headerClaims, passes)
	flattenJWTClaims(parsed, "payload", payloadClaims, passes)
}

func bearerToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return strings.TrimSpace(value[len("bearer "):])
	}
	return value
}

func parseCompactJWT(token string) (map[string]any, map[string]any, bool, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return nil, nil, false, false
	}
	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil {
		return nil, nil, false, false
	}
	payloadBytes, err := decodeJWTPart(parts[1])
	if err != nil {
		return nil, nil, false, false
	}
	headerClaims := map[string]any{}
	payloadClaims := map[string]any{}
	if err := json.Unmarshal(headerBytes, &headerClaims); err != nil {
		return nil, nil, false, false
	}
	if err := json.Unmarshal(payloadBytes, &payloadClaims); err != nil {
		return nil, nil, false, false
	}
	return headerClaims, payloadClaims, strings.TrimSpace(parts[2]) != "", true
}

func decodeJWTPart(value string) ([]byte, error) {
	if mod := len(value) % 4; mod != 0 {
		value += strings.Repeat("=", 4-mod)
	}
	return base64.URLEncoding.DecodeString(value)
}

func flattenJWTClaims(parsed *ParsedRequest, prefix string, value any, passes int) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			name := prefix + "." + key
			flattenJWTClaims(parsed, name, child, passes)
		}
	case []any:
		for i, child := range typed {
			flattenJWTClaims(parsed, fmt.Sprintf("%s[%d]", prefix, i), child, passes)
		}
	case string:
		addField(parsed, "jwt", prefix, "JWT:"+prefix, typed, "", "", passes)
	case json.Number:
		addField(parsed, "jwt", prefix, "JWT:"+prefix, typed.String(), "", "", passes)
	case bool:
		addField(parsed, "jwt", prefix, "JWT:"+prefix, strconv.FormatBool(typed), "", "", passes)
	case nil:
		return
	default:
		addField(parsed, "jwt", prefix, "JWT:"+prefix, fmt.Sprint(typed), "", "", passes)
	}
}
