package normalizer

import (
	"html"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

const maxDecodePasses = 3

var (
	slashCommentPattern = regexp.MustCompile(`/\*.*?\*/`)
	lineCommentPattern  = regexp.MustCompile(`(?m)(--|#)[^\r\n]*`)
	spacePattern        = regexp.MustCompile(`\s+`)
	unionSplitPattern   = regexp.MustCompile(`(?i)\bun\s+ion\b`)
	selectSplitPattern  = regexp.MustCompile(`(?i)\bsel\s+ect\b`)
	insertSplitPattern  = regexp.MustCompile(`(?i)\bins\s+ert\b`)
	updateSplitPattern  = regexp.MustCompile(`(?i)\bup\s+date\b`)
	deleteSplitPattern  = regexp.MustCompile(`(?i)\bdel\s+ete\b`)
)

type Request struct {
	Method  string
	URI     string
	Headers http.Header
	Body    string
	Args    map[string][]string
}

func RequestCopy(req Request) Request {
	return Request{
		Method:  normalizeMethod(req.Method),
		URI:     NormalizePath(req.URI),
		Headers: NormalizeHeaders(req.Headers),
		Body:    NormalizeValue(req.Body),
		Args:    NormalizeArgs(req.Args),
	}
}

func NormalizeArgs(args map[string][]string) map[string][]string {
	if len(args) == 0 {
		return nil
	}
	out := make(map[string][]string, len(args))
	for key, values := range args {
		normalizedKey := strings.ToLower(NormalizeValue(key))
		if normalizedKey == "" {
			continue
		}
		for _, value := range values {
			out[normalizedKey] = append(out[normalizedKey], NormalizeValue(value))
		}
	}
	return out
}

func NormalizeHeaders(headers http.Header) http.Header {
	if len(headers) == 0 {
		return nil
	}
	out := make(http.Header, len(headers))
	for key, values := range headers {
		canonicalKey := http.CanonicalHeaderKey(strings.TrimSpace(key))
		for _, value := range values {
			out.Add(canonicalKey, NormalizeValue(value))
		}
	}
	return out
}

func NormalizePath(uri string) string {
	if uri == "" {
		return ""
	}
	decoded := NormalizeValue(uri)
	pathPart, queryPart, hasQuery := strings.Cut(decoded, "?")
	cleaned := cleanPathOnly(pathPart)
	if !hasQuery {
		return cleaned
	}
	queryPart = normalizeRawQuery(queryPart)
	if queryPart == "" {
		return cleaned
	}
	return cleaned + "?" + queryPart
}

func NormalizeValue(value string) string {
	if value == "" {
		return ""
	}
	current := value
	for i := 0; i < maxDecodePasses; i++ {
		next := html.UnescapeString(current)
		next = decodeUnicodeEscapes(next)
		if decoded, err := url.QueryUnescape(next); err == nil {
			next = decoded
		} else if decoded, err := url.PathUnescape(next); err == nil {
			next = decoded
		}
		if next == current {
			break
		}
		current = next
	}
	current = strings.ToValidUTF8(current, "")
	current = normalizeSQLNoise(current)
	return strings.TrimSpace(current)
}

func normalizeMethod(method string) string {
	method = strings.TrimSpace(method)
	if method == "" {
		return ""
	}
	return strings.ToUpper(method)
}

func normalizeRawQuery(raw string) string {
	if raw == "" {
		return ""
	}
	pairs := strings.Split(raw, "&")
	out := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		if pair == "" {
			continue
		}
		key, value, hasValue := strings.Cut(pair, "=")
		key = strings.ToLower(NormalizeValue(key))
		if key == "" {
			continue
		}
		if hasValue {
			out = append(out, key+"="+NormalizeValue(value))
		} else {
			out = append(out, key)
		}
	}
	return strings.Join(out, "&")
}

func cleanPathOnly(value string) string {
	if value == "" {
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
	if strings.HasSuffix(value, "/") && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}
	return cleaned
}

func normalizeSQLNoise(value string) string {
	value = slashCommentPattern.ReplaceAllString(value, " ")
	value = lineCommentPattern.ReplaceAllString(value, " ")
	value = spacePattern.ReplaceAllString(value, " ")
	value = unionSplitPattern.ReplaceAllString(value, "union")
	value = selectSplitPattern.ReplaceAllString(value, "select")
	value = insertSplitPattern.ReplaceAllString(value, "insert")
	value = updateSplitPattern.ReplaceAllString(value, "update")
	value = deleteSplitPattern.ReplaceAllString(value, "delete")
	return value
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
		if i+4 <= len(value) && value[i] == '%' && (value[i+1] == 'u' || value[i+1] == 'U') {
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
