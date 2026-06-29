package jsparser

import (
	"fmt"
	"strings"
	"unicode"
)

type tokenType int

const (
	tokenEOF tokenType = iota
	tokenIdentifier
	tokenKeyword
	tokenString
	tokenNumber
	tokenOperator
	tokenComma
	tokenDot
	tokenColon
	tokenSemicolon
	tokenLParen
	tokenRParen
	tokenLBracket
	tokenRBracket
	tokenLBrace
	tokenRBrace
	tokenComment
)

type token struct {
	typ   tokenType
	value string
	start int
	end   int
}

var keywords = map[string]struct{}{
	"break": {}, "case": {}, "catch": {}, "class": {}, "const": {}, "continue": {},
	"debugger": {}, "default": {}, "delete": {}, "do": {}, "else": {}, "export": {},
	"extends": {}, "finally": {}, "for": {}, "function": {}, "if": {}, "import": {},
	"in": {}, "instanceof": {}, "let": {}, "new": {}, "return": {}, "super": {},
	"switch": {}, "this": {}, "throw": {}, "try": {}, "typeof": {}, "var": {},
	"void": {}, "while": {}, "with": {}, "yield": {}, "true": {}, "false": {},
	"null": {}, "undefined": {},
}

func tokenize(input string) ([]token, []*Node, error) {
	var tokens []token
	var comments []*Node
	for pos := 0; pos < len(input); {
		r := rune(input[pos])
		if unicode.IsSpace(r) {
			pos++
			continue
		}
		start := pos
		switch {
		case isIdentifierStart(r):
			pos++
			for pos < len(input) && isIdentifierPart(rune(input[pos])) {
				pos++
			}
			value := input[start:pos]
			typ := tokenIdentifier
			if _, ok := keywords[strings.ToLower(value)]; ok {
				typ = tokenKeyword
			}
			tokens = append(tokens, token{typ: typ, value: value, start: start, end: pos})
		case unicode.IsDigit(r):
			pos = scanNumber(input, pos)
			tokens = append(tokens, token{typ: tokenNumber, value: input[start:pos], start: start, end: pos})
		case r == '\'' || r == '"' || r == '`':
			quote := input[pos]
			pos++
			for pos < len(input) {
				if input[pos] == quote {
					pos++
					break
				}
				if input[pos] == '\\' && pos+1 < len(input) {
					pos += 2
					continue
				}
				pos++
			}
			if pos > len(input) || input[pos-1] != quote {
				return nil, nil, &ParseError{Message: "unterminated string literal", Offset: start}
			}
			tokens = append(tokens, token{typ: tokenString, value: input[start:pos], start: start, end: pos})
		case r == '/' && pos+1 < len(input) && input[pos+1] == '/':
			pos += 2
			for pos < len(input) && input[pos] != '\n' && input[pos] != '\r' {
				pos++
			}
			comment := &Node{Type: NodeComment, Value: input[start:pos], Start: start, End: pos}
			comments = append(comments, comment)
			tokens = append(tokens, token{typ: tokenComment, value: input[start:pos], start: start, end: pos})
		case r == '/' && pos+1 < len(input) && input[pos+1] == '*':
			pos += 2
			for pos+1 < len(input) && !(input[pos] == '*' && input[pos+1] == '/') {
				pos++
			}
			if pos+1 >= len(input) {
				return nil, nil, &ParseError{Message: "unterminated block comment", Offset: start}
			}
			pos += 2
			comment := &Node{Type: NodeComment, Value: input[start:pos], Start: start, End: pos}
			comments = append(comments, comment)
			tokens = append(tokens, token{typ: tokenComment, value: input[start:pos], start: start, end: pos})
		case r == ',':
			pos++
			tokens = append(tokens, token{typ: tokenComma, value: input[start:pos], start: start, end: pos})
		case r == '.':
			if pos+1 < len(input) && unicode.IsDigit(rune(input[pos+1])) {
				pos = scanNumber(input, pos)
				tokens = append(tokens, token{typ: tokenNumber, value: input[start:pos], start: start, end: pos})
				break
			}
			pos++
			tokens = append(tokens, token{typ: tokenDot, value: input[start:pos], start: start, end: pos})
		case r == ':':
			pos++
			tokens = append(tokens, token{typ: tokenColon, value: input[start:pos], start: start, end: pos})
		case r == ';':
			pos++
			tokens = append(tokens, token{typ: tokenSemicolon, value: input[start:pos], start: start, end: pos})
		case r == '(':
			pos++
			tokens = append(tokens, token{typ: tokenLParen, value: input[start:pos], start: start, end: pos})
		case r == ')':
			pos++
			tokens = append(tokens, token{typ: tokenRParen, value: input[start:pos], start: start, end: pos})
		case r == '[':
			pos++
			tokens = append(tokens, token{typ: tokenLBracket, value: input[start:pos], start: start, end: pos})
		case r == ']':
			pos++
			tokens = append(tokens, token{typ: tokenRBracket, value: input[start:pos], start: start, end: pos})
		case r == '{':
			pos++
			tokens = append(tokens, token{typ: tokenLBrace, value: input[start:pos], start: start, end: pos})
		case r == '}':
			pos++
			tokens = append(tokens, token{typ: tokenRBrace, value: input[start:pos], start: start, end: pos})
		case isOperatorStart(r):
			pos++
			for pos < len(input) && pos-start < 3 && isOperatorPart(rune(input[pos])) {
				candidate := input[start : pos+1]
				if !isKnownOperatorPrefix(candidate) {
					break
				}
				pos++
			}
			value := input[start:pos]
			if !isKnownOperator(value) {
				return nil, nil, &ParseError{Message: fmt.Sprintf("unexpected operator %q", value), Offset: start}
			}
			tokens = append(tokens, token{typ: tokenOperator, value: value, start: start, end: pos})
		default:
			return nil, nil, &ParseError{Message: fmt.Sprintf("unexpected character %q", r), Offset: start}
		}
	}
	tokens = append(tokens, token{typ: tokenEOF, start: len(input), end: len(input)})
	return tokens, comments, nil
}

func scanNumber(input string, pos int) int {
	if pos+1 < len(input) && input[pos] == '0' && (input[pos+1] == 'x' || input[pos+1] == 'X') {
		pos += 2
		for pos < len(input) && isHexDigit(input[pos]) {
			pos++
		}
		return pos
	}
	for pos < len(input) && unicode.IsDigit(rune(input[pos])) {
		pos++
	}
	if pos < len(input) && input[pos] == '.' {
		pos++
		for pos < len(input) && unicode.IsDigit(rune(input[pos])) {
			pos++
		}
	}
	if pos < len(input) && (input[pos] == 'e' || input[pos] == 'E') {
		next := pos + 1
		if next < len(input) && (input[next] == '+' || input[next] == '-') {
			next++
		}
		if next < len(input) && unicode.IsDigit(rune(input[next])) {
			pos = next + 1
			for pos < len(input) && unicode.IsDigit(rune(input[pos])) {
				pos++
			}
		}
	}
	return pos
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func isIdentifierStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_' || r == '$'
}

func isIdentifierPart(r rune) bool {
	return isIdentifierStart(r) || unicode.IsDigit(r)
}

func isOperatorStart(r rune) bool {
	return strings.ContainsRune("=<>!+-*/%|&^~?", r)
}

func isOperatorPart(r rune) bool {
	return strings.ContainsRune("=<>+-|&*?", r)
}

func isKnownOperator(value string) bool {
	switch value {
	case "=", "+=", "-=", "*=", "/=", "%=", "==", "===", "!=", "!==",
		"<", ">", "<=", ">=", "+", "-", "*", "/", "%", "&&", "||", "!",
		"~", "&", "|", "^", "<<", ">>", ">>>", "++", "--", "?", "=>":
		return true
	default:
		return false
	}
}

func isKnownOperatorPrefix(value string) bool {
	if isKnownOperator(value) {
		return true
	}
	for _, op := range []string{"+=", "-=", "*=", "/=", "%=", "==", "===", "!=", "!==", "<=", ">=", "&&", "||", "<<", ">>", ">>>", "++", "--", "=>"} {
		if strings.HasPrefix(op, value) {
			return true
		}
	}
	return false
}
