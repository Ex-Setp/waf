package sqlparser

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
	tokenLParen
	tokenRParen
	tokenComment
)

type token struct {
	typ   tokenType
	value string
	start int
	end   int
}

var keywords = map[string]struct{}{
	"select": {}, "from": {}, "where": {}, "union": {}, "and": {}, "or": {},
	"as": {}, "order": {}, "by": {}, "group": {}, "having": {}, "limit": {},
	"offset": {}, "insert": {}, "update": {}, "delete": {}, "drop": {}, "into": {},
	"values": {}, "set": {}, "join": {}, "on": {}, "null": {}, "true": {}, "false": {},
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
			pos++
			for pos < len(input) && (unicode.IsDigit(rune(input[pos])) || input[pos] == '.') {
				pos++
			}
			tokens = append(tokens, token{typ: tokenNumber, value: input[start:pos], start: start, end: pos})
		case r == '\'' || r == '"':
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
		case r == '-' && pos+1 < len(input) && input[pos+1] == '-':
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
			pos++
			tokens = append(tokens, token{typ: tokenDot, value: input[start:pos], start: start, end: pos})
		case r == '(':
			pos++
			tokens = append(tokens, token{typ: tokenLParen, value: input[start:pos], start: start, end: pos})
		case r == ')':
			pos++
			tokens = append(tokens, token{typ: tokenRParen, value: input[start:pos], start: start, end: pos})
		case strings.ContainsRune("=<>!+-*/%|&^~*", r):
			pos++
			if pos < len(input) && strings.ContainsRune("=<>|&", rune(input[pos])) {
				pos++
			}
			tokens = append(tokens, token{typ: tokenOperator, value: input[start:pos], start: start, end: pos})
		default:
			return nil, nil, &ParseError{Message: fmt.Sprintf("unexpected character %q", r), Offset: start}
		}
	}
	tokens = append(tokens, token{typ: tokenEOF, start: len(input), end: len(input)})
	return tokens, comments, nil
}

func isIdentifierStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_' || r == '$'
}

func isIdentifierPart(r rune) bool {
	return isIdentifierStart(r) || unicode.IsDigit(r)
}
