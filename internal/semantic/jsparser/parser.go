package jsparser

import (
	"fmt"
	"strings"
)

type Parser struct {
	tokens []token
	pos    int
}

func Parse(input string) (*AST, error) {
	tokens, comments, err := tokenize(input)
	if err != nil {
		return nil, err
	}
	p := &Parser{tokens: tokens}
	root, err := p.parseProgram(len(input))
	if err != nil {
		return nil, err
	}
	skeleton, hash := normalize(root, comments)
	return &AST{Input: input, Root: root, Comments: comments, Skeleton: skeleton, SkeletonHash: hash}, nil
}

func (p *Parser) parseProgram(inputLen int) (*Node, error) {
	root := &Node{Type: NodeProgram, Value: "script", Start: 0, End: inputLen}
	for {
		p.skipTrivia()
		if p.peek().typ == tokenEOF {
			break
		}
		expr, err := p.parseExpression(0)
		if err != nil {
			return nil, err
		}
		root.add(expr)
		root.End = expr.End
		p.skipTrivia()
		hadSemicolon := false
		for p.match(tokenSemicolon) {
			hadSemicolon = true
			p.skipTrivia()
		}
		if p.peek().typ == tokenEOF {
			break
		}
		if hadSemicolon {
			continue
		}
		if isClosingToken(p.peek().typ) {
			return nil, &ParseError{Message: fmt.Sprintf("unexpected token %q", p.peek().value), Offset: p.peek().start}
		}
		return nil, &ParseError{Message: fmt.Sprintf("unexpected token %q", p.peek().value), Offset: p.peek().start}
	}
	return root, nil
}

func (p *Parser) parseExpression(minPrec int) (*Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		p.skipTrivia()
		tok := p.peek()
		prec := precedence(tok)
		if prec < minPrec {
			break
		}
		p.advance()
		nextMin := prec + 1
		if isAssignmentOperator(tok.value) {
			nextMin = prec
		}
		right, err := p.parseExpression(nextMin)
		if err != nil {
			return nil, err
		}
		typ := NodeBinary
		if isAssignmentOperator(tok.value) {
			typ = NodeAssignment
		}
		node := &Node{Type: typ, Value: tok.value, Start: left.Start, End: right.End}
		node.add(left, right)
		left = node
	}
	return left, nil
}

func (p *Parser) parseUnary() (*Node, error) {
	p.skipTrivia()
	tok := p.peek()
	if tok.typ == tokenOperator && isUnaryOperator(tok.value) {
		p.advance()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		node := &Node{Type: NodeUnary, Value: tok.value, Start: tok.start, End: right.End}
		node.add(right)
		return node, nil
	}
	if tok.typ == tokenKeyword && isUnaryKeyword(tok.value) {
		p.advance()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		node := &Node{Type: NodeUnary, Value: strings.ToLower(tok.value), Start: tok.start, End: right.End}
		node.add(right)
		return node, nil
	}
	primary, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	return p.parsePostfix(primary)
}

func (p *Parser) parsePostfix(left *Node) (*Node, error) {
	for {
		p.skipTrivia()
		switch p.peek().typ {
		case tokenDot:
			p.advance()
			propTok := p.advance()
			if propTok.typ != tokenIdentifier && propTok.typ != tokenKeyword {
				return nil, &ParseError{Message: "expected property name", Offset: propTok.start}
			}
			prop := &Node{Type: NodeIdentifier, Value: propTok.value, Start: propTok.start, End: propTok.end}
			member := &Node{Type: NodeMember, Value: propTok.value, Start: left.Start, End: propTok.end}
			member.add(left, prop)
			left = member
		case tokenLBracket:
			start := p.advance()
			if p.peek().typ == tokenRBracket {
				return nil, &ParseError{Message: "expected index expression", Offset: p.peek().start}
			}
			index, err := p.parseExpression(0)
			if err != nil {
				return nil, err
			}
			if !p.match(tokenRBracket) {
				return nil, &ParseError{Message: "expected closing bracket", Offset: p.peek().start}
			}
			close := p.previous()
			node := &Node{Type: NodeIndex, Value: "[]", Start: left.Start, End: close.end}
			if index.Type == NodeLiteral && index.LiteralType == LiteralString {
				node.Value = literalPropertyName(index.Value)
			}
			if close.end < start.end {
				node.End = start.end
			}
			node.add(left, index)
			left = node
		case tokenLParen:
			p.advance()
			call := &Node{Type: NodeCall, Value: calleeName(left), Start: left.Start, End: left.End}
			call.add(left)
			for p.peek().typ != tokenRParen {
				if p.peek().typ == tokenEOF {
					return nil, &ParseError{Message: "unterminated function call", Offset: call.Start}
				}
				arg, err := p.parseExpression(0)
				if err != nil {
					return nil, err
				}
				call.add(arg)
				call.End = arg.End
				if !p.match(tokenComma) {
					break
				}
			}
			if !p.match(tokenRParen) {
				return nil, &ParseError{Message: "expected closing parenthesis", Offset: p.peek().start}
			}
			call.End = p.previous().end
			left = call
		case tokenOperator:
			if p.peek().value != "++" && p.peek().value != "--" {
				return left, nil
			}
			tok := p.advance()
			node := &Node{Type: NodeUnary, Value: tok.value, Start: left.Start, End: tok.end}
			node.add(left)
			left = node
		default:
			return left, nil
		}
	}
}

func (p *Parser) parsePrimary() (*Node, error) {
	p.skipTrivia()
	tok := p.advance()
	switch tok.typ {
	case tokenIdentifier:
		return &Node{Type: NodeIdentifier, Value: tok.value, Start: tok.start, End: tok.end}, nil
	case tokenKeyword:
		value := strings.ToLower(tok.value)
		switch value {
		case "true", "false":
			return &Node{Type: NodeLiteral, Value: value, LiteralType: LiteralBoolean, Start: tok.start, End: tok.end}, nil
		case "null":
			return &Node{Type: NodeLiteral, Value: value, LiteralType: LiteralNull, Start: tok.start, End: tok.end}, nil
		case "this", "undefined":
			return &Node{Type: NodeIdentifier, Value: tok.value, Start: tok.start, End: tok.end}, nil
		default:
			return nil, &ParseError{Message: fmt.Sprintf("unexpected keyword %q", tok.value), Offset: tok.start}
		}
	case tokenString:
		return &Node{Type: NodeLiteral, Value: tok.value, LiteralType: LiteralString, Start: tok.start, End: tok.end}, nil
	case tokenNumber:
		return &Node{Type: NodeLiteral, Value: tok.value, LiteralType: LiteralNumber, Start: tok.start, End: tok.end}, nil
	case tokenLParen:
		expr, err := p.parseExpression(0)
		if err != nil {
			return nil, err
		}
		if !p.match(tokenRParen) {
			return nil, &ParseError{Message: "expected closing parenthesis", Offset: p.peek().start}
		}
		expr.End = p.previous().end
		return expr, nil
	case tokenLBracket:
		return p.parseArray(tok)
	case tokenLBrace:
		return p.parseObject(tok)
	default:
		return nil, &ParseError{Message: fmt.Sprintf("unexpected token %q", tok.value), Offset: tok.start}
	}
}

func (p *Parser) parseArray(start token) (*Node, error) {
	array := &Node{Type: NodeArray, Value: "array", Start: start.start, End: start.end}
	for p.peek().typ != tokenRBracket {
		if p.peek().typ == tokenEOF {
			return nil, &ParseError{Message: "unterminated array literal", Offset: start.start}
		}
		if p.match(tokenComma) {
			continue
		}
		item, err := p.parseExpression(0)
		if err != nil {
			return nil, err
		}
		array.add(item)
		array.End = item.End
		if !p.match(tokenComma) {
			break
		}
	}
	if !p.match(tokenRBracket) {
		return nil, &ParseError{Message: "expected closing bracket", Offset: p.peek().start}
	}
	array.End = p.previous().end
	return array, nil
}

func (p *Parser) parseObject(start token) (*Node, error) {
	object := &Node{Type: NodeObject, Value: "object", Start: start.start, End: start.end}
	for p.peek().typ != tokenRBrace {
		if p.peek().typ == tokenEOF {
			return nil, &ParseError{Message: "unterminated object literal", Offset: start.start}
		}
		keyTok := p.advance()
		if keyTok.typ != tokenIdentifier && keyTok.typ != tokenKeyword && keyTok.typ != tokenString && keyTok.typ != tokenNumber {
			return nil, &ParseError{Message: "expected object property", Offset: keyTok.start}
		}
		property := &Node{Type: NodeProperty, Value: propertyName(keyTok), Start: keyTok.start, End: keyTok.end}
		if p.match(tokenColon) {
			value, err := p.parseExpression(0)
			if err != nil {
				return nil, err
			}
			property.add(value)
			property.End = value.End
		} else if keyTok.typ == tokenIdentifier || keyTok.typ == tokenKeyword {
			property.add(&Node{Type: NodeIdentifier, Value: keyTok.value, Start: keyTok.start, End: keyTok.end})
		} else {
			return nil, &ParseError{Message: "expected property value", Offset: p.peek().start}
		}
		object.add(property)
		object.End = property.End
		if !p.match(tokenComma) {
			break
		}
	}
	if !p.match(tokenRBrace) {
		return nil, &ParseError{Message: "expected closing brace", Offset: p.peek().start}
	}
	object.End = p.previous().end
	return object, nil
}

func precedence(tok token) int {
	if tok.typ == tokenKeyword {
		switch strings.ToLower(tok.value) {
		case "in", "instanceof":
			return 8
		default:
			return -1
		}
	}
	if tok.typ != tokenOperator {
		return -1
	}
	switch tok.value {
	case "=", "+=", "-=", "*=", "/=", "%=":
		return 1
	case "||":
		return 2
	case "&&":
		return 3
	case "|":
		return 4
	case "^":
		return 5
	case "&":
		return 6
	case "==", "===", "!=", "!==":
		return 7
	case "<", ">", "<=", ">=":
		return 8
	case "<<", ">>", ">>>":
		return 9
	case "+", "-":
		return 10
	case "*", "/", "%":
		return 11
	default:
		return -1
	}
}

func isAssignmentOperator(value string) bool {
	switch value {
	case "=", "+=", "-=", "*=", "/=", "%=":
		return true
	default:
		return false
	}
}

func isUnaryOperator(value string) bool {
	switch value {
	case "!", "~", "+", "-", "++", "--":
		return true
	default:
		return false
	}
}

func isUnaryKeyword(value string) bool {
	switch strings.ToLower(value) {
	case "delete", "typeof", "void", "new":
		return true
	default:
		return false
	}
}

func propertyName(tok token) string {
	if tok.typ == tokenString && len(tok.value) >= 2 {
		return literalPropertyName(tok.value)
	}
	return tok.value
}

func literalPropertyName(value string) string {
	if len(value) >= 2 {
		return value[1 : len(value)-1]
	}
	return value
}

func isClosingToken(typ tokenType) bool {
	return typ == tokenRParen || typ == tokenRBracket || typ == tokenRBrace
}

func (p *Parser) skipTrivia() {
	for p.peek().typ == tokenComment {
		p.advance()
	}
}

func (p *Parser) match(typ tokenType) bool {
	if p.peek().typ != typ {
		return false
	}
	p.advance()
	return true
}

func (p *Parser) advance() token {
	tok := p.peek()
	if p.pos < len(p.tokens)-1 {
		p.pos++
	}
	return tok
}

func (p *Parser) previous() token {
	if p.pos == 0 {
		return token{typ: tokenEOF}
	}
	return p.tokens[p.pos-1]
}

func (p *Parser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{typ: tokenEOF}
	}
	return p.tokens[p.pos]
}
