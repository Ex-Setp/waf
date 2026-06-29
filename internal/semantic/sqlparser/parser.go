package sqlparser

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
	root, statement, err := p.parseStatement()
	if err != nil {
		return nil, err
	}
	if tok := p.peek(); tok.typ != tokenEOF {
		return nil, &ParseError{Message: fmt.Sprintf("unexpected token %q", tok.value), Offset: tok.start}
	}
	root.add(comments...)
	skeleton, hash := normalize(root, comments)
	return &AST{Input: input, Statement: statement, Root: root, Comments: comments, Skeleton: skeleton, SkeletonHash: hash}, nil
}

func (p *Parser) parseStatement() (*Node, StatementType, error) {
	p.skipComments()
	if p.matchKeyword("select") {
		selectNode, err := p.parseSelect(p.previous())
		if err != nil {
			return nil, StatementUnknown, err
		}
		root := &Node{Type: NodeStatement, Value: "select", Start: selectNode.Start, End: selectNode.End}
		root.add(selectNode)
		statement := StatementSelect
		for p.matchKeyword("union") {
			unionTok := p.previous()
			unionNode := &Node{Type: NodeUnion, Value: strings.ToLower(unionTok.value), Start: unionTok.start, End: unionTok.end}
			if p.matchKeyword("all") {
				unionNode.Value = "union all"
				unionNode.End = p.previous().end
			}
			if !p.matchKeyword("select") {
				return nil, StatementUnknown, &ParseError{Message: "expected SELECT after UNION", Offset: p.peek().start}
			}
			nextSelect, err := p.parseSelect(p.previous())
			if err != nil {
				return nil, StatementUnknown, err
			}
			unionNode.add(nextSelect)
			root.add(unionNode)
			root.End = unionNode.End
			statement = StatementUnion
		}
		return root, statement, nil
	}
	return nil, StatementUnknown, &ParseError{Message: "expected SELECT statement", Offset: p.peek().start}
}

func (p *Parser) parseSelect(selectTok token) (*Node, error) {
	node := &Node{Type: NodeSelect, Value: "select", Start: selectTok.start, End: selectTok.end}
	list := &Node{Type: NodeList, Value: "columns", Start: selectTok.end, End: selectTok.end}
	for {
		p.skipComments()
		if p.isClauseBoundary() || p.peek().typ == tokenEOF {
			break
		}
		expr, err := p.parseExpression(0)
		if err != nil {
			return nil, err
		}
		list.add(expr)
		list.End = expr.End
		if !p.match(tokenComma) {
			break
		}
	}
	if len(list.Children) == 0 {
		return nil, &ParseError{Message: "SELECT list is empty", Offset: selectTok.end}
	}
	node.add(list)
	node.End = list.End
	for p.isClauseBoundary() {
		clause, err := p.parseClause()
		if err != nil {
			return nil, err
		}
		node.add(clause)
		node.End = clause.End
	}
	return node, nil
}

func (p *Parser) parseClause() (*Node, error) {
	start := p.advance()
	value := strings.ToLower(start.value)
	if value == "order" || value == "group" {
		if p.matchKeyword("by") {
			value += " by"
		}
	}
	clause := &Node{Type: NodeClause, Value: value, Start: start.start, End: start.end}
	for {
		p.skipComments()
		if p.peek().typ == tokenEOF || p.peekKeyword("union") || p.isClauseBoundary() {
			break
		}
		expr, err := p.parseExpression(0)
		if err != nil {
			return nil, err
		}
		clause.add(expr)
		clause.End = expr.End
		p.match(tokenComma)
	}
	return clause, nil
}

func (p *Parser) parseExpression(minPrec int) (*Node, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for {
		p.skipComments()
		tok := p.peek()
		prec := precedence(tok)
		if prec < minPrec {
			break
		}
		p.advance()
		right, err := p.parseExpression(prec + 1)
		if err != nil {
			return nil, err
		}
		op := &Node{Type: NodeOperator, Value: strings.ToLower(tok.value), Start: left.Start, End: right.End}
		op.add(left, right)
		left = op
	}
	return left, nil
}

func (p *Parser) parsePrimary() (*Node, error) {
	p.skipComments()
	tok := p.advance()
	switch tok.typ {
	case tokenIdentifier, tokenKeyword:
		if p.match(tokenLParen) {
			fn := &Node{Type: NodeFunction, Value: tok.value, Start: tok.start, End: tok.end}
			for p.peek().typ != tokenRParen {
				if p.peek().typ == tokenEOF {
					return nil, &ParseError{Message: "unterminated function call", Offset: tok.start}
				}
				expr, err := p.parseExpression(0)
				if err != nil {
					return nil, err
				}
				fn.add(expr)
				fn.End = expr.End
				if !p.match(tokenComma) {
					break
				}
			}
			if !p.match(tokenRParen) {
				return nil, &ParseError{Message: "expected closing parenthesis", Offset: p.peek().start}
			}
			fn.End = p.previous().end
			return fn, nil
		}
		return &Node{Type: NodeIdentifier, Value: tok.value, Start: tok.start, End: tok.end}, nil
	case tokenString:
		return &Node{Type: NodeLiteral, Value: tok.value, LiteralType: LiteralString, Start: tok.start, End: tok.end}, nil
	case tokenNumber:
		return &Node{Type: NodeLiteral, Value: tok.value, LiteralType: LiteralNumber, Start: tok.start, End: tok.end}, nil
	case tokenOperator:
		if tok.value == "*" {
			return &Node{Type: NodeWildcard, Value: tok.value, Start: tok.start, End: tok.end}, nil
		}
		if tok.value == "+" || tok.value == "-" || tok.value == "!" || tok.value == "~" {
			right, err := p.parseExpression(4)
			if err != nil {
				return nil, err
			}
			node := &Node{Type: NodeOperator, Value: tok.value, Start: tok.start, End: right.End}
			node.add(right)
			return node, nil
		}
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
	}
	return nil, &ParseError{Message: fmt.Sprintf("unexpected token %q", tok.value), Offset: tok.start}
}

func precedence(tok token) int {
	if tok.typ == tokenKeyword {
		switch strings.ToLower(tok.value) {
		case "or":
			return 1
		case "and":
			return 2
		}
	}
	if tok.typ != tokenOperator {
		return -1
	}
	switch tok.value {
	case "=", "!=", "<>", "<", ">", "<=", ">=":
		return 2
	case "+", "-", "||":
		return 3
	case "*", "/", "%":
		return 4
	default:
		return -1
	}
}

func (p *Parser) isClauseBoundary() bool {
	return p.peekKeyword("from") || p.peekKeyword("where") || p.peekKeyword("order") || p.peekKeyword("group") || p.peekKeyword("having") || p.peekKeyword("limit") || p.peekKeyword("offset") || p.peekKeyword("join") || p.peekKeyword("on")
}

func (p *Parser) skipComments() {
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

func (p *Parser) matchKeyword(value string) bool {
	if !p.peekKeyword(value) {
		return false
	}
	p.advance()
	return true
}

func (p *Parser) peekKeyword(value string) bool {
	tok := p.peek()
	return tok.typ == tokenKeyword && strings.EqualFold(tok.value, value)
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
