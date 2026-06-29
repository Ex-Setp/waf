package skeleton

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"aegis-waf/internal/semantic/jsparser"
	"aegis-waf/internal/semantic/sqlparser"
)

const (
	LanguageSQL = "sql"
	LanguageJS  = "js"
)

// ASTSkeleton is a canonical fingerprint extracted from an AST.
type ASTSkeleton struct {
	Language  string
	NodeTypes []string
	Structure string
	Hash      string
	Depth     int
}

// ParseSQL parses SQL and returns its canonical AST skeleton.
func ParseSQL(input string) (*ASTSkeleton, error) {
	ast, err := sqlparser.Parse(input)
	if err != nil {
		return nil, err
	}
	return FromSQLAST(ast), nil
}

// ParseJS parses JavaScript and returns its canonical AST skeleton.
func ParseJS(input string) (*ASTSkeleton, error) {
	ast, err := jsparser.Parse(input)
	if err != nil {
		return nil, err
	}
	return FromJSAST(ast), nil
}

// FromSQLAST extracts a canonical skeleton from a parsed SQL AST.
func FromSQLAST(ast *sqlparser.AST) *ASTSkeleton {
	if ast == nil || ast.Root == nil {
		return &ASTSkeleton{Language: LanguageSQL}
	}
	return buildSkeleton(LanguageSQL, sqlNodeTypeLabel, ast.Root)
}

// FromJSAST extracts a canonical skeleton from a parsed JS AST.
func FromJSAST(ast *jsparser.AST) *ASTSkeleton {
	if ast == nil || ast.Root == nil {
		return &ASTSkeleton{Language: LanguageJS}
	}
	return buildSkeleton(LanguageJS, jsNodeTypeLabel, ast.Root)
}

func buildSkeleton(language string, labelFn func(any) string, root any) *ASTSkeleton {
	var nodeTypes []string
	var parts []string
	depth := 0
	walk(root, labelFn, 1, &nodeTypes, &parts, &depth)
	structure := strings.Join(parts, " ")
	sum := sha256.Sum256([]byte(language + "\x00" + structure))
	return &ASTSkeleton{
		Language:  language,
		NodeTypes: nodeTypes,
		Structure: structure,
		Hash:      hex.EncodeToString(sum[:]),
		Depth:     depth,
	}
}

func walk(node any, labelFn func(any) string, level int, nodeTypes *[]string, parts *[]string, depth *int) {
	if node == nil {
		return
	}
	label := labelFn(node)
	if label == "" {
		label = "unknown"
	}
	*nodeTypes = append(*nodeTypes, label)
	if level > *depth {
		*depth = level
	}
	*parts = append(*parts, fmt.Sprintf("(%s", label))

	for _, child := range childrenOf(node) {
		walk(child, labelFn, level+1, nodeTypes, parts, depth)
	}

	*parts = append(*parts, ")")
}

func childrenOf(node any) []any {
	switch n := node.(type) {
	case *sqlparser.Node:
		children := make([]any, 0, len(n.Children))
		for _, child := range n.Children {
			children = append(children, child)
		}
		return children
	case *jsparser.Node:
		children := make([]any, 0, len(n.Children))
		for _, child := range n.Children {
			children = append(children, child)
		}
		return children
	default:
		return nil
	}
}

func sqlNodeTypeLabel(node any) string {
	n, ok := node.(*sqlparser.Node)
	if !ok || n == nil {
		return ""
	}
	switch n.Type {
	case sqlparser.NodeStatement:
		return "statement:" + strings.ToLower(n.Value)
	case sqlparser.NodeSelect:
		return "select"
	case sqlparser.NodeUnion:
		return "union"
	case sqlparser.NodeIdentifier:
		return "identifier"
	case sqlparser.NodeLiteral:
		switch n.LiteralType {
		case sqlparser.LiteralNumber:
			return "literal:number"
		default:
			return "literal:string"
		}
	case sqlparser.NodeFunction:
		return "function:" + strings.ToLower(n.Value)
	case sqlparser.NodeOperator:
		return "operator:" + strings.ToLower(n.Value)
	case sqlparser.NodeComment:
		return "comment"
	case sqlparser.NodeWildcard:
		return "wildcard"
	case sqlparser.NodeList:
		return "list:" + strings.ToLower(n.Value)
	case sqlparser.NodeClause:
		return "clause:" + strings.ToLower(n.Value)
	default:
		return string(n.Type)
	}
}

func jsNodeTypeLabel(node any) string {
	n, ok := node.(*jsparser.Node)
	if !ok || n == nil {
		return ""
	}
	switch n.Type {
	case jsparser.NodeProgram:
		return "program"
	case jsparser.NodeIdentifier:
		return "identifier"
	case jsparser.NodeLiteral:
		switch n.LiteralType {
		case jsparser.LiteralNumber:
			return "literal:number"
		case jsparser.LiteralBoolean:
			return "literal:boolean"
		case jsparser.LiteralNull:
			return "literal:null"
		default:
			return "literal:string"
		}
	case jsparser.NodeCall:
		return "call:" + strings.ToLower(n.Value)
	case jsparser.NodeMember:
		return "member:" + strings.ToLower(n.Value)
	case jsparser.NodeIndex:
		return "index:" + strings.ToLower(n.Value)
	case jsparser.NodeAssignment:
		return "assign:" + strings.ToLower(n.Value)
	case jsparser.NodeBinary:
		return "binary:" + strings.ToLower(n.Value)
	case jsparser.NodeUnary:
		return "unary:" + strings.ToLower(n.Value)
	case jsparser.NodeArray:
		return "array"
	case jsparser.NodeObject:
		return "object"
	case jsparser.NodeProperty:
		return "property:" + strings.ToLower(n.Value)
	case jsparser.NodeComment:
		return "comment"
	default:
		return string(n.Type)
	}
}
