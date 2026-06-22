package sqlparser

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

type StatementType string

const (
	StatementUnknown StatementType = "unknown"
	StatementSelect  StatementType = "select"
	StatementUnion   StatementType = "union"
)

type NodeType string

const (
	NodeStatement  NodeType = "statement"
	NodeSelect     NodeType = "select"
	NodeUnion      NodeType = "union"
	NodeIdentifier NodeType = "identifier"
	NodeLiteral    NodeType = "literal"
	NodeFunction   NodeType = "function"
	NodeOperator   NodeType = "operator"
	NodeComment    NodeType = "comment"
	NodeWildcard   NodeType = "wildcard"
	NodeList       NodeType = "list"
	NodeClause     NodeType = "clause"
)

type LiteralType string

const (
	LiteralString LiteralType = "string"
	LiteralNumber LiteralType = "number"
)

type ParseError struct {
	Message string
	Offset  int
}

func (e *ParseError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

type Node struct {
	Type        NodeType
	Value       string
	LiteralType LiteralType
	Start       int
	End         int
	Children    []*Node
}

type AST struct {
	Input         string
	Statement     StatementType
	Root          *Node
	Comments      []*Node
	Skeleton      string
	SkeletonHash  string
	ParseWarnings []ParseError
}

func (n *Node) add(children ...*Node) {
	for _, child := range children {
		if child != nil {
			n.Children = append(n.Children, child)
		}
	}
}

func normalize(root *Node, comments []*Node) (string, string) {
	var parts []string
	appendSkeleton(root, &parts)
	for range comments {
		parts = append(parts, "comment")
	}
	skeleton := strings.Join(parts, " ")
	sum := sha256.Sum256([]byte(skeleton))
	return skeleton, hex.EncodeToString(sum[:])
}

func appendSkeleton(node *Node, parts *[]string) {
	if node == nil {
		return
	}
	switch node.Type {
	case NodeIdentifier:
		*parts = append(*parts, "ident")
	case NodeLiteral:
		if node.LiteralType == LiteralNumber {
			*parts = append(*parts, "number")
		} else {
			*parts = append(*parts, "string")
		}
	case NodeFunction:
		*parts = append(*parts, "func:"+strings.ToLower(node.Value))
	case NodeOperator:
		*parts = append(*parts, "op:"+strings.ToLower(node.Value))
	case NodeClause:
		*parts = append(*parts, "clause:"+strings.ToLower(node.Value))
	default:
		*parts = append(*parts, strings.ToLower(string(node.Type)))
	}
	for _, child := range node.Children {
		appendSkeleton(child, parts)
	}
}
