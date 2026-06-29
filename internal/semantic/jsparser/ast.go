package jsparser

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

type NodeType string

const (
	NodeProgram    NodeType = "program"
	NodeIdentifier NodeType = "identifier"
	NodeLiteral    NodeType = "literal"
	NodeCall       NodeType = "call"
	NodeMember     NodeType = "member"
	NodeIndex      NodeType = "index"
	NodeAssignment NodeType = "assignment"
	NodeBinary     NodeType = "binary"
	NodeUnary      NodeType = "unary"
	NodeArray      NodeType = "array"
	NodeObject     NodeType = "object"
	NodeProperty   NodeType = "property"
	NodeComment    NodeType = "comment"
)

type LiteralType string

const (
	LiteralString  LiteralType = "string"
	LiteralNumber  LiteralType = "number"
	LiteralBoolean LiteralType = "boolean"
	LiteralNull    LiteralType = "null"
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
		switch node.LiteralType {
		case LiteralNumber:
			*parts = append(*parts, "number")
		case LiteralBoolean:
			*parts = append(*parts, "boolean")
		case LiteralNull:
			*parts = append(*parts, "null")
		default:
			*parts = append(*parts, "string")
		}
	case NodeCall:
		*parts = append(*parts, "call:"+strings.ToLower(node.Value))
	case NodeMember:
		*parts = append(*parts, "member:"+strings.ToLower(node.Value))
	case NodeIndex:
		if node.Value != "" && node.Value != "[]" {
			*parts = append(*parts, "index:"+strings.ToLower(node.Value))
		} else {
			*parts = append(*parts, "index")
		}
	case NodeAssignment:
		*parts = append(*parts, "assign:"+strings.ToLower(node.Value))
	case NodeBinary:
		*parts = append(*parts, "op:"+strings.ToLower(node.Value))
	case NodeUnary:
		*parts = append(*parts, "unary:"+strings.ToLower(node.Value))
	case NodeProperty:
		*parts = append(*parts, "prop:"+strings.ToLower(node.Value))
	default:
		*parts = append(*parts, strings.ToLower(string(node.Type)))
	}
	for _, child := range node.Children {
		appendSkeleton(child, parts)
	}
}

func calleeName(node *Node) string {
	if node == nil {
		return "expr"
	}
	switch node.Type {
	case NodeIdentifier:
		return node.Value
	case NodeMember:
		return node.Value
	case NodeIndex:
		if node.Value != "" && node.Value != "[]" {
			return "index:" + node.Value
		}
		return "index"
	default:
		return string(node.Type)
	}
}
