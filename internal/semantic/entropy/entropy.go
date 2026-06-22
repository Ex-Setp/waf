package entropy

import (
	"math"
	"strings"
)

const (
	// DefaultThreatThreshold is the T034 pre-judgement threshold from the design doc.
	DefaultThreatThreshold = 0.7
)

// SyntaxEntropy is a normalized syntax-randomness score for WAF pre-judgement.
type SyntaxEntropy struct {
	Value     float64
	Threat    bool
	Threshold float64
	Length    int
}

// Analyze calculates syntax entropy using the default threat threshold.
func Analyze(input string) SyntaxEntropy {
	return AnalyzeWithThreshold(input, DefaultThreatThreshold)
}

// AnalyzeWithThreshold calculates a deterministic 0.0~1.0 score from syntax-oriented features.
func AnalyzeWithThreshold(input string, threshold float64) SyntaxEntropy {
	if threshold <= 0 || threshold > 1 {
		threshold = DefaultThreatThreshold
	}
	if input == "" {
		return SyntaxEntropy{Threshold: threshold}
	}

	tokens := tokenize(input)
	features := scoreFeatures(input, tokens)
	patternScore := attackPatternScore(input)
	value := clamp01(
		features.diversity*0.12 +
			features.operatorDensity*0.13 +
			features.transitionRate*0.12 +
			features.depth*0.10 +
			features.suspiciousDensity*0.20 +
			features.structureEntropy*0.10 +
			patternScore*0.23,
	)
	if patternScore >= 1 && value < 0.75 {
		value = 0.75
	}

	return SyntaxEntropy{
		Value:     round4(value),
		Threat:    value > threshold,
		Threshold: threshold,
		Length:    len(input),
	}
}

type tokenCategory uint8

const (
	categoryLetter tokenCategory = iota
	categoryDigit
	categorySpace
	categoryQuote
	categoryOperator
	categoryBracket
	categoryPunctuation
	categoryOther
)

type token struct {
	category tokenCategory
	value    rune
}

type featureScores struct {
	diversity         float64
	operatorDensity   float64
	transitionRate    float64
	depth             float64
	suspiciousDensity float64
	structureEntropy  float64
}

func scoreFeatures(input string, tokens []token) featureScores {
	if len(tokens) == 0 {
		return featureScores{}
	}

	categoryCounts := make(map[tokenCategory]int)
	for _, token := range tokens {
		categoryCounts[token.category]++
	}

	operatorLike := categoryCounts[categoryOperator] + categoryCounts[categoryQuote] + categoryCounts[categoryBracket] + categoryCounts[categoryPunctuation]
	return featureScores{
		diversity:         float64(len(categoryCounts)) / 8,
		operatorDensity:   clamp01(float64(operatorLike) / float64(len(tokens)) * 2.2),
		transitionRate:    transitionRate(tokens),
		depth:             nestingDepth(tokens),
		suspiciousDensity: suspiciousDensity(tokens),
		structureEntropy:  shannonCategoryEntropy(categoryCounts, len(tokens)),
	}
}

func tokenize(input string) []token {
	tokens := make([]token, 0, len(input))
	for _, value := range input {
		tokens = append(tokens, token{category: classify(value), value: value})
	}
	return tokens
}

func classify(value rune) tokenCategory {
	switch {
	case value >= 'a' && value <= 'z', value >= 'A' && value <= 'Z', value == '_':
		return categoryLetter
	case value >= '0' && value <= '9':
		return categoryDigit
	case value == ' ' || value == '\t' || value == '\n' || value == '\r':
		return categorySpace
	case value == '\'' || value == '"' || value == '`':
		return categoryQuote
	case value == '+' || value == '-' || value == '*' || value == '/' || value == '%' || value == '=' || value == '<' || value == '>' || value == '!' || value == '|' || value == '&' || value == '^' || value == '~':
		return categoryOperator
	case value == '(' || value == ')' || value == '[' || value == ']' || value == '{' || value == '}':
		return categoryBracket
	case value == ',' || value == '.' || value == ';' || value == ':' || value == '?' || value == '@' || value == '#':
		return categoryPunctuation
	default:
		return categoryOther
	}
}

func transitionRate(tokens []token) float64 {
	if len(tokens) < 2 {
		return 0
	}
	transitions := 0
	for index := 1; index < len(tokens); index++ {
		if tokens[index].category != tokens[index-1].category {
			transitions++
		}
	}
	return float64(transitions) / float64(len(tokens)-1)
}

func nestingDepth(tokens []token) float64 {
	current := 0
	maxDepth := 0
	for _, token := range tokens {
		switch token.value {
		case '(', '[', '{':
			current++
			if current > maxDepth {
				maxDepth = current
			}
		case ')', ']', '}':
			if current > 0 {
				current--
			}
		}
	}
	return clamp01(float64(maxDepth) / 5)
}

func suspiciousDensity(tokens []token) float64 {
	if len(tokens) == 0 {
		return 0
	}

	suspicious := 0
	for _, token := range tokens {
		switch token.value {
		case '\'', '"', '`', ';', '|', '&', '<', '>', '*', '=', '/', '\\', '$', '#', '(', ')':
			suspicious++
		}
	}
	return clamp01(float64(suspicious) / float64(len(tokens)) * 2.4)
}

func attackPatternScore(input string) float64 {
	lower := strings.ToLower(input)
	patterns := []string{
		" or ", " union ", "select", "--", "/*", "*/",
		"<script", "</script", "javascript:", "onerror=", "alert(",
		"../", "/etc/passwd", "/bin/", " -c ", "cmd", "powershell", "$(", "|", "&&",
	}

	matches := 0
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			matches++
		}
	}
	return clamp01(float64(matches) / 2)
}

func shannonCategoryEntropy(counts map[tokenCategory]int, total int) float64 {
	if total <= 1 {
		return 0
	}
	entropy := 0.0
	for _, count := range counts {
		probability := float64(count) / float64(total)
		entropy -= probability * math.Log2(probability)
	}
	return clamp01(entropy / math.Log2(8))
}

func clamp01(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func round4(value float64) float64 {
	return math.Round(value*10000) / 10000
}
