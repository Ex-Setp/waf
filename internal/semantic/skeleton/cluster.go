package skeleton

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

const defaultClusterDistance = 0.35

// ClusterByTreeEditDistance groups similar AST skeletons and returns one
// deterministic common fingerprint for every non-singleton cluster.
func ClusterByTreeEditDistance(payloads []*ASTSkeleton) []*ASTSkeleton {
	return ClusterByTreeEditDistanceThreshold(payloads, defaultClusterDistance)
}

// ClusterByTreeEditDistanceThreshold is the testable implementation behind
// ClusterByTreeEditDistance. maxNormalizedDistance is clamped to [0, 1].
func ClusterByTreeEditDistanceThreshold(payloads []*ASTSkeleton, maxNormalizedDistance float64) []*ASTSkeleton {
	if maxNormalizedDistance < 0 {
		maxNormalizedDistance = 0
	}
	if maxNormalizedDistance > 1 {
		maxNormalizedDistance = 1
	}

	items := compactSkeletons(payloads)
	if len(items) == 0 {
		return nil
	}

	visited := make([]bool, len(items))
	var clusters [][]*ASTSkeleton
	for i := range items {
		if visited[i] {
			continue
		}
		visited[i] = true
		cluster := []*ASTSkeleton{items[i]}
		for j := i + 1; j < len(items); j++ {
			if visited[j] || items[i].Language != items[j].Language {
				continue
			}
			if similarSkeletons(items[i], items[j], maxNormalizedDistance) {
				visited[j] = true
				cluster = append(cluster, items[j])
			}
		}
		if len(cluster) > 1 {
			clusters = append(clusters, cluster)
		}
	}

	fingerprints := make([]*ASTSkeleton, 0, len(clusters))
	for _, cluster := range clusters {
		fingerprints = append(fingerprints, commonFingerprint(cluster))
	}
	sort.Slice(fingerprints, func(i, j int) bool {
		if fingerprints[i].Language != fingerprints[j].Language {
			return fingerprints[i].Language < fingerprints[j].Language
		}
		return fingerprints[i].Hash < fingerprints[j].Hash
	})
	return fingerprints
}

func compactSkeletons(payloads []*ASTSkeleton) []*ASTSkeleton {
	seen := make(map[string]*ASTSkeleton)
	items := make([]*ASTSkeleton, 0, len(payloads))
	for index, payload := range payloads {
		if payload == nil || payload.Structure == "" || payload.Hash == "" {
			continue
		}
		key := payload.Language + "\x00" + payload.Hash
		if len(attackAnchors(payload)) > 0 {
			items = append(items, payload)
			seen[key+"\x00attack\x00"+string(rune(index))] = payload
			continue
		}
		if _, ok := seen[key]; !ok {
			seen[key] = payload
			items = append(items, payload)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Language != items[j].Language {
			return items[i].Language < items[j].Language
		}
		if items[i].Hash != items[j].Hash {
			return items[i].Hash < items[j].Hash
		}
		return items[i].Structure < items[j].Structure
	})
	return items
}

func normalizedTreeEditDistance(left, right *ASTSkeleton) float64 {
	leftTokens := structureTokens(left)
	rightTokens := structureTokens(right)
	maxLen := len(leftTokens)
	if len(rightTokens) > maxLen {
		maxLen = len(rightTokens)
	}
	if maxLen == 0 {
		return 0
	}
	return float64(editDistance(leftTokens, rightTokens)) / float64(maxLen)
}

func similarSkeletons(left, right *ASTSkeleton, maxNormalizedDistance float64) bool {
	if shareAttackAnchor(left, right) {
		return true
	}
	return normalizedTreeEditDistance(left, right) <= maxNormalizedDistance
}

func shareAttackAnchor(left, right *ASTSkeleton) bool {
	leftAnchors := attackAnchors(left)
	if len(leftAnchors) == 0 {
		return false
	}
	for anchor := range attackAnchors(right) {
		if _, ok := leftAnchors[anchor]; ok {
			return true
		}
	}
	return false
}

func attackAnchors(skeleton *ASTSkeleton) map[string]struct{} {
	anchors := make(map[string]struct{})
	for _, nodeType := range skeleton.NodeTypes {
		lower := strings.ToLower(nodeType)
		switch {
		case lower == "union", strings.HasPrefix(lower, "function:load_file"), strings.HasPrefix(lower, "function:mysql_query"), strings.HasPrefix(lower, "function:exec"):
			anchors[lower] = struct{}{}
		case strings.HasPrefix(lower, "call:eval"), strings.HasPrefix(lower, "call:document.write"), strings.HasPrefix(lower, "member:innerhtml"):
			anchors[lower] = struct{}{}
		}
	}
	return anchors
}

func structureTokens(skeleton *ASTSkeleton) []string {
	if skeleton == nil {
		return nil
	}
	return strings.Fields(strings.NewReplacer("(", " (", ")", " )").Replace(skeleton.Structure))
}

func editDistance(left, right []string) int {
	if len(left) == 0 {
		return len(right)
	}
	if len(right) == 0 {
		return len(left)
	}
	previous := make([]int, len(right)+1)
	current := make([]int, len(right)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(left); i++ {
		current[0] = i
		for j := 1; j <= len(right); j++ {
			cost := 1
			if left[i-1] == right[j-1] {
				cost = 0
			}
			current[j] = minInt(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous, current = current, previous
	}
	return previous[len(right)]
}

func commonFingerprint(cluster []*ASTSkeleton) *ASTSkeleton {
	if len(cluster) == 0 {
		return nil
	}
	sort.Slice(cluster, func(i, j int) bool {
		return cluster[i].Hash < cluster[j].Hash
	})
	language := cluster[0].Language
	commonTypes := commonNodeTypes(cluster)
	commonStructure := commonStructureTokens(cluster)
	if commonStructure == "" {
		commonStructure = strings.Join(commonTypes, " ")
	}
	hash := hashCluster(language, commonStructure)
	return &ASTSkeleton{
		Language:  language,
		NodeTypes: commonTypes,
		Structure: commonStructure,
		Hash:      hash,
		Depth:     minDepth(cluster),
	}
}

func commonNodeTypes(cluster []*ASTSkeleton) []string {
	counts := make(map[string]int)
	for _, item := range cluster {
		seen := make(map[string]struct{})
		for _, nodeType := range item.NodeTypes {
			seen[nodeType] = struct{}{}
		}
		for nodeType := range seen {
			counts[nodeType]++
		}
	}
	var common []string
	for nodeType, count := range counts {
		if count == len(cluster) {
			common = append(common, nodeType)
		}
	}
	sort.Strings(common)
	return common
}

func commonStructureTokens(cluster []*ASTSkeleton) string {
	if len(cluster) == 0 {
		return ""
	}
	common := structureTokens(cluster[0])
	for _, item := range cluster[1:] {
		common = longestCommonSubsequence(common, structureTokens(item))
		if len(common) == 0 {
			break
		}
	}
	return strings.Join(common, " ")
}

func longestCommonSubsequence(left, right []string) []string {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}
	dp := make([][]int, len(left)+1)
	for i := range dp {
		dp[i] = make([]int, len(right)+1)
	}
	for i := len(left) - 1; i >= 0; i-- {
		for j := len(right) - 1; j >= 0; j-- {
			if left[i] == right[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	result := make([]string, 0, dp[0][0])
	for i, j := 0, 0; i < len(left) && j < len(right); {
		if left[i] == right[j] {
			result = append(result, left[i])
			i++
			j++
		} else if dp[i+1][j] >= dp[i][j+1] {
			i++
		} else {
			j++
		}
	}
	return result
}

func minDepth(cluster []*ASTSkeleton) int {
	if len(cluster) == 0 {
		return 0
	}
	depth := cluster[0].Depth
	for _, item := range cluster[1:] {
		if item.Depth < depth {
			depth = item.Depth
		}
	}
	return depth
}

func hashCluster(language, structure string) string {
	sum := sha256.Sum256([]byte(language + "\x00cluster\x00" + structure))
	return hex.EncodeToString(sum[:])
}

func minInt(values ...int) int {
	min := values[0]
	for _, value := range values[1:] {
		if value < min {
			min = value
		}
	}
	return min
}
