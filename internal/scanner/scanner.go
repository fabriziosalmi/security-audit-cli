package scanner

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// CompanionRecommendation links a companion file to source-grounded files that triggered it.
type CompanionRecommendation struct {
	File     string   `json:"file"`
	Reason   string   `json:"reason"`
	Evidence []string `json:"evidence_paths"`
}

// RepoBrief is the deterministic static reconnaissance output returned by Init.
type RepoBrief struct {
	TotalFiles              int                       `json:"total_files"`
	Languages               map[string]int            `json:"languages"`
	Manifests               []string                  `json:"manifests"`
	EntrypointCandidates    []string                  `json:"entrypoint_candidates"`
	AuthBoundaryCandidates  []string                  `json:"auth_boundary_candidates"`
	RecommendedCompanions   []CompanionRecommendation `json:"recommended_companions"`
	SuggestedSeedSubsystems []string                  `json:"suggested_seed_subsystems"`
}

var ignoredDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	".venv":        true,
	"dist":         true,
	"build":        true,
	"target":       true,
}

var extLanguageMap = map[string]string{
	".go":      "go",
	".py":      "python",
	".ts":      "typescript",
	".tsx":     "typescript",
	".js":      "javascript",
	".jsx":     "javascript",
	".cjs":     "javascript",
	".mjs":     "javascript",
	".rs":      "rust",
	".c":       "c_cpp",
	".cc":      "c_cpp",
	".cpp":     "c_cpp",
	".h":       "c_cpp",
	".hpp":     "c_cpp",
	".java":    "jvm",
	".kt":      "jvm",
	".proto":   "idl",
	".capnp":   "idl",
	".thrift":  "idl",
	".graphql": "idl",
	".tf":      "terraform",
	".hcl":     "terraform",
}

var manifestFilenames = map[string]bool{
	"go.mod":             true,
	"package.json":       true,
	"pyproject.toml":     true,
	"Cargo.toml":         true,
	"requirements.txt":   true,
	"pom.xml":            true,
	"Dockerfile":         true,
	"docker-compose.yml": true,
}

var entrypointTokens = []string{"router", "handler", "server", "api", "cmd/", "main."}
var authBoundaryTokens = []string{"auth", "jwt", "oauth", "session", "middleware", "rbac", "acl", "policy"}

var docExtensions = map[string]bool{
	".md":   true,
	".txt":  true,
	".rst":  true,
	".adoc": true,
}

type companionRule struct {
	File   string
	Reason string
	Match  func(rel, lowerRel, name, ext string) bool
}

var companionRules = []companionRule{
	{
		File:   "MEMORY-SAFETY-AND-BINARY.md",
		Reason: "Native/C/C++ or low-level binary paths detected",
		Match: func(_, _, _, ext string) bool {
			return extLanguageMap[ext] == "c_cpp"
		},
	},
	{
		File:   "AI-AND-LLM.md",
		Reason: "LLM, prompt, agent, or MCP server/client paths detected",
		Match: func(_, lowerRel, _, _ string) bool {
			return containsAny(lowerRel, "mcp", "prompt", "llm", "agent", "openai", "rag")
		},
	},
	{
		File:   "WEB-PROTOCOL-AND-AUTH.md",
		Reason: "HTTP, session, authentication, or authorization boundary files detected",
		Match: func(_, lowerRel, _, _ string) bool {
			return containsAny(lowerRel, authBoundaryTokens...)
		},
	},
	{
		File:   "CLIENT-SIDE.md",
		Reason: "Browser/UI/DOM or frontend component files detected",
		Match: func(_, lowerRel, _, ext string) bool {
			return ext == ".tsx" || ext == ".jsx" || containsAny(lowerRel, "webview", "service-worker")
		},
	},
	{
		File:   "SUPPLY-CHAIN-AND-RELEASE.md",
		Reason: "CI/CD workflow or release automation files detected",
		Match: func(_, lowerRel, name, _ string) bool {
			return containsAny(lowerRel, ".github/workflows/", ".gitlab-ci") || name == "goreleaser.yml" || name == ".goreleaser.yaml"
		},
	},
	{
		File:   "CLOUD-AND-DEPLOYMENT.md",
		Reason: "Container, IaC, Kubernetes, or edge deployment manifests detected",
		Match: func(_, lowerRel, name, ext string) bool {
			return extLanguageMap[ext] == "terraform" || name == "Dockerfile" || name == "wrangler.toml" || containsAny(lowerRel, "k8s/", "helm/", "wrangler")
		},
	},
	{
		File:   "PROTOCOLS-RPC-AND-MESSAGING.md",
		Reason: "RPC, IDL, webhook, or message queue paths detected",
		Match: func(_, lowerRel, _, ext string) bool {
			return extLanguageMap[ext] == "idl" || containsAny(lowerRel, "grpc", "rpc", "webhook", "queue", "broker")
		},
	},
	{
		File:   "DATA-ISOLATION-AND-LIFECYCLE.md",
		Reason: "Storage, tenant, migration, or export/backup paths detected",
		Match: func(_, lowerRel, _, _ string) bool {
			return containsAny(lowerRel, "tenant", "export", "backup", "migration", "store", "db")
		},
	},
	{
		File:   "DESKTOP-MOBILE-AND-LOCAL-IPC.md",
		Reason: "Local IPC, daemon, or socket paths detected",
		Match: func(_, lowerRel, _, _ string) bool {
			return containsAny(lowerRel, "ipc", "socket", "daemon", "unix")
		},
	},
}

// ScanRepository walks targetDir deterministically and produces a RepoBrief with language counts,
// manifests, entrypoint/auth-boundary candidates, and source-grounded companion recommendations.
func ScanRepository(targetDir string) RepoBrief {
	brief := RepoBrief{
		Languages:               make(map[string]int),
		Manifests:               []string{},
		EntrypointCandidates:    []string{},
		AuthBoundaryCandidates:  []string{},
		RecommendedCompanions:   []CompanionRecommendation{},
		SuggestedSeedSubsystems: []string{},
	}

	subsystems := make(map[string]bool)
	evidenceByCompanion := make([][]string, len(companionRules))

	_ = filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if ignoredDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(targetDir, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		brief.TotalFiles++

		parts := strings.Split(rel, "/")
		if len(parts) > 1 {
			subsystems[parts[0]] = true
		} else {
			subsystems["."] = true
		}

		ext := strings.ToLower(filepath.Ext(name))
		if lang, ok := extLanguageMap[ext]; ok {
			brief.Languages[lang]++
		}
		if manifestFilenames[name] {
			brief.Manifests = appendCap(brief.Manifests, rel, 25)
		}

		lowerRel := strings.ToLower(rel)
		if !docExtensions[ext] {
			if containsAny(lowerRel, entrypointTokens...) {
				brief.EntrypointCandidates = appendCap(brief.EntrypointCandidates, rel, 20)
			}
			if containsAny(lowerRel, authBoundaryTokens...) {
				brief.AuthBoundaryCandidates = appendCap(brief.AuthBoundaryCandidates, rel, 20)
			}

			for i, rule := range companionRules {
				if rule.Match(rel, lowerRel, name, ext) {
					evidenceByCompanion[i] = appendCap(evidenceByCompanion[i], rel, 5)
				}
			}
		}
		return nil
	})

	for sub := range subsystems {
		brief.SuggestedSeedSubsystems = append(brief.SuggestedSeedSubsystems, sub)
	}
	sort.Strings(brief.SuggestedSeedSubsystems)

	for i, rule := range companionRules {
		if len(evidenceByCompanion[i]) > 0 {
			brief.RecommendedCompanions = append(brief.RecommendedCompanions, CompanionRecommendation{
				File:     rule.File,
				Reason:   rule.Reason,
				Evidence: evidenceByCompanion[i],
			})
		}
	}

	return brief
}

func containsAny(s string, tokens ...string) bool {
	for _, tok := range tokens {
		if strings.Contains(s, tok) {
			return true
		}
	}
	return false
}

func appendCap(slice []string, val string, max int) []string {
	if len(slice) >= max {
		return slice
	}
	return append(slice, val)
}
