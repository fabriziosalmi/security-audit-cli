package scanner

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
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
	".git":          true,
	"node_modules":  true,
	"vendor":        true,
	".venv":         true,
	"venv":          true,
	"env":           true,
	"__pycache__":   true,
	".pytest_cache": true,
	".mypy_cache":   true,
	".ruff_cache":   true,
	".tox":          true,
	".cache":        true,
	"dist":          true,
	"build":         true,
	"target":        true,
	".next":         true,
	".nuxt":         true,
	".svelte-kit":   true,
	".astro":        true,
	".vitepress":    true,
	".docusaurus":   true,
	"_site":         true,
	"coverage":      true,
	"htmlcov":       true,
	".terraform":    true,
	".gradle":       true,
	"Pods":          true,
	"DerivedData":   true,
	".claude":       true,
	".cursor":       true,
	".gemini":       true,
	".codex":        true,
	".agent":        true,
	".agents":       true,
	".worktrees":    true,
	"worktrees":     true,
}

var nonTargetDirs = map[string]bool{
	"test":       true,
	"tests":      true,
	"testing":    true,
	"testdata":   true,
	"e2e":        true,
	"fixtures":   true,
	"mocks":      true,
	"mock":       true,
	"bench":      true,
	"benches":    true,
	"benchmark":  true,
	"benchmarks": true,
	"doc":        true,
	"docs":       true,
	"example":    true,
	"examples":   true,
	"demo":       true,
	"demos":      true,
	"spikes":     true,
	"assets":     true,
	"static":     true,
	"public":     true,
	"fonts":      true,
	"img":        true,
	"images":     true,
	"css":        true,
	"styles":     true,
	"templates":  true,
	"licenses":   true,
	"reports":    true,
	"logs":       true,
	"output":     true,
	"processed":  true,
	"cache":      true,
	"contrib":    true,
	"archived":   true,
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
	".swift":   "swift",
	".php":     "php",
	".rb":      "ruby",
	".sh":      "shell",
	".bash":    "shell",
	".zsh":     "shell",
	".astro":   "frontend",
	".vue":     "frontend",
	".svelte":  "frontend",
	".gd":      "gdscript",
	".cs":      "csharp",
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
	"composer.json":      true,
	"Gemfile":            true,
	"Package.swift":      true,
	"Chart.yaml":         true,
	"wrangler.toml":      true,
	"wrangler.jsonc":     true,
	"Dockerfile":         true,
	"docker-compose.yml": true,
}

var entrypointBaseTokens = []string{
	"router", "routes", "handler", "handlers", "controller", "controllers",
	"server", "serve", "api", "endpoints", "cli", "commands",
	"mcp", "entrypoint", "daemon", "worker", "proxy", "waf",
}
var entrypointTerminalTokens = map[string]bool{
	"main":   true,
	"app":    true,
	"plugin": true,
	"run":    true,
}
var authBoundaryTokens = []string{"auth", "authentication", "jwt", "oauth", "oidc", "saml", "session", "middleware", "rbac", "acl", "bearer", "apikey", "serve_token", "auth_token"}

var docExtensions = map[string]bool{
	".md":   true,
	".mdx":  true,
	".txt":  true,
	".rst":  true,
	".adoc": true,
}

type companionRule struct {
	File       string
	Reason     string
	AllowInfra bool
	Match      func(rel, lowerRel, name, ext string) bool
}

var companionRules = []companionRule{
	{
		File:   "MEMORY-SAFETY-AND-BINARY.md",
		Reason: "Native/C/C++/Rust or low-level binary/parser paths detected",
		Match: func(rel, _, _, ext string) bool {
			lang := extLanguageMap[ext]
			return lang == "c_cpp" || lang == "rust" || (lang != "" && hasPathToken(rel, "ffi", "unsafe", "fuzz"))
		},
	},
	{
		File:   "AI-AND-LLM.md",
		Reason: "LLM, prompt, agent, or MCP server/client paths detected",
		Match: func(rel, lowerRel, _, ext string) bool {
			if extLanguageMap[ext] == "" {
				return false
			}
			if hasPathToken(rel, "mcp", "prompt", "prompts", "llm", "agents", "openai", "rag") {
				return true
			}
			if hasPathToken(rel, "agent") && !strings.Contains(lowerRel, "launchagent") && !strings.Contains(lowerRel, "useragent") && !strings.Contains(lowerRel, "user_agent") {
				return true
			}
			return false
		},
	},
	{
		File:   "WEB-PROTOCOL-AND-AUTH.md",
		Reason: "HTTP, session, authentication, or authorization boundary files detected",
		Match: func(rel, _, name, ext string) bool {
			return extLanguageMap[ext] != "" &&
				(hasPathToken(rel, authBoundaryTokens...) ||
					hasPathToken(rel, "handler", "request", "response", "proxy", "waf", "clientip", "cors", "csrf", "mtls", "endpoint", "endpoints", "admin") ||
					hasPathToken(name, "serve", "http", "rest"))
		},
	},
	{
		File:   "CLIENT-SIDE.md",
		Reason: "Browser/UI/DOM or frontend component files detected",
		Match: func(rel, _, _, ext string) bool {
			return ext == ".tsx" || ext == ".jsx" || ext == ".vue" || ext == ".svelte" || ext == ".astro" ||
				(extLanguageMap[ext] != "" && hasPathToken(rel, "webview", "dom", "frontend", "renderer"))
		},
	},
	{
		File:       "SUPPLY-CHAIN-AND-RELEASE.md",
		Reason:     "CI/CD workflow or release automation files detected",
		AllowInfra: true,
		Match: func(_, lowerRel, name, _ string) bool {
			return strings.Contains(lowerRel, ".github/workflows/") ||
				strings.Contains(lowerRel, ".gitlab-ci") ||
				name == "goreleaser.yml" || name == ".goreleaser.yaml"
		},
	},
	{
		File:       "CLOUD-AND-DEPLOYMENT.md",
		Reason:     "Container, IaC, Kubernetes, or edge deployment manifests detected",
		AllowInfra: true,
		Match: func(rel, lowerRel, name, ext string) bool {
			if strings.Contains(lowerRel, ".github/workflows/") || strings.Contains(lowerRel, ".gitlab-ci") || strings.HasSuffix(lowerRel, ".lock.hcl") {
				return false
			}
			return extLanguageMap[ext] == "terraform" || name == "Dockerfile" ||
				name == "Chart.yaml" || name == "wrangler.toml" || name == "wrangler.jsonc" ||
				((ext == ".yaml" || ext == ".yml" || extLanguageMap[ext] != "") && hasPathToken(rel, "k8s", "helm", "wrangler"))
		},
	},
	{
		File:   "PROTOCOLS-RPC-AND-MESSAGING.md",
		Reason: "RPC, IDL, webhook, or message queue paths detected",
		Match: func(rel, _, _, ext string) bool {
			return extLanguageMap[ext] == "idl" ||
				(extLanguageMap[ext] != "" && hasPathToken(rel, "grpc", "rpc", "webhook", "webhooks", "queue", "broker"))
		},
	},
	{
		File:   "DATA-ISOLATION-AND-LIFECYCLE.md",
		Reason: "Storage, tenant, migration, or export/backup paths detected",
		Match: func(rel, _, _, ext string) bool {
			lang := extLanguageMap[ext]
			if lang == "" {
				return false
			}
			if hasPathToken(rel, "tenant", "tenants", "export", "backup", "migration", "migrations", "db", "database", "sqlite", "postgres", "redis") {
				return true
			}
			if lang != "typescript" && lang != "javascript" && lang != "frontend" {
				return hasPathToken(rel, "store")
			}
			return false
		},
	},
	{
		File:   "DESKTOP-MOBILE-AND-LOCAL-IPC.md",
		Reason: "Local IPC, daemon, or socket paths detected",
		Match: func(rel, _, _, ext string) bool {
			return extLanguageMap[ext] != "" && hasPathToken(rel, "ipc", "socket", "daemon", "electron", "tauri", "xpc", "menubar")
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
			if shouldIgnoreDir(name) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(targetDir, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		lowerRel := strings.ToLower(rel)
		lowerName := strings.ToLower(name)
		if strings.HasSuffix(lowerName, ".lock.hcl") {
			return nil
		}
		brief.TotalFiles++

		parts := strings.Split(rel, "/")
		if len(parts) > 1 {
			top := parts[0]
			if (!strings.HasPrefix(top, ".") || top == ".github" || top == ".gitlab") && !isNonTargetDir(top) {
				subsystems[top] = true
			}
		} else if extLanguageMap[strings.ToLower(filepath.Ext(name))] != "" {
			subsystems["."] = true
		}

		ext := strings.ToLower(filepath.Ext(name))
		isCodeFile := extLanguageMap[ext] != ""
		inNonTarget := isTestOrNonTargetPath(parts, name)
		if lang, ok := extLanguageMap[ext]; ok && !inNonTarget {
			brief.Languages[lang]++
		}
		if manifestFilenames[name] {
			brief.Manifests = appendCap(brief.Manifests, rel, 25)
		}

		if docExtensions[ext] {
			return nil
		}

		if isCodeFile && !inNonTarget {
			if isEntrypointCandidate(rel, name, ext) {
				brief.EntrypointCandidates = appendCap(brief.EntrypointCandidates, rel, 20)
			}
			if hasPathToken(rel, authBoundaryTokens...) {
				brief.AuthBoundaryCandidates = appendCap(brief.AuthBoundaryCandidates, rel, 20)
			}
		}

		for i, rule := range companionRules {
			if inNonTarget && (!rule.AllowInfra || isTestFileName(name)) {
				continue
			}
			if rule.Match(rel, lowerRel, name, ext) {
				evidenceByCompanion[i] = appendCap(evidenceByCompanion[i], rel, 5)
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

func shouldIgnoreDir(name string) bool {
	if ignoredDirs[name] {
		return true
	}
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "dist-") ||
		strings.HasPrefix(lower, "build-") ||
		strings.HasSuffix(lower, ".xcodeproj") ||
		strings.HasSuffix(lower, ".xcworkspace")
}

func isNonTargetDir(name string) bool {
	lower := strings.ToLower(name)
	return nonTargetDirs[lower] ||
		strings.HasSuffix(lower, "tests") ||
		strings.HasPrefix(lower, "test-") ||
		strings.HasPrefix(lower, "tests-")
}

func isTestFileName(name string) bool {
	lowerName := strings.ToLower(name)
	if strings.HasSuffix(lowerName, "_test.go") ||
		strings.HasSuffix(lowerName, "_test.py") ||
		strings.HasPrefix(lowerName, "test_") ||
		strings.HasSuffix(lowerName, "_test.rs") ||
		strings.Contains(lowerName, ".test.") ||
		strings.Contains(lowerName, ".spec.") ||
		strings.Contains(lowerName, ".e2e.") ||
		lowerName == "conftest.py" {
		return true
	}
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	return hasTokenInSegment(stem, "test", "tests", "spec", "specs", "mock", "mocks")
}

func isTestOrNonTargetPath(parts []string, name string) bool {
	if isTestFileName(name) {
		return true
	}
	for i := 0; i < len(parts)-1; i++ {
		if isNonTargetDir(parts[i]) {
			return true
		}
	}
	return false
}

func isEntrypointCandidate(rel, name, ext string) bool {
	if extLanguageMap[ext] == "terraform" {
		return false
	}
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	if strings.EqualFold(stem, "index") {
		return true
	}
	tokens := splitIdentifierTokens(stem)
	if len(tokens) > 0 && entrypointTerminalTokens[tokens[len(tokens)-1]] {
		return true
	}
	return hasTokenInSegment(stem, entrypointBaseTokens...)
}

func hasPathToken(rel string, targets ...string) bool {
	for _, seg := range strings.Split(rel, "/") {
		stem := strings.TrimSuffix(seg, filepath.Ext(seg))
		if hasTokenInSegment(stem, targets...) {
			return true
		}
	}
	return false
}

func hasTokenInSegment(segment string, targets ...string) bool {
	lowerSeg := strings.ToLower(segment)
	for _, target := range targets {
		if lowerSeg == target {
			return true
		}
	}
	tokens := splitIdentifierTokens(segment)
	for _, tok := range tokens {
		for _, target := range targets {
			if tok == target {
				return true
			}
		}
	}
	return false
}

func splitIdentifierTokens(segment string) []string {
	parts := strings.FieldsFunc(segment, func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})
	var tokens []string
	for _, p := range parts {
		runes := []rune(p)
		if len(runes) == 0 {
			continue
		}
		start := 0
		for i := 1; i < len(runes); i++ {
			prev := runes[i-1]
			curr := runes[i]
			split := (unicode.IsLower(prev) || unicode.IsDigit(prev)) && unicode.IsUpper(curr)
			if !split && i+1 < len(runes) && unicode.IsUpper(prev) && unicode.IsUpper(curr) && unicode.IsLower(runes[i+1]) {
				split = true
			}
			if split {
				tokens = append(tokens, strings.ToLower(string(runes[start:i])))
				start = i
			}
		}
		tokens = append(tokens, strings.ToLower(string(runes[start:])))
	}
	return tokens
}

func appendCap(slice []string, val string, max int) []string {
	if len(slice) >= max {
		return slice
	}
	return append(slice, val)
}
