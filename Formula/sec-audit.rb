# Homebrew formula for sec-audit.
#
# Install (no separate tap repository needed, Homebrew accepts an explicit git URL):
#
#   brew tap fabriziosalmi/sec-audit https://github.com/fabriziosalmi/security-audit-cli
#   brew install sec-audit
#
# Builds from the tagged source with the Go toolchain Homebrew provides at build time.
class SecAudit < Formula
  desc "Gated multi-agent security audits: CLI and MCP server"
  homepage "https://github.com/fabriziosalmi/security-audit-cli"
  url "https://github.com/fabriziosalmi/security-audit-cli/archive/refs/tags/v0.2.0.tar.gz"
  sha256 "52786c81838ef1bb447495421643c15869572ea5aabf42710970772b99f54853"
  license "MIT"
  head "https://github.com/fabriziosalmi/security-audit-cli.git", branch: "main"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w -X main.Version=#{version}"), "./cmd/sec-audit"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sec-audit version --format text")
    system bin/"sec-audit", "demo", "--dir", testpath/"demo"
    assert_path_exists testpath/"demo/run/REPORT.md"
  end
end
