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
  url "https://github.com/fabriziosalmi/security-audit-cli/archive/refs/tags/v0.2.1.tar.gz"
  sha256 "d4e9b1aced6caea9fe987fb3c8ed98d05f21a982f290f497245d95fa4ef07c03"
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
