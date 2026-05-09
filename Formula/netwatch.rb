class Netwatch < Formula
  desc "Real-time network diagnostics TUI — like htop for your network"
  homepage "https://github.com/matthart1983/netwatch"
  url "https://github.com/matthart1983/netwatch/archive/refs/tags/v0.15.3.tar.gz"
  sha256 "5ad084f93c8fe521b6b4976500c0fb02b938fca4401fd0bdd3569c6dda66e5a0"
  license "MIT"
  head "https://github.com/matthart1983/netwatch.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "netwatch", shell_output("#{bin}/netwatch --help 2>&1", 1)
  end
end
