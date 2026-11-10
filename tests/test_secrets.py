import unittest

from leash.secrets import find_secrets, mask, redact


class MaskTests(unittest.TestCase):
    def test_mask_keeps_only_a_hint(self):
        self.assertEqual(mask("hunter2secret"), "hunt… (13 characters)")
        self.assertEqual(mask("abc"), "***")
        self.assertNotIn("hunter2secret", mask("hunter2secret"))


class FindSecretsTests(unittest.TestCase):
    def kinds(self, text):
        return [s.kind for s in find_secrets(text)]

    def test_env_password_in_command(self):
        found = find_secrets("PGPASSWORD=hunter2secret psql -h db -U app")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].kind, "a password or key set as an environment variable")
        self.assertEqual(found[0].masked, "hunt… (13 characters)")

    def test_env_variable_reference_is_not_a_secret(self):
        self.assertEqual(find_secrets("PGPASSWORD=$PGPASSWORD psql -h db"), [])
        self.assertEqual(find_secrets('PGPASSWORD="${DB_PASS}" psql'), [])

    def test_placeholders_are_not_secrets(self):
        self.assertEqual(find_secrets("API_TOKEN=<your-token> run"), [])
        self.assertEqual(find_secrets("API_TOKEN=xxxxxx run"), [])
        self.assertEqual(find_secrets("--password changeme"), [])

    def test_sshpass(self):
        self.assertEqual(self.kinds("sshpass -p S3cretPass ssh root@host"), ["a password passed to sshpass"])

    def test_mysql_glued_p(self):
        self.assertEqual(self.kinds("mysql -u root -pRootPw123 app"), ["a password glued to -p for mysql"])
        self.assertEqual(find_secrets("mysql -u root -p app"), [])          # prompts for it: fine
        self.assertEqual(find_secrets("mysql -u root -p app -e 'select 1'"), [])

    def test_option_password(self):
        self.assertEqual(self.kinds("tool --password=Sup3rSecret"), ["a password or token passed as a command option"])
        self.assertEqual(self.kinds("tool --token Sup3rSecret"), ["a password or token passed as a command option"])
        self.assertEqual(find_secrets("tool --token $TOKEN"), [])

    def test_url_password(self):
        self.assertEqual(self.kinds("psql postgres://app:Sup3r@db.example.com/app"), ["a password inside a URL"])
        self.assertEqual(find_secrets("curl https://example.com/path"), [])

    def test_connection_string(self):
        self.assertEqual(self.kinds("psql 'host=db user=app password=Sup3r'"), ["a password inside a connection string"])

    def test_bearer_header(self):
        self.assertEqual(self.kinds('curl -H "Authorization: Bearer abcdefgh12345678" https://x'),
                         ["a bearer or basic Authorization header"])

    def test_curl_user_pass(self):
        self.assertEqual(self.kinds("curl -u admin:Sup3rSecret https://x"), ["a user:password pair passed to curl"])

    def test_known_token_shapes(self):
        self.assertEqual(self.kinds("x ghp_" + "a" * 36), ["a GitHub token"])
        self.assertEqual(self.kinds("sk-ant-" + "a" * 30), ["an Anthropic API key"])
        self.assertEqual(self.kinds("sk-" + "a" * 30), ["an OpenAI-style API key"])
        self.assertEqual(self.kinds("AKIA" + "A" * 16), ["an AWS access key id"])
        self.assertEqual(self.kinds("xoxb-" + "1" * 12), ["a Slack token"])
        self.assertEqual(self.kinds("-----BEGIN RSA PRIVATE KEY-----"), ["a private key block"])
        self.assertEqual(self.kinds("eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12), ["a signed web token (JWT)"])

    def test_no_overlap_token_inside_header(self):
        text = 'curl -H "Authorization: Bearer ghp_' + "a" * 36 + '" https://api.github.com'
        self.assertEqual(self.kinds(text), ["a bearer or basic Authorization header"])

    def test_ordinary_commands_are_clean(self):
        for cmd in ("git push origin main", "npm test", "ls -la", "pytest -x", "cat README.md",
                    "git commit -m 'add token refresh'", "grep -r password src/", "echo $SECRET_KEY"):
            self.assertEqual(find_secrets(cmd), [], cmd)

    def test_redact_hides_value(self):
        out = redact("PGPASSWORD=hunter2secret psql")
        self.assertNotIn("hunter2secret", out)
        self.assertIn("psql", out)
        self.assertIn("hunt…", out)


if __name__ == "__main__":
    unittest.main()
