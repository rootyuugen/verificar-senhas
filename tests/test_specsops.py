import hashlib
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from specsops import breach, cli
from specsops.policy import Policy, evaluate, longest_repeat, longest_sequence

STRONG = "Tr0v@dor-Cavalo#Bateria9"


def failed(result):
    return {c.name for c in result.checks if not c.passed}


class PolicyTests(unittest.TestCase):
    def test_strong_password_passes(self):
        r = evaluate(STRONG)
        self.assertTrue(r.passed, failed(r))

    def test_short_and_simple_fails(self):
        self.assertTrue({"comprimento", "maiúscula", "símbolo"} <= failed(evaluate("abc12")))

    def test_common_and_leet_variants(self):
        self.assertIn("dicionário", failed(evaluate("P@ssw0rd")))
        self.assertIn("dicionário", failed(evaluate("Flamengo!2024xyz")))

    def test_repeat_and_sequence(self):
        self.assertEqual(longest_repeat("aaab"), 3)
        self.assertEqual(longest_sequence("xabcdz"), 4)
        self.assertEqual(longest_sequence("Zqwerty"), 6)
        self.assertEqual(longest_sequence("9876"), 4)
        self.assertIn("sequência", failed(evaluate("Kx!9abcdeZq#2mW")))

    def test_forbidden_words(self):
        r = evaluate("Tales#Rio-2026!xK", Policy(forbidden_words=("tales",)))
        self.assertIn("palavras proibidas", failed(r))


class BreachTests(unittest.TestCase):
    def test_ntlm_known_vector(self):
        self.assertEqual(breach.ntlm("password"), "8846f7eaee8fb117ad06bdd830b7586c")
        self.assertEqual(breach.ntlm(""), "31d6cfe0d16ae931b73c59d7e0c089c0")

    def test_hibp_k_anonymity(self):
        digest = hashlib.sha1(b"password").hexdigest().upper()
        seen = []

        def fake_fetch(url, timeout):
            seen.append(url)
            return f"0000000000000000000000000000000000A:0\r\n{digest[5:]}:9545824\r\n"

        hit = breach.check_hibp("password", fetch=fake_fetch)
        self.assertEqual(hit.count, 9545824)
        self.assertTrue(seen[0].endswith("/range/" + digest[:5]))
        self.assertNotIn(digest[5:], seen[0])

    def test_hibp_ignores_padding_and_misses(self):
        digest = hashlib.sha1(STRONG.encode()).hexdigest().upper()
        self.assertIsNone(breach.check_hibp(STRONG, fetch=lambda u, t: f"{digest[5:]}:0"))
        self.assertIsNone(breach.check_hibp(STRONG, fetch=lambda u, t: "ABC:3"))

    def test_local_hash_lines_any_algorithm(self):
        lines = ["# comentário", hashlib.sha256(b"segredo").hexdigest().upper() + ":42"]
        hit = breach.check_hash_lines("segredo", lines, "dump.txt")
        self.assertEqual((hit.algorithm, hit.count), ("sha256", 42))
        hit = breach.check_hash_lines("password", [breach.ntlm("password")], "ntds")
        self.assertEqual(hit.algorithm, "ntlm")
        self.assertIsNone(breach.check_hash_lines("outra", lines, "dump.txt"))


class CliTests(unittest.TestCase):
    def run_cli(self, password, *args):
        out = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(password + "\n")), redirect_stdout(out):
            code = cli.main(["--stdin", "--json", *args])
        return code, json.loads(out.getvalue())

    def test_offline_strong(self):
        code, data = self.run_cli(STRONG, "--offline")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertTrue(data["aprovada"])

    def test_breached_via_hibp(self):
        hit = breach.BreachHit("haveibeenpwned", "sha1", 7)
        with mock.patch.object(cli, "check_hibp", return_value=hit):
            code, data = self.run_cli(STRONG)
        self.assertEqual(code, cli.EXIT_BREACHED)
        self.assertEqual(data["vazamentos"][0]["count"], 7)

    def test_network_failure_is_warning(self):
        with mock.patch.object(cli, "check_hibp", side_effect=OSError("sem rede")):
            code, data = self.run_cli(STRONG)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertTrue(data["avisos"])


if __name__ == "__main__":
    unittest.main()
