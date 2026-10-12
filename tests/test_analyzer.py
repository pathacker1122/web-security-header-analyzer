
import unittest

from analyzer import analyze_headers, validate_url


class TestAnalyzeHeaders(unittest.TestCase):
    def test_all_headers_missing(self):
        results = analyze_headers({})

        self.assertEqual(len(results), 5)

        for item in results.values():
            self.assertFalse(item["present"])
            self.assertIsNone(item["value"])

    def test_security_headers_present(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        }

        results = analyze_headers(headers)

        for item in results.values():
            self.assertTrue(item["present"])
            self.assertIsNotNone(item["value"])

    def test_header_names_are_case_insensitive(self):
        results = analyze_headers({
            "CONTENT-SECURITY-POLICY": "default-src 'self'",
        })

        self.assertTrue(results["content-security-policy"]["present"])
        self.assertFalse(results["strict-transport-security"]["present"])

    def test_header_values_are_preserved(self):
        results = analyze_headers({
            "X-Content-Type-Options": "nosniff",
        })

        self.assertEqual(
            results["x-content-type-options"]["value"],
            "nosniff",
        )


class TestValidateUrl(unittest.TestCase):
    def test_valid_https_url(self):
        self.assertTrue(validate_url("https://example.com"))

    def test_rejects_http(self):
        self.assertFalse(validate_url("http://example.com"))

    def test_rejects_missing_hostname(self):
        self.assertFalse(validate_url("https://"))

    def test_rejects_url_with_credentials(self):
        self.assertFalse(
            validate_url("https://user:password@example.com")
        )

    def test_rejects_invalid_port(self):
        self.assertFalse(
            validate_url("https://example.com:invalid")
        )


if __name__ == "__main__":
    unittest.main()
