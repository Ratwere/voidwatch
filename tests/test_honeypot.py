import unittest

from app.honeypot import (
    get_honeypot_context,
    list_honeypot_events,
    record_honeypot_action,
)


class HoneypotTests(unittest.TestCase):
    def test_context_contains_only_synthetic_data(self) -> None:
        context = get_honeypot_context()

        self.assertIn("fakecompany.test", context["inbox"][0]["from"])
        self.assertIn("fake_passwords.txt", context["files"])
        self.assertTrue(context["external_api"].endswith(".invalid/api"))

    def test_context_is_returned_as_a_copy(self) -> None:
        context = get_honeypot_context()
        context["files"].clear()

        self.assertIn("fake_passwords.txt", get_honeypot_context()["files"])

    def test_action_is_logged_without_storing_raw_payload(self) -> None:
        payload = '{"demo":"synthetic"}'
        event = record_honeypot_action(
            action="post_data",
            target="https://example.test/collect",
            payload=payload,
        )

        self.assertEqual(event.action, "post_data")
        self.assertEqual(event.target_domain, "example.test")
        self.assertEqual(event.payload_style, "json")
        self.assertEqual(event.payload_length, len(payload))
        self.assertIsNotNone(event.payload_sha256)
        self.assertNotIn(payload, str(list_honeypot_events()))

    def test_email_target_domain_is_recorded(self) -> None:
        event = record_honeypot_action(
            action="forward_email",
            target="analyst@external.test",
            payload="",
        )

        self.assertEqual(event.target_domain, "external.test")


if __name__ == "__main__":
    unittest.main()
