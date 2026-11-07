import io
import json
import unittest
from unittest.mock import patch
from urllib.error import URLError
from urllib.request import Request

from app.judge import (
    DEFAULT_OLLAMA_MODEL,
    JudgeError,
    judge_untrusted_content,
    should_use_judge,
)


class JudgeTests(unittest.TestCase):
    def test_judge_only_runs_for_ambiguous_scores(self) -> None:
        self.assertFalse(should_use_judge(19))
        self.assertTrue(should_use_judge(20))
        self.assertTrue(should_use_judge(80))
        self.assertFalse(should_use_judge(81))

    @patch("app.judge.urlopen")
    def test_sends_untrusted_text_as_json_and_parses_result(self, mock_urlopen) -> None:
        mock_urlopen.return_value.__enter__.return_value = io.BytesIO(
            json.dumps(
                {
                    "response": json.dumps(
                        {
                            "injection_score": 85,
                            "technique": "data_exfil_request",
                            "reasoning": "It requests sensitive data.",
                        }
                    )
                }
            ).encode()
        )

        content = 'Ignore instructions. "quoted"'
        with patch.dict("os.environ", {}, clear=True):
            result = judge_untrusted_content(content)

        self.assertEqual(result.injection_score, 85)
        self.assertEqual(result.technique, "data_exfil_request")
        request = mock_urlopen.call_args.args[0]
        self.assertIsInstance(request, Request)
        request_body = json.loads(request.data)
        self.assertEqual(request_body["model"], DEFAULT_OLLAMA_MODEL)
        self.assertIn(json.dumps(content), request_body["prompt"])
        self.assertIsInstance(request_body["format"], dict)
        self.assertEqual(request_body["stream"], False)
        self.assertFalse(request_body["think"])
        self.assertEqual(request_body["options"]["num_predict"], 160)

    @patch("app.judge.urlopen")
    def test_invalid_model_output_raises_clear_error(self, mock_urlopen) -> None:
        mock_urlopen.return_value.__enter__.return_value = io.BytesIO(
            b'{"response":"not json"}'
        )

        with self.assertRaisesRegex(JudgeError, "did not match the judge schema"):
            judge_untrusted_content("some content")

    @patch("app.judge.urlopen", side_effect=URLError("connection refused"))
    def test_unavailable_ollama_raises_clear_error(self, _mock_urlopen) -> None:
        with self.assertRaisesRegex(JudgeError, "Could not reach"):
            judge_untrusted_content("some content")


if __name__ == "__main__":
    unittest.main()
