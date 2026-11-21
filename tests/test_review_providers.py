import io
import json
import unittest
from unittest.mock import Mock

from providers import GUIDANCE, NoRedirect, PROVIDERS, review


class ReviewProviderTests(unittest.TestCase):
    evidence = {"included_frames": 1, "matching_frames": 1, "frames": [{"frame": 42}]}
    replies = {
        "responses": {"output": [{"content": [{"type": "output_text", "text": "frame 42"}]}]},
        "messages": {"content": [{"type": "thinking", "thinking": "private"}, {"type": "text", "text": "frame 42"}],
                     "stop_reason": "end_turn"},
        "gemini": {"candidates": [{"content":{"parts":[{"text":"frame 42"}]}, "finishReason":"STOP"}]},
        "chat": {"choices": [{"message":{"content":"frame 42"}, "finish_reason":"stop"}]},
    }

    def exercise(self, provider, protocol, model, **options):
        opener = Mock()
        opener.open.return_value = io.BytesIO(json.dumps(self.replies[protocol]).encode())
        result = review(provider, "fixture-key", model, self.evidence, opener, **options)
        req = opener.open.call_args.args[0]
        self.assertTrue(result["complete"])
        self.assertEqual(result["text"], "frame 42")
        self.assertNotIn("fixture-key", req.full_url)
        self.assertNotIn(b"fixture-key", req.data)
        self.assertIn(GUIDANCE, req.data.decode())
        self.assertIn("included_frames", req.data.decode())
        return req

    def test_named_providers(self):
        for name, preset in PROVIDERS.items():
            if name == "custom":
                continue
            with self.subTest(name=name):
                req = self.exercise(name, preset.protocol, preset.model or "team/model")
                self.assertEqual(req.full_url, preset.url.format(model=preset.model))
                headers = {k.lower(): v for k,v in req.header_items()}
                if name == "gemini":
                    self.assertEqual(headers["x-goog-api-key"], "fixture-key")
                elif name == "anthropic":
                    self.assertEqual(headers["x-api-key"], "fixture-key")
                    self.assertIn("anthropic-version", headers)
                else:
                    self.assertEqual(headers["authorization"], "Bearer fixture-key")

    def test_custom_formats_and_headers(self):
        for fmt in self.replies:
            with self.subTest(fmt=fmt):
                opener = Mock()
                opener.open.return_value = io.BytesIO(json.dumps(self.replies[fmt]).encode())
                result = review("custom", "fixture-key", "team/model", self.evidence, opener,
                                protocol=fmt, auth="api-key", endpoint="https://gateway.example/api/{model}")
                req = opener.open.call_args.args[0]
                self.assertEqual(req.full_url, "https://gateway.example/api/team%2Fmodel")
                self.assertEqual(req.get_header("Api-key"), "fixture-key")
                self.assertEqual(result["provider_label"], "Custom · gateway.example")
                self.assertEqual(result["text"], "frame 42")

    def test_invalid_destinations_never_send(self):
        for url in ["http://remote.example", "file:///tmp/review", "https://user:pw@example.org/review", "",
                    "https://example.org/a\\b", "https://example.org/#fragment"]:
            opener = Mock()
            with self.assertRaises(ValueError):
                review("custom", "fixture-key", "model", self.evidence, opener, endpoint=url)
            opener.open.assert_not_called()
        self.assertIsNone(NoRedirect().redirect_request(None))
