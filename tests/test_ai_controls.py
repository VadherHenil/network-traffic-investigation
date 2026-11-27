import io
import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from providers import (approved_review, excerpt, prepare_review, review, set_approvals,
                       validate_saved_review)


class AIControlsTests(unittest.TestCase):
    def setUp(self):
        self.policy = patch.dict(os.environ)
        self.policy.start()
        self.addCleanup(self.policy.stop)
        os.environ.pop("HENIX_AI_ALLOWED_ORIGINS", None)
        rows = [{"frame.number": str(i), "ip.src": "192.0.2.6", "ip.dst": "198.51.100.1",
                 "dns.qry.name":"secret.example", "dns.flags.rcode":"0", "http.host":"secret.example",
                 "frame.time_epoch":"1760000000", "_ws.col.Protocol":"DNS", "frame.protocols":"udp:dns"}
                for i in (1, 2)]
        self.capture = SimpleNamespace(id="EV-A12345678901", rows=rows, by_number={r["frame.number"]:r for r in rows})
        self.evidence = excerpt(self.capture, rows, 'dns.qry.name == "secret.example"', [], redact=True)
        self.options = dict(endpoint="https://gateway.example:8443/v1/chat/completions")
        self.answer = json.dumps({"observations":[
            {"evidence":self.capture.id, "frames":[1], "text":"DNS query observed."},
            {"evidence":"EV-000000000000", "frames":[2], "text":"Wrong capture."},
            {"evidence":self.capture.id, "frames":[99], "text":"Wrong frame."},
            {"evidence":self.capture.id, "frames":[2], "text":"Inspect frame 99."},
        ]})

    def test_exact_preview_and_redaction(self):
        preview = prepare_review("custom","model",self.evidence,**self.options)
        outgoing = json.dumps(preview)
        for value in ("secret.example","192.0.2.6","198.51.100.1"):
            self.assertNotIn(value, outgoing)
        self.assertEqual(self.evidence["frames"][0]["source"], self.evidence["frames"][1]["source"])
        self.assertEqual(self.evidence["frames"][0]["fields"], {"dns.flags.rcode":"0"})
        opener = Mock()
        opener.open.return_value = io.BytesIO(json.dumps({"choices":[{"message":{"content":self.answer}, "finish_reason":"stop"}]}).encode())
        result = review("custom","dummy","model",self.evidence,opener,fingerprint=preview["fingerprint"],**self.options)
        request = opener.open.call_args.args[0]
        self.assertEqual(json.loads(request.data), preview["body"])
        self.assertEqual(request.full_url, preview["url"])
        self.assertEqual([o["valid"] for o in result["observations"]],[True,False,False,False])
        self.assertIsNone(approved_review(result))
        with self.assertRaises(ValueError):
            set_approvals(result, result["id"], [2])
        with self.assertRaises(ValueError):
            set_approvals(result, "stale", [0])
        set_approvals(result, result["id"], [0])
        restored = validate_saved_review(result, self.capture)
        self.assertEqual(approved_review(restored)["text"],"DNS query observed. (frames 1)")
        result["observations"][2]["valid"] = True
        result["approved"] = [2]
        with self.assertRaises(ValueError):
            validate_saved_review(result, self.capture)

    def test_changed_preview_and_allowlist_fail_before_contact(self):
        preview = prepare_review("custom","model",self.evidence,**self.options)
        opener = Mock()
        with self.assertRaisesRegex(ValueError,"changed"):
            review("custom","dummy","other",self.evidence,opener,fingerprint=preview["fingerprint"],**self.options)
        os.environ["HENIX_AI_ALLOWED_ORIGINS"] = "https://gateway.example:8443"
        prepare_review("custom","model",self.evidence,**self.options)
        for url in ("https://gateway.example/v1","https://sub.gateway.example:8443/v1","https://other.example/v1"):
            with self.assertRaisesRegex(ValueError,"does not allow"):
                review("custom","dummy","model",self.evidence,opener,endpoint=url)
        with self.assertRaisesRegex(ValueError,"does not allow"):
            prepare_review("openai","model",self.evidence)
        os.environ["HENIX_AI_ALLOWED_ORIGINS"] = ""
        with self.assertRaisesRegex(ValueError,"does not allow"):
            review("custom","dummy","model",self.evidence,opener,**self.options)
        opener.open.assert_not_called()

    def test_malformed_provider_and_saved_unicode(self):
        for answer in ("\ud800", json.dumps({"observations": [{"text": "\ud800"}]})):
            opener = Mock()
            response = {"choices": [{"message": {"content": answer}, "finish_reason": "stop"}]}
            opener.open.return_value = io.BytesIO(json.dumps(response).encode())
            with self.assertRaisesRegex(ValueError, "Unicode"):
                review("custom", "dummy", "model", self.evidence, opener, **self.options)
        saved = dict(id="a" * 32, provider="custom", model="org/model", provider_label="\ud800", text=self.answer)
        with self.assertRaisesRegex(ValueError, "metadata"):
            validate_saved_review(saved, self.capture)
