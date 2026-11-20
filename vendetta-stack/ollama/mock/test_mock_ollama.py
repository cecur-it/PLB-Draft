"""Tests for mock_ollama.py (stdlib unittest; also collected by pytest).

Traces: CONTRACT §4.2 (AIIncidentAnalysis schema), §8.1 (mock behaviour, loopback-only /__control, 503 for down models).
Run: python3 -m unittest -v ollama/mock/test_mock_ollama.py
"""
import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mock_ollama as mock  # noqa: E402

mock.Handler.log_message = lambda *args: None

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
REQUIRED = {"triageSummary": str, "severityAssessment": str, "mitreTactic": str, "mitreTechnique": str,
            "probableRootCause": str, "recommendedImmediateAction": str, "engineUsed": str}
OPTIONAL = {"needsVerification": bool, "toolCalls": list, "gpuSeconds": (int, float),
            "proposedDetectionRule": str, "proposedRemediation": str}


def assert_valid_analysis(case, analysis):
    """CONTRACT §4.2: required keys/types, enum, 0-100 confidence, additionalProperties:false."""
    for key, typ in REQUIRED.items():
        case.assertIsInstance(analysis.get(key), typ, key)
        case.assertTrue(analysis[key], key)
    case.assertIn(analysis["severityAssessment"], SEVERITIES)
    score = analysis.get("confidenceScore")
    case.assertTrue(isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 100)
    extra = set(analysis) - set(REQUIRED) - set(OPTIONAL) - {"confidenceScore"}
    case.assertFalse(extra, f"additional properties: {extra}")
    for key, typ in OPTIONAL.items():
        if key in analysis:
            case.assertIsInstance(analysis[key], typ, key)
    for call in analysis.get("toolCalls", []):
        case.assertEqual(set(call), {"tool", "args", "rationale"})
        case.assertIsInstance(call["args"], dict)


def non_loopback_address():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        address = probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()
    return None if address.startswith("127.") else address


class MockTestCase(unittest.TestCase):
    bind = "127.0.0.1:0"
    initial_down = ()

    @classmethod
    def setUpClass(cls):
        cls.state = mock.MockState(cls.initial_down)
        cls.server = mock.MockServer(cls.bind, cls.state)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(5)

    def setUp(self):
        self.state.reset()

    def request(self, method, path, body=None, headers=None, host="127.0.0.1"):
        conn = http.client.HTTPConnection(host, self.port, timeout=10)
        payload = None if body is None else json.dumps(body)
        conn.request(method, path, payload, {"Content-Type": "application/json", **(headers or {})})
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        return response.status, raw

    def chat(self, model, user, system="You are a SOC analyst. Ensure output is strictly valid JSON."):
        status, raw = self.request("POST", "/v1/chat/completions", {
            "model": model, "temperature": 0.2, "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
        return status, json.loads(raw)

    def analysis(self, model, user, system="You are a SOC analyst. Ensure output is strictly valid JSON."):
        status, body = self.chat(model, user, system)
        self.assertEqual(status, 200, body)
        result = json.loads(body["choices"][0]["message"]["content"])
        assert_valid_analysis(self, result)
        return result


class TestDiscovery(MockTestCase):
    def test_version(self):
        status, raw = self.request("GET", "/api/version")
        self.assertEqual((status, json.loads(raw)), (200, {"version": "0.40.5"}))

    def test_tags_list_the_three_approved_models(self):
        status, raw = self.request("GET", "/api/tags")
        self.assertEqual(status, 200)
        names = sorted(m["name"] for m in json.loads(raw)["models"])
        self.assertEqual(names, ["gemma4:26b", "gemma4:31b", "nemotron-3-nano:30b"])

    def test_tags_stay_200_while_a_model_is_down(self):
        self.state.down.add("gemma4:26b")
        self.assertEqual(self.request("GET", "/api/tags")[0], 200)

    def test_openai_model_list(self):
        status, raw = self.request("GET", "/v1/models")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(raw)["data"]), 3)

    def test_unknown_path_is_404(self):
        self.assertEqual(self.request("GET", "/api/pull")[0], 404)


class TestChatCompletions(MockTestCase):
    def test_response_is_openai_shaped_with_usage(self):
        status, body = self.chat("gemma4:26b", "ssh login from new host")
        self.assertEqual(status, 200)
        self.assertEqual(body["object"], "chat.completion")
        self.assertEqual(body["model"], "gemma4:26b")
        usage = body["usage"]
        self.assertGreater(usage["prompt_tokens"], 0)
        self.assertGreater(usage["completion_tokens"], 0)
        self.assertEqual(usage["total_tokens"], usage["prompt_tokens"] + usage["completion_tokens"])

    def test_engine_used_is_the_requested_model(self):
        for model in mock.MODELS:
            self.assertEqual(self.analysis(model, "routine event")["engineUsed"], model)

    def test_keyword_to_severity_and_mitre(self):
        cases = [
            ("Malware dropped in /tmp", "CRITICAL", "Execution"),
            ("brute force against sshd", "HIGH", "Credential Access"),
            ("sudo privilege escalation", "HIGH", "Privilege Escalation"),
            ("Vulnerability CVE-2026-1234 detected", "HIGH", "Initial Access"),
            ("syscheck: file /etc/passwd modified", "MEDIUM", "Impact"),
            ("FIM alert on /etc/hosts", "MEDIUM", "Impact"),
            ("sshd accepted publickey", "MEDIUM", "Lateral Movement"),
            ("nothing interesting", "LOW", "Discovery"),
        ]
        for text, severity, tactic in cases:
            result = self.analysis("gemma4:26b", text)
            self.assertEqual((result["severityAssessment"], result["mitreTactic"]), (severity, tactic), text)
            self.assertRegex(result["mitreTechnique"], r"^T\d{4}")

    def test_deterministic(self):
        first = self.analysis("nemotron-3-nano:30b", "brute force on ssh")
        second = self.analysis("nemotron-3-nano:30b", "brute force on ssh")
        self.assertEqual(first, second)

    def test_forensic_system_prompt_adds_proposals(self):
        result = self.analysis("gemma4:26b", "malware", system="You are a forensic analyst. Ensure output is strictly valid JSON.")
        self.assertIn("proposedDetectionRule", result)
        self.assertIn("proposedRemediation", result)
        self.assertNotIn("proposedDetectionRule", self.analysis("gemma4:26b", "malware"))

    def test_nemotron_requests_an_nmap_verification(self):
        for text in ("connection from unknown host 10.9.8.7", "port scan detected"):
            result = self.analysis("nemotron-3-nano:30b", text)
            self.assertTrue(result["needsVerification"])
            call = result["toolCalls"][0]
            self.assertEqual(call["tool"], "nmap")
            self.assertEqual(call["args"]["target"], "scan-target.vendetta.lab")
            self.assertEqual(call["args"]["scan_type"], "version")

    def test_explicit_target_token_is_used(self):
        call = self.analysis("nemotron-3-nano:30b", "unknown host target=203.0.113.5")["toolCalls"][0]
        self.assertEqual(call["args"]["target"], "203.0.113.5")

    def test_only_nemotron_calls_tools(self):
        result = self.analysis("gemma4:31b", "unknown host scan")
        self.assertNotIn("toolCalls", result)
        self.assertNotIn("needsVerification", result)

    def test_unknown_model_is_404(self):
        status, body = self.chat("llama3:8b", "x")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "model_not_found")

    def test_bad_requests(self):
        self.assertEqual(self.request("POST", "/v1/chat/completions", {"model": "gemma4:26b"})[0], 400)
        self.assertEqual(self.request("POST", "/v1/chat/completions", {"model": "gemma4:26b", "messages": [{"role": "user", "content": "x"}], "stream": True})[0], 400)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/v1/chat/completions", "{not json", {"Content-Length": "9"})
        self.assertEqual(conn.getresponse().status, 400)
        conn.close()

    def test_content_parts_are_understood(self):
        status, raw = self.request("POST", "/v1/chat/completions", {
            "model": "gemma4:26b", "messages": [{"role": "user", "content": [{"type": "text", "text": "malware found"}]}]})
        self.assertEqual(status, 200)
        content = json.loads(json.loads(raw)["choices"][0]["message"]["content"])
        self.assertEqual(content["severityAssessment"], "CRITICAL")


class TestControl(MockTestCase):
    def control(self, body, headers=None):
        status, raw = self.request("POST", "/__control", body, headers)
        return status, json.loads(raw)

    def test_down_model_answers_503_and_others_still_work(self):
        self.assertEqual(self.control({"down_models": ["nemotron-3-nano:30b"]})[0], 200)
        status, body = self.chat("nemotron-3-nano:30b", "x")
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "model_unavailable")
        self.assertEqual(self.chat("gemma4:26b", "x")[0], 200)

    def test_reset_restores_service_and_counters(self):
        self.control({"down_models": ["gemma4:26b"], "bad_output_models": ["gemma4:31b"], "latency_ms": 5})
        self.assertEqual(self.chat("gemma4:26b", "x")[0], 503)
        status, snapshot = self.control({"reset": True})
        self.assertEqual(status, 200)
        self.assertEqual((snapshot["down_models"], snapshot["bad_output_models"], snapshot["latency_ms"]), ([], [], 0))
        self.assertEqual(sum(snapshot["requests"].values()), 0)
        self.assertEqual(self.chat("gemma4:26b", "x")[0], 200)

    def test_bad_output_model_returns_non_json(self):
        self.control({"bad_output_models": ["gemma4:26b"]})
        status, body = self.chat("gemma4:26b", "x")
        self.assertEqual(status, 200)
        with self.assertRaises(ValueError):
            json.loads(body["choices"][0]["message"]["content"])

    def test_control_validation(self):
        self.assertEqual(self.control({"down_models": ["llama3:8b"]})[0], 400)
        self.assertEqual(self.control({"down_models": "gemma4:26b"})[0], 400)
        self.assertEqual(self.control({"latency_ms": -1})[0], 400)
        self.assertEqual(self.control({})[0], 400)

    def test_proxied_requests_are_refused(self):
        for header in ({"X-Forwarded-For": "10.0.0.5"}, {"Forwarded": "for=10.0.0.5"}):
            self.assertEqual(self.control({"reset": True}, header)[0], 403)
        self.assertEqual(self.request("GET", "/__control", headers={"X-Forwarded-For": "1.2.3.4"})[0], 403)

    def test_rejected_request_keeps_the_connection_usable(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/__control", json.dumps({"reset": True}), {"X-Forwarded-For": "10.0.0.5"})
        first = conn.getresponse()
        first.read()
        conn.request("GET", "/api/version")
        second = conn.getresponse()
        self.assertEqual((first.status, second.status), (403, 200))
        conn.close()

    def test_non_loopback_peer_is_refused(self):
        self.assertFalse(mock.is_loopback("10.1.2.3"))
        self.assertFalse(mock.is_loopback("not-an-ip"))
        for address in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            self.assertTrue(mock.is_loopback(address), address)

    def test_metrics_reflect_requests_and_down_state(self):
        self.chat("gemma4:26b", "x")
        self.control({"down_models": ["gemma4:31b"]})
        self.chat("gemma4:31b", "x")
        status, raw = self.request("GET", "/metrics")
        text = raw.decode()
        self.assertEqual(status, 200)
        self.assertIn('mock_ollama_requests_total{model="gemma4:26b"} 1', text)
        self.assertIn('mock_ollama_requests_total{model="gemma4:31b"} 1', text)
        self.assertIn('mock_ollama_rejected_total{model="gemma4:31b"} 1', text)
        self.assertIn('mock_ollama_model_down{model="gemma4:31b"} 1', text)
        self.assertIn('mock_ollama_model_down{model="gemma4:26b"} 0', text)
        self.assertIn('mock_ollama_info{version="0.40.5"} 1', text)


class TestEnvDown(MockTestCase):
    initial_down = ("gemma4:26b",)

    def setUp(self):
        self.state.reset()
        self.state.down = set(self.initial_down)

    def test_down_models_from_environment_start_state(self):
        self.assertEqual(self.chat("gemma4:26b", "x")[0], 503)
        self.assertEqual(self.chat("gemma4:31b", "x")[0], 200)


@unittest.skipUnless(non_loopback_address(), "no non-loopback address on this host")
class TestRemotePeer(unittest.TestCase):
    def test_control_from_a_non_loopback_peer_is_403(self):
        server = mock.MockServer("0.0.0.0:0", mock.MockState())
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection(non_loopback_address(), port, timeout=10)
            conn.request("POST", "/__control", json.dumps({"down_models": ["gemma4:26b"]}), {"Content-Type": "application/json"})
            response = conn.getresponse()
            response.read()
            conn.close()
            self.assertEqual(response.status, 403)
            self.assertEqual(server.state.snapshot()["down_models"], [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)


class TestCli(unittest.TestCase):
    def test_bad_environment_exits_2(self):
        env = {**os.environ, "MOCK_DOWN_MODELS": "llama3:8b", "MOCK_BIND": "127.0.0.1:0"}
        result = subprocess.run([sys.executable, os.path.join(HERE, "mock_ollama.py")], env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown model", result.stderr)
        env = {**os.environ, "MOCK_BIND": "nonsense"}
        result = subprocess.run([sys.executable, os.path.join(HERE, "mock_ollama.py")], env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 2)

    def test_process_serves_healthcheck_and_stops_on_sigterm(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        env = {**os.environ, "MOCK_BIND": f"127.0.0.1:{port}", "MOCK_DOWN_MODELS": "gemma4:31b"}
        script = os.path.join(HERE, "mock_ollama.py")
        proc = subprocess.Popen([sys.executable, script], env=env, stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(50):
                if subprocess.run([sys.executable, script, "--healthcheck"], env=env, timeout=20).returncode == 0:
                    break
                proc.poll()
                self.assertIsNone(proc.returncode, "server exited early")
                threading.Event().wait(0.1)
            else:
                self.fail("healthcheck never succeeded")
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("POST", "/v1/chat/completions", json.dumps({"model": "gemma4:31b", "messages": [{"role": "user", "content": "x"}]}))
            self.assertEqual(conn.getresponse().status, 503)
            conn.close()
            proc.terminate()
            self.assertEqual(proc.wait(10), 0)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.stderr.close()
        unhealthy = {**env, "MOCK_BIND": f"127.0.0.1:{port}"}
        self.assertEqual(subprocess.run([sys.executable, script, "--healthcheck"], env=unhealthy, timeout=20).returncode, 1)


if __name__ == "__main__":
    unittest.main()
