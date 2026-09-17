"""
End-to-End API Route Tests using httpx.AsyncClient
"""

import unittest
import asyncio
import httpx
from backend.app import app


def run_async(coro):
    """Helper to run async test coroutine."""
    return asyncio.run(coro)


class TestAPIRoutes(unittest.TestCase):

    def test_health_endpoint(self):
        async def _test():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
                response = await client.get("/api/health")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["status"], "healthy")
        run_async(_test())

    def test_scan_url_api(self):
        async def _test():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
                payload = {"url": "https://www.google.com", "deep_analysis": True}
                response = await client.post("/api/scan/url", json=payload)
                self.assertEqual(response.status_code, 200)
                data = response.json()
                self.assertIn("prediction", data)
                self.assertIn("confidence", data)
                self.assertIn("risk_score", data)
                self.assertIn("indicators", data)
        run_async(_test())

    def test_scan_message_api(self):
        async def _test():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
                payload = {"message": "Your OTP code is 948201. Do not disclose to anyone."}
                response = await client.post("/api/scan/message", json=payload)
                self.assertEqual(response.status_code, 200)
                data = response.json()
                self.assertEqual(data["scan_type"], "message")
                self.assertIn("prediction", data)
        run_async(_test())

    def test_get_history_api(self):
        async def _test():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
                response = await client.get("/api/history?page=1&page_size=10")
                self.assertEqual(response.status_code, 200)
                data = response.json()
                self.assertIn("total", data)
                self.assertIn("scans", data)
        run_async(_test())

    def test_get_analytics_api(self):
        async def _test():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
                response = await client.get("/api/analytics")
                self.assertEqual(response.status_code, 200)
                data = response.json()
                self.assertIn("total_scans", data)
                self.assertIn("detection_rate", data)
        run_async(_test())

    def test_get_model_metrics_api(self):
        async def _test():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
                response = await client.get("/api/model/metrics")
                self.assertEqual(response.status_code, 200)
                data = response.json()
                self.assertIn("url_classifier", data)
                self.assertIn("text_classifier", data)
        run_async(_test())

    def test_get_demo_samples_api(self):
        async def _test():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
                response = await client.get("/api/demo/samples")
                self.assertEqual(response.status_code, 200)
                self.assertIsInstance(response.json(), list)
        run_async(_test())


if __name__ == "__main__":
    unittest.main()
