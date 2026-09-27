"""Headless tests for the Streamlit dashboard."""

import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest


APP_PATH = Path(__file__).resolve().parents[1] / "streamlit_app.py"


class StreamlitAppTests(unittest.TestCase):
    """Verify the dashboard entry screen renders without errors."""

    def test_entry_screen_renders_title_and_caption(self):
        app = AppTest.from_file(str(APP_PATH)).run()

        self.assertFalse(app.exception)
        self.assertEqual(app.title[0].value, "Network traffic analyser")
        self.assertEqual(
            app.caption[0].value,
            "Upload a PCAP file to explore traffic statistics and security alerts.",
        )

    def test_entry_screen_prompts_for_one_capture_file(self):
        app = AppTest.from_file(str(APP_PATH)).run()

        self.assertFalse(app.exception)
        self.assertEqual(len(app.get("file_uploader")), 1)
        self.assertEqual(
            app.info[0].value,
            "Upload a PCAP or PCAPNG file to begin analysis.",
        )
        self.assertFalse(app.success)


if __name__ == "__main__":
    unittest.main()
