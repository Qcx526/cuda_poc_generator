import sys, unittest
from io import StringIO
from unittest.mock import patch


class TestCLI(unittest.TestCase):

    def test_help(self):
        with patch("sys.argv", ["main.py", "--help"]):
            with self.assertRaises(SystemExit) as ctx:
                from main import parse_args
                parse_args()
            self.assertEqual(ctx.exception.code, 0)

    def test_cve_id(self):
        with patch("sys.argv", ["main.py", "--cve-id", "CVE-2024-0124"]):
            from main import parse_args
            args = parse_args()
            self.assertEqual(args.cve_id, "CVE-2024-0124")

    def test_input_dir(self):
        with patch("sys.argv", ["main.py", "--input-dir", "/tmp/test"]):
            from main import parse_args
            args = parse_args()
            self.assertEqual(args.input_dir, "/tmp/test")

    def test_mutual_exclusion(self):
        with patch("sys.argv", ["main.py", "--cve-id", "X", "--input-dir", "Y"]):
            with patch("sys.stderr", new_callable=StringIO):
                with self.assertRaises(SystemExit) as ctx:
                    import main
                    main.main()
                self.assertEqual(ctx.exception.code, 1)

    def test_no_args(self):
        with patch("sys.argv", ["main.py"]):
            with self.assertRaises(SystemExit) as ctx:
                import main
                main.main()
            self.assertEqual(ctx.exception.code, 1)

    def test_output_dir(self):
        with patch("sys.argv", ["main.py", "--output-dir", "/tmp/out"]):
            from main import parse_args
            args = parse_args()
            self.assertEqual(args.output_dir, "/tmp/out")


if __name__ == "__main__":
    unittest.main()
