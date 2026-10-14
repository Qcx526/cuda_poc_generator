"""Read-only Git hygiene checks using hypothetical paths, without creating files."""

from pathlib import Path
import shutil
import subprocess
import unittest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


@unittest.skipUnless((PROJECT_ROOT / ".git").exists(), "Source snapshot has no Git metadata")
class TestRepositoryHygiene(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.git = shutil.which("git")
        if cls.git is None:
            raise unittest.SkipTest("Git is not installed or unavailable on PATH")

    def git_result(self, arguments, input_text=None):
        return subprocess.run(
            [self.git, *arguments], cwd=str(PROJECT_ROOT), input=input_text,
            capture_output=True, text=True, encoding="utf-8", timeout=20,
        )

    def ignored_paths(self, paths):
        # --no-index checks the policy even for paths currently tracked by Git.
        # -z prevents Git's filename quoting from affecting the assertions.
        result = self.git_result(
            ["check-ignore", "--no-index", "-z", "--stdin"],
            input_text="\0".join(paths) + "\0",
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return set(filter(None, result.stdout.split("\0")))

    def test_local_environments_secrets_and_runtime_outputs_are_ignored(self):
        paths = (
            ".venv/Scripts/python.exe", ".venv/bin/python", ".venv-linux/bin/python",
            ".venv-windows/Scripts/activate.ps1", "venv/bin/python", "env/Scripts/python.exe",
            ".conda/conda-meta/history", "environment.local.yml", "conda-export-local.yaml",
            ".env", ".env.local", ".env.wsl", "config/local.yaml", "config/deepseek.local.yml",
            "credentials/provider.json", "secrets/local.json", "src/__pycache__/pipeline.pyc",
            ".pytest_cache/v/cache/nodeids", ".ruff_cache/metadata", ".mypy_cache/types.json",
            "dist/project.whl", "cuda_poc_generator.egg-info/PKG-INFO",
            ".vscode/launch.json", ".vscode/session.tmp", ".workbuddy/session.json",
            "logs/local.log", "data/llm_logs/raw-call.json", "data/probes/windows-host.json",
            "data/probes/wsl-host.log", "data/outputs/manual-run/candidate.py",
            "data/outputs/CVE-2024-0124/cuda_poc_v1.py",
            "data/knowledge_bases/.chromadb/chroma.sqlite3", ".chromadb/chroma.sqlite3",
            "benchmark/results/local.json", "benchmarks/results/local.csv",
            "data/benchmark_results/report.json", "runs/local/kernel.cubin",
            "runs/local/kernel.o", "build/kernel.ptx", "build/cuda-test.exe",
            "artifacts/local/kernel.fatbin", "tmp/nvcc-intermediate.cu",
        )
        self.assertEqual(self.ignored_paths(paths), set(paths))

    def test_templates_research_sources_and_fixtures_remain_trackable(self):
        paths = (
            ".env.example", ".vscode/settings.json", ".vscode/extensions.json",
            "data/inputs/CVE-2024-0124/1_os_environment.json",
            "data/inputs/CVE-2025-23339/7_root_cause.json",
            "data/knowledge_bases/cuda/cuda_vulnerability_knowledge.md",
            "data/knowledge_bases/cuda/controlled-source.txt", "data/outputs/.gitkeep",
            "tests/fixtures/source.cu", "tests/fixtures/source.cubin",
            "tests/fixtures/source.log", "tests/fixtures/source.json",
            "src/research/source.cu", "research/source.cu", "research/source.cubin",
            "research/source.log", "research/source.json", "data/research/source.cu",
        )
        self.assertEqual(self.ignored_paths(paths), set())

    def test_private_dotenv_and_workbuddy_files_are_not_in_index(self):
        result = self.git_result(["ls-files", "-z", "--", ".env", ".workbuddy"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "", "Private .env or .workbuddy data is already tracked")


if __name__ == "__main__":
    unittest.main()
