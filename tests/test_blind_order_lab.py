"""Check that anonymous fixtures differ in behavior and never leak the answer key."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "new_blind_order_lab.py"
spec = importlib.util.spec_from_file_location("blind_order_generator", SCRIPT)
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


def test_anonymous_pair_and_original_tests(tmp_path):
    projects = tmp_path / "projects"
    answers = tmp_path / "answers"
    manifest = generator.generate(projects, answers)
    assert set(manifest["projects"].values()) == {"restricted", "unrestricted"}
    behaviors = {}
    for name, variant in manifest["projects"].items():
        project = projects / name
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                       cwd=project, check=True, capture_output=True, timeout=30)
        result = subprocess.run([sys.executable, "-c",
            "import json; from orders.service import OrderService; s=OrderService(); "
            "print(json.dumps({'own': s.lookup_order('customer-001','order-100') is not None, "
            "'other': s.lookup_order('customer-001','order-200') is not None, "
            "'listed': [o['id'] for o in s.list_orders('customer-001')]}))"],
            cwd=project, check=True, capture_output=True, text=True, timeout=30)
        behavior = json.loads(result.stdout)
        assert behavior["own"] is True
        assert behavior["listed"] == ["order-100"]
        assert behavior["other"] is (variant == "unrestricted")
        behaviors[name] = behavior
        assert not list(project.rglob("*answer*"))
        assert not list(project.rglob("*EVALUATION*"))
        assert not (project / "AGENTS.md").exists()
        for path in project.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert "intentional" not in text.lower()
            assert "vulnerab" not in text.lower()
        status = subprocess.run(["git", "-C", str(project), "status", "--porcelain"],
                                check=True, capture_output=True, text=True, timeout=30)
        assert not status.stdout
    assert sorted(b["other"] for b in behaviors.values()) == [False, True]
    for name in generator.COMMON:
        if name != "orders/repository.py":
            assert (projects / "project-01" / name).read_bytes() == (projects / "project-02" / name).read_bytes()


def test_existing_directories_are_preserved(tmp_path):
    projects, answers = tmp_path / "projects", tmp_path / "answers"
    projects.mkdir()
    marker = projects / "keep.txt"
    marker.write_text("preserve", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        generator.generate(projects, answers)
    assert marker.read_text(encoding="utf-8") == "preserve"
    assert not answers.exists()


def test_answer_directory_cannot_be_inside_project_tree(tmp_path):
    projects = tmp_path / "projects"
    with pytest.raises(ValueError, match="outside"):
        generator.generate(projects, projects / "answers")
    assert not projects.exists()
