"""Fixture isolation and contrasts; these tests do not certify product discovery."""
import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

spec=importlib.util.spec_from_file_location('reliability_lab',Path(__file__).resolve().parents[1]/'scripts/new_reliability_lab.py')
lab=importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


def test_suite_is_fresh_anonymous_and_locally_testable(tmp_path):
    projects,reviewer=tmp_path/'projects',tmp_path/'reviewer'
    result=lab.generate(projects,reviewer)
    assert result['project_count']==22
    answers=json.loads((reviewer/'answer-key.json').read_text(encoding='utf-8'))
    assert len(answers)==22
    for name,answer in answers.items():
        project=projects/name
        assert (project/'.git').is_dir()
        assert not (project/'AGENTS.md').exists()
        assert not list(project.rglob('*answer*')) and not list(project.rglob('*PROMPT*'))
        prompt=(reviewer/'prompts'/f'{name}.txt').read_text(encoding='utf-8')
        assert str(project) in prompt and 'ai-security' not in prompt and '请扫描' not in prompt
        for path in project.rglob('*.py'):
            ast.parse(path.read_text(encoding='utf-8'))
        if (project/'tests').exists():
            subprocess.run([sys.executable,'-B','-m','unittest','discover','-s','tests','-q'],
                           cwd=project,check=True,capture_output=True,timeout=20)
        status=subprocess.check_output(['git','-C',str(project),'status','--porcelain']).decode()
        assert not status
        if answer['family']=='dependency':
            profile=json.loads((project/'component-profile.json').read_text())
            assert profile['version']==answer['variant']
            assert not json.loads((project/'package.json').read_text()).get('dependencies')
        if answer['family']=='secret':
            text=(project/'feature.py').read_text()
            assert ('TOKEN = "ghp_' in text)==(answer['variant']=='format-match')
        if answer['family']=='long-file':
            tree=ast.parse((project/'feature.py').read_text())
            assert next(n for n in tree.body if isinstance(n,ast.FunctionDef)).lineno>500
    for family in lab.SNIPPETS:
        assert sorted(v['variant'] for v in answers.values() if v['family']==family)==['conditional','control']
    assert sorted(v['variant'] for v in answers.values() if v['family']=='multi-task')==['control','mixed']
    assert set(n for n in answers if n.startswith('workbench-'))=={'workbench-01','workbench-02'}


def test_existing_directory_and_overlapping_answers_are_rejected(tmp_path):
    projects=tmp_path/'projects';projects.mkdir()
    marker=projects/'keep';marker.write_text('existing')
    with pytest.raises(ValueError):lab.generate(projects,tmp_path/'answers')
    assert marker.read_text()=='existing'
    with pytest.raises(ValueError):lab.generate(tmp_path/'new',tmp_path/'new/answers')
    assert not (tmp_path/'new').exists()


def test_basic_controls_have_different_semantics():
    # Safe operations that can be evaluated without commands, network or payloads.
    for family in ('sql','page'):
        unsafe,safe=[{} for _ in range(2)]
        exec(lab.SNIPPETS[family][0],unsafe)
        exec(lab.SNIPPETS[family][1],safe)
        if family=='page':
            assert unsafe['perform']('<b>item</b>')=='<span><b>item</b></span>'
            assert safe['perform']('<b>item</b>')=='<span>&lt;b&gt;item&lt;/b&gt;</span>'
        else:
            class Connection:
                def execute(self,*args):self.args=args;return self
                def fetchall(self):return []
            connection=Connection()
            safe['perform'](connection,"O'Reilly")
            assert connection.args==('SELECT id FROM items WHERE name = ?',("O'Reilly",))
            unsafe['perform'](connection,"O'Reilly")
            assert len(connection.args)==1
