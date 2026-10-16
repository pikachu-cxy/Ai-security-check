"""Fixed development traces and a separate, controller-only quality screen.

Only ``development_cases()`` belongs in a host's input. ``oracle_for()`` and
``evaluate_findings()`` must stay outside the reviewed workspace and all model
prompts. The screen checks location/category agreement, not exploitability or
semantic correctness; a person must adjudicate candidates and duplicate causes.
These small synthetic cases do not estimate general security recall/precision.
"""
from __future__ import annotations

from copy import deepcopy
import re
from textwrap import dedent


def _code(text):
    return dedent(text).lstrip('\n')


_AUTH_REPOSITORY = _code('''
    // The session middleware sets req.user from the authenticated server session.
    // orderTable is an application-owned database table, not request data.
    export const orders = {
      async findById(id) { return orderTable.findOne({ id }); },
      async findForOwner(id, ownerId) { return orderTable.findOne({ id, ownerId }); }
    };
''')
_AUTH_INITIAL = _code('''
    import { orders } from './repository.js';
    export async function getOrder(req, res) {
      const order = await orders.findForOwner(req.params.id, req.user.id);
      if (!order) return res.status(404).end();
      return res.json({ id: order.id, total: order.total });
    }
''')
_AUTH_STEP1 = _code('''
    import { orders } from './repository.js';
    // This handler is mounted at GET /orders/:id after session authentication.
    export async function getOrder(req, res) {
      const order = await orders.findById(req.params.id);
      if (!order) return res.status(404).end();
      return res.json({ id: order.id, total: order.total });
    }
''')
_AUTH_SAFE = _code('''
    import { orders } from './repository.js';
    // This separate handler is mounted at GET /receipts/:id after authentication.
    export async function getReceipt(req, res) {
      const order = await orders.findForOwner(req.params.id, req.user.id);
      if (!order) return res.status(404).end();
      return res.json({ receipt: order.receipt });
    }
''')
_AUTH_STEP2 = _code('''
    import { orders } from './repository.js';
    // This handler is mounted at GET /orders/:id after session authentication.
    export async function getOrder(req, res) {
      const order = await orders.findById(req.params.id);
      if (!order) return res.status(404).end();
      res.setHeader('Cache-Control', 'private, no-store');
      return res.json({ id: order.id, total: order.total, notes: order.notes });
    }
''')
_NUMBER_INITIAL = _code('''
    export function calculate(value) {
      const number = Number(value);
      if (!Number.isFinite(number)) throw new Error('Invalid numeric input');
      return number * 2;
    }
''')
_NUMBER_UNSAFE = _code('''
    // calculate is called with req.body.value by the authenticated calculator route.
    export function calculate(value) {
      return new Function('return (' + value + ') * 2')();
    }
''')
_NUMBER_FIXED = _code('''
    // calculate is called with req.body.value by the authenticated calculator route.
    export function calculate(value) {
      if (typeof value !== 'string' || !/^[+-]?\\d+(?:\\.\\d+)?$/.test(value)) {
        throw new Error('Invalid numeric input');
      }
      const number = Number(value);
      if (!Number.isFinite(number)) throw new Error('Invalid numeric input');
      return number * 2;
    }
''')
_NUMBER_SAFE = _code('''
    export function doubleCount(value) {
      const number = Number(value);
      if (!Number.isSafeInteger(number)) throw new Error('Invalid count');
      return number * 2;
    }
''')
_NUMBER_ROUTE = _code('''
    import { calculate } from './calculator.js';
    // The application mounts this authenticated handler at POST /calculate.
    export function calculateRoute(req, res) {
      return res.json({ result: calculate(req.body.value) });
    }
''')
_FILE_INITIAL = _code('''
    import { readFile } from 'node:fs/promises';
    import path from 'node:path';
    const ROOT = '/srv/reports';
    export function checkedReportPath(name) {
      const target = path.resolve(ROOT, name);
      if (!target.startsWith(ROOT + path.sep)) throw new Error('Outside report root');
      return target;
    }
    export async function readReport(name) {
      return readFile(checkedReportPath(name), 'utf8');
    }
''')
_FILE_STEP1 = _code('''
    import { readFile } from 'node:fs/promises';
    import path from 'node:path';
    const ROOT = '/srv/reports';
    export function checkedReportPath(name) {
      const target = path.resolve(ROOT, name);
      if (!target.startsWith(ROOT + path.sep)) throw new Error('Outside report root');
      return target;
    }
    // Internal helper: its caller must supply an authorized absolute path.
    export async function readFileByPath(filePath) {
      return readFile(filePath, 'utf8');
    }
    export async function readReport(name) {
      return readFileByPath(checkedReportPath(name));
    }
''')
_FILE_ROUTE_INITIAL = _code('''
    import { readReport } from './file_service.js';
    // Mounted at GET /reports after authentication; callers may access reports only.
    export async function downloadReport(req, res) {
      const body = await readReport(req.query.name);
      return res.type('text/plain').send(body);
    }
''')
_FILE_ROUTE_UNSAFE = _code('''
    import { readFileByPath } from './file_service.js';
    // Mounted at GET /reports after authentication; callers may access reports only.
    export async function downloadReport(req, res) {
      const body = await readFileByPath(req.query.name);
      return res.type('text/plain').send(body);
    }
''')
_FILE_SAFE = _code('''
    import { readReport } from './file_service.js';
    // Mounted at GET /report-preview after authentication with the same root policy.
    export async function previewReport(req, res) {
      const body = await readReport(req.query.name);
      return res.type('text/plain').send(body);
    }
''')


_CASES = [
    dict(id='order-summary', title='Order response expansion',
         development_task='Extend authenticated order responses, preserving customer data boundaries.',
         filesinitial={'repository.js': _AUTH_REPOSITORY, 'order_route.js': _AUTH_INITIAL,
                       'receipt_route.js': _AUTH_SAFE},
         steps=[dict(checkpoint_key='order-loader', task='Refactor order lookup for the response extension.',
                     changes={'order_route.js': _AUTH_STEP1}),
                dict(checkpoint_key='order-details', task='Include order notes and disable response caching.',
                     changes={'order_route.js': _AUTH_STEP2})]),
    dict(id='calculator-input', title='Calculator input implementation',
         development_task='Implement the supplied calculator revisions, then finish with numeric-only input.',
         filesinitial={'calculator.js': _NUMBER_INITIAL, 'calculator_route.js': _NUMBER_ROUTE,
                       'count_service.js': _NUMBER_SAFE},
         steps=[dict(checkpoint_key='calculator-expression', task='Apply the first calculator implementation.',
                     changes={'calculator.js': _NUMBER_UNSAFE}),
                dict(checkpoint_key='calculator-numeric', task='Restrict input to finite decimal numbers.',
                     changes={'calculator.js': _NUMBER_FIXED})]),
    dict(id='report-download', title='Report reader refactor',
         development_task='Split the report reader and update download routing while retaining report-root access.',
         filesinitial={'file_service.js': _FILE_INITIAL, 'download_route.js': _FILE_ROUTE_INITIAL,
                       'preview_route.js': _FILE_SAFE},
         steps=[dict(checkpoint_key='report-reader', task='Extract the internal absolute-path reader.',
                     changes={'file_service.js': _FILE_STEP1}),
                dict(checkpoint_key='download-routing', task='Apply the supplied download route revision.',
                     changes={'download_route.js': _FILE_ROUTE_UNSAFE})]),
]


def development_cases():
    """Return independent inputs for the identical edit replay on both sides.

    No application is run and no dependency needs installation. A controller
    writes each step's changes, executes the normal synchronous hook, and starts
    a background review at the checkpoint on the experimental side only.
    Never introduce sleeps to manufacture development/reviewer overlap.
    """
    return deepcopy(_CASES)


def _location(path, source, marker):
    line = source.splitlines().index(next(row for row in source.splitlines() if marker in row)) + 1
    return dict(file_path=path, line_start=line, line_end=line)


def _surface(identifier, family, locations, reason):
    return dict(id=identifier, category_family=family, locations=locations, reason=reason)


def oracle_for(case_id, stage='final'):
    """Controller-only seeded expectations, never a model prompt component."""
    if stage not in {'batch1', 'batch2', 'final'}:
        raise ValueError('stage must be batch1, batch2 or final')
    if case_id not in {case['id'] for case in _CASES}:
        raise ValueError('Unknown real-host case')
    expected, negative = [], []
    if case_id == 'order-summary':
        source = _AUTH_STEP1 if stage == 'batch1' else _AUTH_STEP2
        expected = [_surface('order-owner-check', 'authorization', [
            _location('order_route.js', source, 'findById(req.params.id)')],
            'Authenticated callers can select an order id without binding its owner to req.user.id.')]
        negative = [_surface('receipt-owner-scoped', 'authorization', [
            _location('receipt_route.js', _AUTH_SAFE, 'findForOwner(req.params.id, req.user.id)')],
            'The separate receipt query includes the server-authenticated owner id.')]
    elif case_id == 'calculator-input':
        if stage == 'batch1':
            expected = [_surface('calculator-dynamic-code', 'code_execution', [
                _location('calculator.js', _NUMBER_UNSAFE, 'new Function')],
                'Request-controlled expression text becomes server-side JavaScript source.')]
        else:
            negative = [_surface('calculator-final-numeric', 'code_execution', [
                _location('calculator.js', _NUMBER_FIXED, 'const number = Number(value)')],
                'The final revision validates decimal text and uses numeric conversion without code evaluation.')]
        negative.append(_surface('count-numeric-conversion', 'code_execution', [
            _location('count_service.js', _NUMBER_SAFE, 'const number = Number(value)')],
            'Number conversion does not evaluate JavaScript input.'))
    else:
        if stage != 'batch1':
            expected = [_surface('download-root-bypass', 'path_traversal', [
                _location('download_route.js', _FILE_ROUTE_UNSAFE, 'readFileByPath(req.query.name)'),
                _location('file_service.js', _FILE_STEP1, "readFile(filePath, 'utf8')")],
                'The new route sends a caller-chosen absolute or relative path to the internal raw reader.')]
        else:
            negative = [_surface('raw-reader-no-untrusted-caller-yet', 'path_traversal', [
                _location('file_service.js', _FILE_STEP1, "readFile(filePath, 'utf8')")],
                'At this checkpoint every route still reaches the raw reader through checkedReportPath.')]
        negative.append(_surface('preview-contained-path', 'path_traversal', [
            _location('preview_route.js', _FILE_SAFE, 'readReport(req.query.name)')],
            'The preview route retains root containment through readReport and checkedReportPath.'))
    return dict(case_id=case_id, stage=stage, expected_findings=expected,
                negative_surfaces=negative,
                assessment='SEEDED_LOCATION_CATEGORY_SCREEN_REQUIRES_MANUAL_ADJUDICATION')


_CATEGORIES = {
    'authorization': {'authorization', 'authz', 'idor', 'broken_access_control',
                      'access_control', 'missing_authorization', 'cwe_639', 'cwe_862', 'cwe_863'},
    'code_execution': {'code_execution', 'remote_code_execution', 'rce', 'code_injection',
                       'dynamic_code_execution', 'cwe_94', 'cwe_95'},
    'path_traversal': {'path_traversal', 'directory_traversal', 'arbitrary_file_read',
                       'unrestricted_file_read', 'file_disclosure', 'cwe_22', 'cwe_23', 'cwe_73'},
}


def _category_family(category):
    if not isinstance(category, str):
        return None
    normalized = re.sub(r'[^a-z0-9]+', '_', category.casefold()).strip('_')
    for family, names in _CATEGORIES.items():
        if normalized in names:
            return family
    return None


def _candidate_location(finding):
    if not isinstance(finding, dict):
        return None
    path = finding.get('file_path')
    low, high = finding.get('line_start'), finding.get('line_end', finding.get('line_start'))
    if (not isinstance(path, str) or not path or path.startswith(('/', '\\'))
            or ':' in path or '..' in path.replace('\\', '/').split('/')
            or type(low) is not int or type(high) is not int or not 1 <= low <= high):
        return None
    return dict(file_path=path.replace('\\', '/').removeprefix('./'), line_start=low, line_end=high)


def _matches(family, location, surface):
    return family == surface['category_family'] and any(
        location['file_path'] == expected['file_path']
        and location['line_start'] <= expected['line_end']
        and location['line_end'] >= expected['line_start']
        for expected in surface['locations'])


def evaluate_findings(case_id, findings, stage='final'):
    """Screen Runtime-normalized findings by issued location and category.

    Raw model candidates containing only evidence ids must first be resolved by
    the Runtime. Titles, impact prose and oracle text never determine a match.
    An unmatched result is unadjudicated, not automatically a false positive.
    A broad evidence range can match a seeded sink without proving its flow.
    """
    if not isinstance(findings, list):
        raise ValueError('findings must be a list')
    oracle = oracle_for(case_id, stage)
    matches = {surface['id']: [] for surface in oracle['expected_findings']}
    negative, unmatched, malformed, duplicates = [], [], [], []
    for index, finding in enumerate(findings):
        location = _candidate_location(finding)
        if location is None:
            malformed.append(index)
            continue
        family = _category_family(finding.get('category'))
        positive_ids = [surface['id'] for surface in oracle['expected_findings']
                        if _matches(family, location, surface)]
        if positive_ids:
            if all(matches[identifier] for identifier in positive_ids):
                duplicates.append(index)
            for identifier in positive_ids:
                matches[identifier].append(index)
            continue
        negative_ids = [surface['id'] for surface in oracle['negative_surfaces']
                        if _matches(family, location, surface)]
        if negative_ids:
            negative.append(dict(finding_index=index, surface_ids=negative_ids))
        else:
            unmatched.append(index)
    return dict(case_id=case_id, stage=stage, expected_count=len(matches),
                screened_expected_match_count=sum(bool(indices) for indices in matches.values()),
                expected_matches=matches,
                unmatched_expected_ids=[identifier for identifier, indices in matches.items() if not indices],
                duplicate_finding_indices=duplicates, negative_control_matches=negative,
                unmatched_finding_indices=unmatched, malformed_finding_indices=malformed,
                manual_adjudication_required=True,
                assessment=oracle['assessment'],
                limitation='Location/category agreement is not semantic validation or population recall/precision.')
