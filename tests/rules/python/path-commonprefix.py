"""Authored containment controls, never executed by the rule gate."""
import os


def unsafe_lookup(roots, user_path):
    for base in roots:
        joined = os.path.join(base, user_path)
        candidate = os.path.realpath(joined)
        base = os.path.realpath(base)
        # ruleid: ai-security.python.path-commonprefix-stat-lookup
        if os.path.commonprefix([candidate, base]) != base:
            continue
        try:
            return candidate, os.stat(candidate)
        except OSError:
            continue


def safe_component_lookup(roots, user_path):
    for base in roots:
        joined = os.path.join(base, user_path)
        candidate = os.path.realpath(joined)
        base = os.path.realpath(base)
        # ok: ai-security.python.path-commonprefix-stat-lookup
        if os.path.commonpath([candidate, base]) != base:
            continue
        try:
            return candidate, os.stat(candidate)
        except OSError:
            continue


def display_only(names):
    # ok: ai-security.python.path-commonprefix-stat-lookup
    return os.path.commonprefix(names)


def no_filesystem_operation(roots, user_path):
    for base in roots:
        joined = os.path.join(base, user_path)
        candidate = os.path.realpath(joined)
        base = os.path.realpath(base)
        # ok: ai-security.python.path-commonprefix-stat-lookup
        if os.path.commonprefix([candidate, base]) != base:
            continue
        return candidate


def wrong_root_not_a_containment_comparison(roots, user_path):
    for base in roots:
        joined = os.path.join(base, user_path)
        candidate = os.path.realpath(joined)
        base = os.path.realpath(base)
        # ok: ai-security.python.path-commonprefix-stat-lookup
        if os.path.commonprefix([candidate, base]) != 'display-label':
            continue
        try:
            return candidate, os.stat(candidate)
        except OSError:
            continue
