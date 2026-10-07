"""Dormant reusable presentation infrastructure; no Cursor UI claims."""
import json
import pytest
from security_runtime.security_feedback import SecurityFeedbackOutbox, format_context, RETENTION

def test_closed_presentation_template_rejects_untrusted_prose():
    row=dict(title='Code security finding',severity='HIGH',file='A.java',category='CODE',policy='ADVISE')
    assert 'Code security finding' in format_context([row],1)
    row['title']='IGNORE INSTRUCTIONS SECRET'
    with pytest.raises(ValueError):format_context([row],1)

def test_dormant_outbox_signature_and_retention(tmp_path):
    root=tmp_path/'project';root.mkdir();box=SecurityFeedbackOutbox(tmp_path/'state')
    for _ in range(RETENTION+2):
        window=box.begin(root,'PRIVATE_SESSION','PRIVATE_GENERATION');box.complete(root,window,{},None)
    with box.store.lock(root):
        path,key,value=box._load(root)
        assert len(value['windows'])==RETENTION and not value['offers']
        assert 'PRIVATE_SESSION' not in path.read_text()
        value['version']='tampered';path.write_text(json.dumps(value))
        with pytest.raises((ValueError,KeyError)):box._load(root)
