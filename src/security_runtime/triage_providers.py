"""Agent-native handoff and explicitly authorized OpenAI-compatible BYOK."""
import json
import os
import re
import socket
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import URLError, HTTPError

from .storage import SQLiteStore
from .triage_models import INSTRUCTIONS, RESULT_SCHEMA, TriageBudget
from .triage_evidence import encoded


class AIProvider(Protocol):
    provider_type: str
    provider_name: str
    model: str
    supports_structured_output: bool
    is_external: bool
    def triage(self, packet: dict) -> dict: ...


@dataclass
class AgentNativeProvider:
    provider_name: str = 'host-agent'
    model: str = 'host-managed'
    provider_type: str = 'AGENT_NATIVE'
    supports_structured_output: bool = True
    is_external: bool = False

    def triage(self, packet):
        raise ValueError('Runtime cannot invoke its host model; use prepare_triage then submit_triage')


def config_path():
    return SQLiteStore.default_path().parent/'ai.json'


@dataclass(frozen=True)
class AIConfig:
    base_url: str
    model: str
    api_key_env: str = 'SECURITY_RUNTIME_AI_KEY'
    provider: str = 'openai-compatible'

    def __post_init__(self):
        value=urlsplit(self.base_url)
        if (value.scheme not in {'https','http'} or not value.hostname or value.username or value.password
            or value.query or value.fragment or
            (value.scheme=='http' and value.hostname not in {'localhost','127.0.0.1','::1'})):
            raise ValueError('AI base URL requires HTTPS (loopback HTTP allowed), without credentials, query or fragment')
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{2,100}',self.api_key_env):
            raise ValueError('Provide an environment variable name, never an API key')
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9/_.:@-]{0,150}',self.model):
            raise ValueError('Invalid model name')
        if self.provider!='openai-compatible':
            raise ValueError('Unsupported AI provider')

    def save(self,path=None):
        destination=path or config_path()
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_text(json.dumps(asdict(self),indent=2)+'\n',encoding='utf-8')

    @classmethod
    def load(cls,path=None):
        location=path or config_path()
        with location.open('rb') as stream: raw=stream.read(16385)
        if len(raw)>16384: raise ValueError('AI configuration exceeds size limit')
        data=json.loads(raw)
        if not isinstance(data,dict) or set(data)-{'base_url','model','api_key_env','provider'}:
            raise ValueError('Invalid AI configuration')
        return cls(**data)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None


class OpenAICompatibleProvider:
    provider_type='BYOK'
    supports_structured_output=True
    is_external=True

    def __init__(self,config,*,allow_external_code_context=False,budget=None):
        if not allow_external_code_context:
            raise ValueError('External AI sends bounded, redacted code context. Explicit --allow-external-code-context is required')
        self.config=config
        self.model=config.model
        self.provider_name=config.base_url.rstrip('/')
        self.budget=budget or TriageBudget()

    def triage(self,packet):
        return self._request({'evidence_packet':packet},RESULT_SCHEMA)

    def triage_batch(self,packets):
        if not packets or len(packets)>self.budget.max_findings_per_batch:
            raise ValueError('Invalid AI batch size')
        # Same dependency group shares code context once, while each advisory
        # retains its own hash, finding ID, metadata and allowed references.
        common=packets[0]['context']
        items=[]
        for packet in packets:
            item=dict(packet)
            if item['context']==common:
                item['context']={'shared_context':'shared_UNTRUSTED_CODE'}
            items.append(item)
        schema={'type':'object','additionalProperties':False,'required':['results'],
                'properties':{'results':{'type':'array','maxItems':len(packets),'items':RESULT_SCHEMA}}}
        result=self._request({'evidence_packets':items,'shared_UNTRUSTED_CODE':common},schema)
        if not isinstance(result,dict) or set(result)!={'results'} or not isinstance(result['results'],list):
            raise ValueError('Malformed AI batch response')
        return result['results']

    def _request(self,evidence,schema):
        if os.getenv('SECURITY_RUNTIME_OFFLINE')=='1' and urlsplit(self.provider_name).hostname not in {'localhost','127.0.0.1','::1'}:
            raise ValueError('External AI provider is unavailable in offline mode')
        key=os.getenv(self.config.api_key_env,'')
        if not key: raise ValueError('Configured AI key environment variable is missing')
        body=encoded({'model':self.model,'messages':[
            {'role':'system','content':INSTRUCTIONS},
            {'role':'user','content':json.dumps(evidence|{'required_output_schema':schema},ensure_ascii=False)}],
            'response_format':{'type':'json_schema','json_schema':{'name':'finding_triage','strict':True,'schema':schema}}})
        if len(body)>262144: raise ValueError('AI request exceeds total batch context budget')
        request=Request(self.provider_name+'/chat/completions',data=body,
            headers={'Content-Type':'application/json','Authorization':'Bearer '+key},method='POST')
        try:
            with build_opener(NoRedirect()).open(request,timeout=self.budget.provider_timeout) as response:
                raw=response.read(self.budget.max_response_bytes+1)
            if len(raw)>self.budget.max_response_bytes:
                raise ValueError('AI response exceeds size limit')
            # Prevent even a malicious server from echoing the key into output.
            raw=raw.replace(key.encode(),'[REDACTED_SECRET]'.encode())
            data=json.loads(raw)
            content=data['choices'][0]['message']['content']
            if not isinstance(content,str): raise ValueError('Invalid AI structured response')
            result=json.loads(content)
            def scrub(value):
                if isinstance(value,str): return value.replace(key,'[REDACTED_SECRET]')
                if isinstance(value,list): return [scrub(item) for item in value]
                if isinstance(value,dict): return {name:scrub(item) for name,item in value.items()}
                return value
            return scrub(result)
        except HTTPError:
            raise ValueError('AI provider HTTP error; no response body retained') from None
        except (TimeoutError,socket.timeout):
            raise ValueError('AI provider timeout') from None
        except URLError:
            raise ValueError('AI provider connection failed; credentials and response omitted') from None
        except (KeyError,TypeError,json.JSONDecodeError):
            raise ValueError('AI provider returned malformed structured JSON') from None
