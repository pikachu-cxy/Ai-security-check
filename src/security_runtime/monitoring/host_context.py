"""Bounded projection of already-read transcript items, never final model input."""
from collections import deque
import hashlib
import secrets


class VisibleContext:
    def __init__(self):
        self.rows = deque(maxlen=32)
        self.current = None
        self.sequence = 0
        self.seen = set()
        self.ids = deque(maxlen=1024)
        self.salt = secrets.token_bytes(32)
        self.omitted = 0

    def consume(self, row):
        payload = row.get('payload')
        if type(payload) is not dict:
            return
        if row.get('type') == 'turn_context':
            self.sequence += 1
            if len(self.rows) == self.rows.maxlen:
                self.omitted += 1
            self.current = dict(input_index=self.sequence, source='VISIBLE_TURN_CONTEXT',
                components={}, items=0, partial=False, final_model_input=False)
            self.rows.append(self.current)
            return
        if row.get('type') != 'response_item' or self.current is None:
            return
        identifier = payload.get('id')
        if type(identifier) is str and 0 < len(identifier) <= 256:
            opaque = hashlib.sha256(self.salt + identifier.encode('utf-8')).digest()
            if opaque in self.seen:
                return
            if len(self.ids) == self.ids.maxlen:
                self.seen.discard(self.ids.popleft())
            self.ids.append(opaque)
            self.seen.add(opaque)
        else:
            self.current['partial'] = True  # Replay/dedup identity is unavailable.
        kind, role = payload.get('type'), payload.get('role')
        category = None
        texts, media = [], 0
        if kind == 'message':
            category = {'user':'user_input','assistant':'assistant_history','system':'system_instructions',
                        'developer':'developer_instructions'}.get(role, 'unknown')
            content = payload.get('content')
            if type(content) is str:
                texts = [content]
            elif type(content) is list:
                if len(content) > 128:
                    self.current['partial'] = True
                for item in content[:128]:
                    if type(item) is dict and item.get('type') in {'input_text','output_text','text'} and type(item.get('text')) is str:
                        texts.append(item['text'])
                    else:
                        media += 1
                        self.current['partial'] = True
            else:
                self.current['partial'] = True
        elif kind in {'function_call_output','custom_tool_call_output'}:
            category = 'tool_results'
            if type(payload.get('output')) is str:
                texts = [payload['output']]
            else:
                self.current['partial'] = True
        elif kind in {'function_call','custom_tool_call'}:
            category = 'tool_call_arguments'
            field = 'arguments' if kind == 'function_call' else 'input'
            if type(payload.get(field)) is str:
                texts = [payload[field]]
            else:
                self.current['partial'] = True
        else:
            self.current['partial'] = True
        if category is not None:
            group = self.current['components'].setdefault(category, dict(text_bytes=0, items=0, media_parts=0))
            group['text_bytes'] += sum(len(value.encode('utf-8')) for value in texts)
            group['items'] += 1
            group['media_parts'] += media
            self.current['items'] += 1

    def view(self):
        return dict(status='PARTIAL' if self.rows else 'UNAVAILABLE',
            inputs=[dict(row, components=[dict(category=category, **value)
                for category,value in row['components'].items()]) for row in self.rows],
            omitted_inputs=self.omitted, scope='VISIBLE_TRANSCRIPT_SEGMENTS; NOT_FINAL_INPUT_OR_TOKEN_BREAKDOWN',
            request_usage_link='UNAVAILABLE', hidden_context='UNKNOWN',
            historical_carry_forward='UNKNOWN', server_compaction='UNKNOWN')
