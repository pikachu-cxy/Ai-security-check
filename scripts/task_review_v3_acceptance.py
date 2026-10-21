"""Real v3 API navigation for acceptance drivers, without production imports."""

TASK_TOOLS = frozenset({'begin_security_task', 'finish_security_task',
    'prepare_task_security_review', 'get_task_review_plan', 'get_task_review_method',
    'read_task_review_context', 'submit_task_review_batch',
    'submit_task_security_review', 'get_task_security_review'})


def require_v3(info, tools):
    assert TASK_TOOLS <= set(tools), 'The connected Runtime lacks v3 task tools'
    feature = info['features']['task_security_review_protocol']
    assert 'task-review-plan-v3' in feature and 'ONLY_V3' in feature


class V3Review:
    def __init__(self, call, task_ref, session, workspace):
        self.call, self.task_ref, self.session = call, task_ref, session
        self.workspace = str(workspace)
        self.sources, self.units, self.deliveries = {}, {}, []

    async def _call(self, tool, **arguments):
        return await self.call(tool, task_ref=self.task_ref,
                               workspace_path=self.workspace, **arguments)

    async def plan(self):
        """Read all navigation fragments; this alone supplies no source proof."""
        units, cursor = {}, 0
        while True:
            page = await self._call('get_task_review_plan', review_session=self.session,
                                    cursor=cursor, limit=5)
            assert page['protocol_version'] == 3
            self.sources.update((source['source_ref'], source) for source in page['sources'])
            for item in page['units']:
                unit = units.setdefault(item['unit_id'], dict(item, required_windows=[]))
                unit['required_windows'].extend(item['required_windows'])
            cursor = page['next_cursor']
            if cursor is None:
                self.units = units
                return list(units.values())

    async def read(self, path, start_line=1, end_line=None, *, source_version='CURRENT'):
        """Use actual IDs, bounded requests and the Runtime's source dictionary."""
        versions = {'CURRENT_TASK_END'} if source_version == 'CURRENT' else {'BEFORE_TASK', 'BEFORE_DELETION'}
        binding = next((item for item in self.sources.values()
                        if item['path'] == path and item['location_version'] in versions), {})
        total = binding.get('total_lines')
        target = min(end_line, total) if end_line is not None and total is not None else end_line or total
        cursor, identifiers = start_line, []
        while target is None or cursor <= target:
            high = min(cursor + 79, target) if target is not None else cursor + 79
            pending = [[cursor, high]]
            while pending:
                low, last = pending.pop(0)
                packet = await self._call('read_task_review_context', review_session=self.session,
                    file_path=path, start_line=low, end_line=last, source_version=source_version)
                self.deliveries.append(packet)
                if packet.get('source'):
                    source = packet['source']
                    self.sources[source['source_ref']] = source
                    total = source.get('total_lines', total)
                if packet.get('status') == 'ALREADY_DELIVERED':
                    assert packet['source_lines_delivered'] == 0 and packet['evidence_refs']
                    identifiers.extend(packet['evidence_refs'])
                else:
                    assert packet['evidence_id'] and packet['lines']
                    assert len(packet['lines']) <= 80
                    identifiers.append(packet['evidence_id'])
                    if total is None and len(packet['lines']) < last-low+1 and not packet.get('next_range'):
                        total = packet['start_line'] + len(packet['lines']) - 1
                if total is not None:
                    target = min(end_line, total) if end_line is not None else total
                assert target is not None, 'The Runtime did not establish a finite source range'
                following = ([packet['next_range']] if packet.get('next_range') else [])
                following.extend(packet.get('unread_ranges', []))
                for first, final in following:
                    if first <= target:
                        pending.append([first, min(final, target)])
            cursor = high + 1
        assert identifiers
        return list(dict.fromkeys(identifiers))

    async def history(self, *, completion_revision=None):
        """Read history quietly or explicitly deliver the saved terminal revision."""
        pages, offset = [], 0
        while True:
            arguments = dict(finding_offset=offset, finding_limit=3)
            if completion_revision is not None:
                arguments['completion_revision'] = completion_revision
            page = await self._call('get_task_security_review', **arguments)
            assert page['protocol_version'] == 3
            if completion_revision is None:
                assert page['history_read_only'] and not page['risk_choices']
            else:
                assert page['delivery_read_only'] and page['completion_revision'] == completion_revision
            pages.append(page)
            offset = page['finding_page']['next_offset']
            if offset is None:
                return pages

    async def save_partial(self, findings, limitations, *, risk_resolutions=None):
        """A fixture can record partial work, never claim observed host reasoning."""
        assert limitations
        for unit in await self.plan():
            # Partial host reasoning does not excuse readable source obligations.
            for window in unit['required_windows']:
                source = self.sources[window['source_ref']]
                version = 'CURRENT' if source['location_version'] == 'CURRENT_TASK_END' else 'BEFORE_TASK'
                await self.read(source['path'], window['start_line'], window['end_line'], source_version=version)
            batch = await self._call('submit_task_review_batch', review_session=self.session,
                unit_ids=[unit['unit_id']], coverage='PARTIAL', limitations=limitations)
            assert batch['status'] == 'BATCH_RECORDED' and not batch['scanner_run']
        arguments = dict(review_session=self.session, findings=findings,
                         coverage='PARTIAL', limitations=limitations)
        if risk_resolutions is not None:
            arguments['risk_resolutions'] = risk_resolutions
        receipt = await self._call('submit_task_security_review', **arguments)
        assert receipt['status'] == 'COMPLETE' and receipt['result_details_required']
        pages = await self.history(completion_revision=receipt['next_action']['completion_revision'])
        assert pages[0]['host_review']['coverage'] == 'PARTIAL'
        return receipt, pages
