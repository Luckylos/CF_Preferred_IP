#!/usr/bin/env python3
"""通过真实interface验证发现延迟、失败计数、队列裁剪与请求选择。"""
from datetime import datetime
from pathlib import Path
import tempfile
import unittest

from admission import maintain_queue, process_screen, select_candidates
from test_cycle_admission import sandbox

NOW = datetime(2026, 8, 24, 10)


class QueueCase(unittest.TestCase):
    def setUp(self):
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.tmp = Path(holder.name)

    def write(self, name, text=''):
        path = self.tmp/name
        path.write_text(text)
        return path

    def maintain(self, text, excluded=None, limit=180):
        queue = self.write('queue', text)
        maintain_queue(queue, NOW, 24, limit, excluded=excluded)
        return queue

    def screen(self, queue, requested='', passed=''):
        pool = self.write('pool')
        process_screen(pool, self.write('requested', requested), self.write('passed', passed),
                       queue, self.tmp/'quality', NOW, 150, 3)
        return queue.read_text()


class LatencyFieldFlowTests(QueueCase):
    def test_scan_latency_ttl_prune_keeps_latency(self):
        queue = self.maintain('2026-08-24 09:00:00\t10.100.0.1\t0\t42.5\n'
                              '2026-08-24 09:00:00\t10.100.0.2\t2\t61.0\n')
        self.assertEqual([line.split('\t')[3] for line in queue.read_text().splitlines()], ['42.5', '61.0'])

    def test_legacy_rows_survive_with_empty_latency(self):
        queue = self.maintain('2026-08-24 09:00:00\t10.100.0.1\t0\n'
                              '2026-08-24 09:00:00\t10.100.0.2\n')
        self.assertEqual(queue.read_text(), '2026-08-24 09:00:00\t10.100.0.1\t0\t\n'
                                            '2026-08-24 09:00:00\t10.100.0.2\t0\t\n')

    def test_slow_maintenance_keeps_latency(self):
        excluded = self.write('excluded')
        original = '2026-08-24 09:00:00\t10.100.0.1\t1\t47.3\n'
        queue = self.maintain(original, excluded=excluded)
        self.assertEqual(queue.read_text(), original)

    def test_slow_maintenance_respects_cooldown(self):
        excluded = self.write('excluded', '10.100.0.2\n')
        queue = self.maintain('2026-08-24 09:00:00\t10.100.0.1\t0\t40.0\n'
                              '2026-08-24 09:00:00\t10.100.0.2\t0\t50.0\n', excluded=excluded)
        self.assertEqual(queue.read_text(), '2026-08-24 09:00:00\t10.100.0.1\t0\t40.0\n')

    def test_screen_writeback_keeps_latency(self):
        queue = self.write('queue', '2026-08-24 09:00:00\t10.100.0.1\t0\t40.0\n'
                                    '2026-08-24 09:00:00\t10.100.0.2\t0\t55.5\n'
                                    '2026-08-24 09:00:00\t10.100.0.3\t1\t66.6\n')
        result = self.screen(queue, '10.100.0.1\n10.100.0.2\n', '10.100.0.1\n')
        self.assertEqual(result, '2026-08-24 09:00:00\t10.100.0.2\t1\t55.5\n'
                                 '2026-08-24 09:00:00\t10.100.0.3\t1\t66.6\n')

    def test_latency_survives_maintenance_selection_and_writeback(self):
        original = '2026-08-24 09:00:00\t10.100.0.1\t0\t44.4\n'
        queue = self.maintain(original)
        excluded = self.write('excluded')
        maintain_queue(queue, NOW, 24, 180, excluded=excluded)
        pool = self.write('pool')
        requested = self.tmp/'requested'
        select_candidates(pool, queue, excluded, requested, 150, 20)
        process_screen(pool, requested, self.write('passed'), queue, self.tmp/'quality', NOW, 150, 3)
        self.assertEqual(queue.read_text(), '2026-08-24 09:00:00\t10.100.0.1\t1\t44.4\n')


class QueueEvictionTests(QueueCase):
    def test_overflow_keeps_newest_candidates(self):
        queue = self.maintain('2026-08-24 01:00:00\t10.100.0.1\t0\t41\n'
                              '2026-08-24 02:00:00\t10.100.0.2\t0\t42\n'
                              '2026-08-24 09:00:00\t10.100.0.3\t0\t43\n', limit=2)
        self.assertEqual(queue.read_text(), '2026-08-24 02:00:00\t10.100.0.2\t0\t42\n'
                                            '2026-08-24 09:00:00\t10.100.0.3\t0\t43\n')

    def test_eviction_restores_ascending_order_on_disk(self):
        queue = self.maintain('2026-08-24 03:00:00\t10.100.0.3\t0\t43\n'
                              '2026-08-24 01:00:00\t10.100.0.1\t0\t41\n'
                              '2026-08-24 02:00:00\t10.100.0.2\t0\t42\n', limit=3)
        self.assertEqual([line.split('\t')[1] for line in queue.read_text().splitlines()],
                         ['10.100.0.1', '10.100.0.2', '10.100.0.3'])

    def test_eviction_preserves_latency_column(self):
        queue = self.maintain('2026-08-24 01:00:00\t10.100.0.1\t0\t41.5\n'
                              '2026-08-24 02:00:00\t10.100.0.2\t0\t42.5\n', limit=1)
        self.assertEqual(queue.read_text(), '2026-08-24 02:00:00\t10.100.0.2\t0\t42.5\n')

    def test_screen_selection_is_independent_of_disk_order(self):
        queue = self.write('queue', '2026-08-24 09:00:00\t10.100.0.2\t2\t40\n'
                                    '2026-08-24 08:00:00\t10.100.0.1\t0\t50\n')
        chosen = select_candidates(self.write('pool'), queue, self.write('excluded'),
                                    self.tmp/'requested', 150, 20)
        self.assertEqual(chosen, ['10.100.0.1', '10.100.0.2'])


class ScreenWritebackPreconditionTests(QueueCase):
    def test_failed_screen_execution_does_not_writeback_partial_pass(self):
        sb = sandbox(self.tmp, rc=75)
        before = (sb.sb/'discovered_ips.tsv').read_bytes()
        result = sb.run('slow')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((sb.sb/'discovered_ips.tsv').read_bytes(), before)
        self.assertEqual(len([line for line in (sb.sb/'contenders.tsv').read_text().splitlines()
                              if line and not line.startswith('#')]), 4)

    def test_empty_request_keeps_queue(self):
        original = '2026-08-24 09:00:00\t10.100.0.1\t0\t44.4\n'
        queue = self.write('queue', original)
        self.assertEqual(self.screen(queue), original)
