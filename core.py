"""Persistent state and bounded sliding-window detection. No Discord credentials here."""
import json
import sqlite3
import time
from collections import OrderedDict, deque
from pathlib import Path

DEFAULTS = dict(enabled=True, spam_limit=6, spam_seconds=8, mention_limit=8,
                timeout_minutes=10, join_limit=10, join_seconds=15,
                join_hold_minutes=10, audit_limit=3, audit_seconds=15,
                block_bots=False, block_webhooks=False, log_channel_id="")
RANGES = dict(spam_limit=(3, 50), spam_seconds=(3, 120), mention_limit=(3, 100),
              timeout_minutes=(1, 1440), join_limit=(3, 100), join_seconds=(5, 120),
              join_hold_minutes=(1, 60), audit_limit=(1, 20), audit_seconds=(5, 120))


def validate_config(data):
    if not isinstance(data, dict) or set(data) - set(DEFAULTS):
        raise ValueError("不明な設定項目があります")
    for key, value in data.items():
        if key in RANGES:
            lo, hi = RANGES[key]
            if type(value) is not int or not lo <= value <= hi:
                raise ValueError(f"{key}: {lo}〜{hi}の整数が必要です")
        elif key == "log_channel_id":
            if not isinstance(value, str) or (value and (not value.isdecimal() or len(value) > 20)):
                raise ValueError("通知チャンネルIDが不正です")
        elif type(value) is not bool:
            raise ValueError(f"{key}: 真偽値が必要です")
    return data


class Windows:
    def __init__(self, max_keys=20000):
        self.items = OrderedDict()
        self.max_keys = max_keys

    def hit(self, key, seconds, limit, now=None):
        now = time.monotonic() if now is None else now
        q = self.items.pop(key, deque(maxlen=200))
        while q and q[0] <= now - seconds:
            q.popleft()
        q.append(now)
        self.items[key] = q
        while len(self.items) > self.max_keys:
            self.items.popitem(last=False)
        return len(q) >= limit


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS kv (guild TEXT, key TEXT, value TEXT, PRIMARY KEY(guild,key));
        CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY, guild TEXT, at REAL, kind TEXT, actor TEXT, detail TEXT);
        CREATE TABLE IF NOT EXISTS snapshots (id INTEGER PRIMARY KEY, guild TEXT, at REAL, data TEXT);
        ''')

    def get(self, guild, key, default=None):
        row = self.db.execute("SELECT value FROM kv WHERE guild=? AND key=?", (str(guild), key)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, guild, key, value):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO kv VALUES (?,?,?)", (str(guild), key, json.dumps(value)))

    def config(self, guild):
        return DEFAULTS | self.get(guild, "config", {})

    def incident(self, guild, kind, actor, detail):
        with self.db:
            self.db.execute("INSERT INTO incidents(guild,at,kind,actor,detail) VALUES (?,?,?,?,?)",
                            (str(guild), time.time(), kind, str(actor), detail[:8000]))
            self.db.execute("DELETE FROM incidents WHERE guild=? AND id NOT IN (SELECT id FROM incidents WHERE guild=? ORDER BY id DESC LIMIT 3000)", (str(guild), str(guild)))

    def events(self, guild):
        return [dict(r) for r in self.db.execute("SELECT * FROM incidents WHERE guild=? ORDER BY id DESC LIMIT 100", (str(guild),))]

    def snapshot(self, guild, data):
        with self.db:
            cur = self.db.execute("INSERT INTO snapshots(guild,at,data) VALUES (?,?,?)", (str(guild), time.time(), json.dumps(data)))
            self.db.execute("DELETE FROM snapshots WHERE guild=? AND id NOT IN (SELECT id FROM snapshots WHERE guild=? ORDER BY id DESC LIMIT 30)", (str(guild), str(guild)))
        return cur.lastrowid

    def snapshots(self, guild):
        return [dict(r) for r in self.db.execute("SELECT id,at FROM snapshots WHERE guild=? ORDER BY id DESC", (str(guild),))]

    def load_snapshot(self, guild, sid):
        row = self.db.execute("SELECT data FROM snapshots WHERE id=? AND guild=?", (sid, str(guild))).fetchone()
        if not row:
            raise ValueError("バックアップがありません")
        return json.loads(row[0])
