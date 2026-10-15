import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock, patch

import discord
from aiohttp.test_utils import TestClient, TestServer

from core import Store, Windows, validate_config
from guard import Guard
from server import make_app


class CoreTests(unittest.TestCase):
    def test_window_boundary_and_isolation(self):
        w = Windows()
        self.assertFalse(w.hit("a", 8, 3, 0))
        self.assertFalse(w.hit("a", 8, 3, 1))
        self.assertTrue(w.hit("a", 8, 3, 2))
        self.assertFalse(w.hit("b", 8, 3, 2))
        self.assertFalse(w.hit("a", 8, 3, 10))

    def test_bounded_detection_memory(self):
        w = Windows(max_keys=10)
        for i in range(100):
            w.hit(i, 100, 3)
        self.assertEqual(len(w.items), 10)

    def test_config_rejects_invalid_values(self):
        for data in ({"enabled": "false"}, {"spam_limit": True}, {"spam_limit": 0},
                     {"unknown": 1}, {"log_channel_id": "abc"}, {"audit_seconds": 121}):
            with self.assertRaises(ValueError):
                validate_config(data)
        self.assertEqual(validate_config({"enabled": False}), {"enabled": False})

    def test_store_survives_restart_and_isolates_guilds(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "db"
            store = Store(path)
            store.put(1, "config", {"enabled": False})
            store.put(1, "lockdown", {"1:2": {"send_messages": None}})
            store.incident(1, "x", 2, "detail")
            sid = store.snapshot(1, {"roles": []})
            store.db.close()
            other = Store(path)
            self.assertFalse(other.config(1)["enabled"])
            self.assertTrue(other.config(2)["enabled"])
            self.assertTrue(other.get(1, "lockdown"))
            self.assertEqual(len(other.events(1)), 1)
            with self.assertRaises(ValueError):
                other.load_snapshot(2, sid)
            other.db.close()

    def test_snapshot_retention(self):
        store = Store(":memory:")
        for i in range(35):
            store.snapshot(1, {"i": i})
        self.assertEqual(len(store.snapshots(1)), 30)
        self.assertEqual(store.load_snapshot(1, store.snapshots(1)[0]["id"])["i"], 34)
        store.db.close()


class Role:
    def __init__(self, ident, position, **perms):
        self.id, self.position, self.name = ident, position, str(ident)
        self.permissions = discord.Permissions(**perms)
        self.managed = False
    def __lt__(self, other): return self.position < other.position
    def __ge__(self, other): return self.position >= other.position
    def is_default(self): return self.id == 1


class BotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store = Store(":memory:")
        self.bot = Guard(self.store)
        self.bot._connection.user = NS(id=999)
        self.bot.record = AsyncMock()
        self.guild = NS(id=1, owner_id=100, me=NS(top_role=Role(999, 100)), get_channel=lambda _: None)
        self.member = NS(id=10, top_role=Role(10, 5), roles=[Role(1, 0), Role(10, 5, administrator=True)],
                         timeout=AsyncMock(), remove_roles=AsyncMock(), bot=False)

    async def asyncTearDown(self):
        self.store.db.close()

    async def test_owner_and_higher_role_protected(self):
        self.member.id = 100
        await self.bot.contain(self.guild, self.member, "x", True)
        self.member.timeout.assert_not_called()
        self.member.id, self.member.top_role = 10, Role(20, 110)
        result = await self.bot.contain(self.guild, self.member, "x", True)
        self.assertIn("失敗", result)
        self.member.remove_roles.assert_not_called()

    async def test_containment_persists_removed_roles(self):
        await self.bot.contain(self.guild, self.member, "x", True)
        self.member.remove_roles.assert_awaited_once()
        self.member.timeout.assert_awaited_once()
        self.assertEqual(self.store.get(1, "removed:10")["roles"], ["10"])

    async def test_spam_threshold_and_delete(self):
        self.bot.contain = AsyncMock(return_value="timeout")
        msg = NS(guild=self.guild, author=self.member, mentions=[], role_mentions=[], mention_everyone=False,
                 id=1, delete=AsyncMock(), created_at=discord.utils.utcnow())
        for _ in range(5):
            await self.bot.check_message(msg)
        self.bot.contain.assert_not_called()
        await self.bot.check_message(msg)
        self.bot.contain.assert_awaited_once()
        msg.delete.assert_awaited_once()

    async def test_disabled_skips_detection(self):
        self.store.put(1, "config", {"enabled": False})
        self.bot.contain = AsyncMock()
        msg = NS(guild=self.guild, author=self.member, mention_everyone=True)
        await self.bot.check_message(msg)
        self.bot.contain.assert_not_called()

    async def test_everyone_mention_immediate(self):
        self.bot.contain = AsyncMock(return_value="ok")
        msg = NS(guild=self.guild, author=self.member, mentions=[], role_mentions=[], mention_everyone=True,
                 id=1, delete=AsyncMock(), created_at=discord.utils.utcnow())
        await self.bot.check_message(msg)
        self.bot.contain.assert_awaited_once()

    async def test_audit_mixed_actions_dedup_and_freeze(self):
        self.guild.fetch_member = AsyncMock(return_value=self.member)
        self.bot.contain = AsyncMock(return_value="removed")
        entries = [NS(id=i, guild=self.guild, user_id=10, action=NS(name=a))
                   for i, a in enumerate(["channel_delete", "role_delete", "ban"], 1)]
        await self.bot.on_audit_log_entry_create(entries[0])
        await self.bot.on_audit_log_entry_create(entries[0])  # duplicate cannot count
        await self.bot.on_audit_log_entry_create(entries[1])
        self.bot.contain.assert_not_called()
        await self.bot.on_audit_log_entry_create(entries[2])
        self.bot.contain.assert_awaited_once()
        self.assertTrue(self.store.get(1, "backup_frozen"))

    async def test_join_burst_restricts_prior_members_once(self):
        self.bot.contain = AsyncMock(return_value="timeout")
        self.store.put(1, "config", {"join_limit": 3})
        members = [NS(id=i, bot=False, guild=self.guild, joined_at=discord.utils.utcnow()) for i in range(11, 15)]
        self.guild.members = []
        for member in members[:3]:
            self.guild.members.append(member)
            await self.bot.on_member_join(member)
        self.assertEqual(self.bot.contain.await_count, 3)
        self.guild.members.append(members[3])
        await self.bot.on_member_join(members[3])
        self.assertEqual(self.bot.contain.await_count, 4)
        self.assertGreater(self.store.get(1, "join_hold_until"), time.time())

    async def test_dangerous_grants_are_reverted_at_threshold(self):
        self.store.put(1, "config", {"audit_limit": 1})
        self.guild.fetch_member = AsyncMock(return_value=self.member)
        role = Role(33, 6, administrator=True, manage_roles=True)
        role.edit = AsyncMock()
        self.guild.get_role = lambda _: role
        self.bot.contain = AsyncMock(return_value="removed")
        entry = NS(id=8, guild=self.guild, user_id=10, action=NS(name="role_update"),
                   target=NS(id=33), before=NS(permissions=discord.Permissions(manage_roles=True)),
                   after=NS(permissions=role.permissions))
        await self.bot.on_audit_log_entry_create(entry)
        role.edit.assert_awaited_once()
        fixed = role.edit.call_args.kwargs["permissions"]
        self.assertFalse(fixed.administrator)
        self.assertTrue(fixed.manage_roles)  # preexisting permissions remain

    async def test_restore_skips_channel_if_deny_target_missing(self):
        sid = self.store.snapshot(1, {"roles": [], "channels": [dict(id="3", name="private", type=0,
            category=None, position=0, overwrites=[dict(id="1000", role=False, allow=0, deny=1024)],
            topic=None, nsfw=False, slowmode=0, bitrate=64000, user_limit=0)]})
        self.guild.get_channel = lambda _: None
        self.guild.get_member = lambda _: None
        self.guild.create_text_channel = AsyncMock()
        results = await self.bot.restore(self.guild, sid)
        self.guild.create_text_channel.assert_not_called()
        self.assertIn("保留", results[0])

    async def test_restore_mapping_prevents_duplicate_roles(self):
        sid = self.store.snapshot(1, {"roles": [dict(id="5", name="team", permissions=0, colour=0,
            hoist=False, mentionable=False, position=1, default=False)], "channels": []})
        roles = {}
        self.guild.get_role = lambda rid: roles.get(rid)
        async def create(**kw):
            r = Role(123, 1)
            roles[123] = r
            return r
        self.guild.create_role = AsyncMock(side_effect=create)
        await self.bot.restore(self.guild, sid)
        await self.bot.restore(self.guild, sid)
        self.guild.create_role.assert_awaited_once()
        self.assertEqual(self.store.get(1, f"restore:{sid}"), {"5": "123"})

    async def test_lock_unlock_idempotent_and_restores_none(self):
        role = MagicMock(spec=discord.Role)
        role.id = 1
        role.permissions = discord.Permissions.none()
        channel = MagicMock(spec=discord.TextChannel)
        channel.id, channel.name = 2, "general"
        state = {}
        channel.overwrites = {}
        channel.overwrites_for.side_effect = lambda target: state.get(target.id, discord.PermissionOverwrite())
        async def set_permissions(target, *, overwrite, reason):
            state[target.id] = overwrite or discord.PermissionOverwrite()
        channel.set_permissions = AsyncMock(side_effect=set_permissions)
        self.guild.channels = [channel]
        self.guild.default_role = role
        self.guild.get_role = lambda rid: role if rid == 1 else None
        self.guild.get_member = lambda _: None
        await self.bot.lockdown(self.guild)
        self.assertFalse(state[1].send_messages)
        await self.bot.lockdown(self.guild)
        await self.bot.lockdown(self.guild, unlock=True)
        self.assertIsNone(state[1].send_messages)
        self.assertFalse(self.store.get(1, "lockdown"))


class WebTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store = Store(":memory:")
        self.bot = NS(is_ready=lambda: True, guilds=[], store=self.store)
        self.app = make_app(self.bot, "test-password-12345678", "http://guard.local")
        self.client = TestClient(TestServer(self.app))
        await self.client.start_server()
        self.headers = {"Host": "guard.local", "Origin": "http://guard.local"}

    async def asyncTearDown(self):
        await self.client.close()
        self.store.db.close()

    async def login(self):
        response = await self.client.post('/api/login', headers=self.headers, json={"password": "test-password-12345678"})
        self.assertEqual(response.status, 200)
        return response.cookies['rg_session'].value, (await response.json())["csrf"]

    async def test_no_auth_no_access(self):
        response = await self.client.get('/api/me', headers=self.headers)
        self.assertEqual(response.status, 401)

    async def test_host_and_cross_origin_rejected(self):
        response = await self.client.get('/api/me')
        self.assertEqual(response.status, 403)
        response = await self.client.post('/api/login', headers={"Host": "guard.local", "Origin": "http://evil.local"}, json={"password": "test-password-12345678"})
        self.assertEqual(response.status, 403)

    async def test_login_cookie_csrf_and_logout(self):
        token, csrf = await self.login()
        headers = self.headers | {"Cookie": f"rg_session={token}"}
        response = await self.client.get('/api/me', headers=headers)
        self.assertEqual(response.status, 200)
        response = await self.client.post('/api/logout', headers=headers, json={})
        self.assertEqual(response.status, 403)
        response = await self.client.post('/api/logout', headers=headers | {"X-CSRF-Token": csrf}, json={})
        self.assertEqual(response.status, 200)
        response = await self.client.get('/api/me', headers=headers)
        self.assertEqual(response.status, 401)

    async def test_wrong_password_and_rate_limit(self):
        for _ in range(10):
            response = await self.client.post('/api/login', headers=self.headers, json={"password": "wrong"})
            self.assertEqual(response.status, 401)
        response = await self.client.post('/api/login', headers=self.headers, json={"password": "wrong"})
        self.assertEqual(response.status, 429)

    async def test_static_has_security_headers(self):
        response = await self.client.get('/', headers=self.headers)
        self.assertEqual(response.status, 200)
        self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
        self.assertEqual(response.headers['Cache-Control'], 'no-store')

    async def test_unauthenticated_mutation_rejected(self):
        response = await self.client.put('/api/guilds/1/settings', headers=self.headers, json={"enabled": False})
        self.assertEqual(response.status, 401)
        self.assertTrue(self.store.config(1)["enabled"])


if __name__ == '__main__':
    unittest.main()
