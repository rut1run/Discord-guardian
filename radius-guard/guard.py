import asyncio
import datetime as dt
import logging
import time
from collections import OrderedDict, defaultdict, deque

import discord
from discord import app_commands
from discord.ext import tasks

from core import Windows

LOG = logging.getLogger("guard")
DANGEROUS = ("administrator", "manage_guild", "manage_roles", "manage_channels",
             "ban_members", "kick_members", "manage_webhooks", "moderate_members")
SEND_FLAGS = ("send_messages", "send_messages_in_threads", "create_public_threads",
              "create_private_threads", "add_reactions", "connect", "speak")
SUPPORTED_CHANNELS = (discord.CategoryChannel, discord.TextChannel, discord.VoiceChannel)


def dangerous(permissions):
    return any(getattr(permissions, p, False) for p in DANGEROUS)


class Guard(discord.Client):
    def __init__(self, store):
        intents = discord.Intents.none()
        intents.guilds = intents.members = intents.moderation = True
        intents.guild_messages = intents.message_content = True
        super().__init__(intents=intents, allowed_mentions=discord.AllowedMentions.none(),
                         max_messages=2000)
        self.store = store
        self.tree = app_commands.CommandTree(self)
        self.windows = Windows()
        self.seen_audit = OrderedDict()
        self.locks = defaultdict(asyncio.Lock)
        self.actor_locks = defaultdict(asyncio.Lock)
        self.pending = set()
        self.join_treated = OrderedDict()
        self.recent_grants = OrderedDict()
        self.last_backup = {}
        self.register_commands()

    async def setup_hook(self):
        # Guild-scoped commands keep installation immediate and avoid global propagation delays.
        self.maintenance.start()

    async def close(self):
        self.maintenance.cancel()
        await super().close()

    async def on_ready(self):
        LOG.info("Bot connected; %s servers", len(self.guilds))
        for g in self.guilds:
            try:
                self.tree.copy_global_to(guild=g)
                await self.tree.sync(guild=g)
                if not self.store.snapshots(g.id):
                    await self.backup(g)
            except discord.HTTPException:
                LOG.exception("Initialization failed for server %s", g.id)

    async def on_guild_join(self, guild):
        self.tree.copy_global_to(guild=guild)
        await self.tree.sync(guild=guild)
        await self.backup(guild)

    async def record(self, guild, kind, actor, detail):
        self.store.incident(guild.id, kind, actor, detail)
        cid = self.store.config(guild.id)["log_channel_id"]
        channel = guild.get_channel(int(cid)) if cid else None
        if isinstance(channel, discord.TextChannel):
            try:
                await channel.send(f"**{kind}**\n対象ID: `{actor}`\n{discord.utils.escape_markdown(detail)[:1700]}")
            except discord.HTTPException:
                LOG.warning("Cannot send security notification to %s", cid)

    def exempt(self, guild, member):
        return member.id in (guild.owner_id, self.user.id)

    async def contain(self, guild, member, reason, strip=False):
        if self.exempt(guild, member):
            return "所有者・保護Bot自身は操作できません"
        if member.top_role >= guild.me.top_role:
            return "対処失敗: Botより上位または同順位のロールです"
        result = []
        if strip:
            roles = [r for r in member.roles if not r.is_default() and not r.managed
                     and dangerous(r.permissions) and r < guild.me.top_role]
            # Write ahead: keep recovery evidence even if the API call fails partway.
            self.store.put(guild.id, f"removed:{member.id}",
                           dict(at=time.time(), roles=[str(r.id) for r in roles], reason=reason))
            for role in roles:
                try:
                    await member.remove_roles(role, reason=f"Radius Guard: {reason}")
                    result.append(f"権限解除: {role.name}")
                except discord.HTTPException as e:
                    result.append(f"権限解除失敗 {role.id}: HTTP {e.status}")
        try:
            minutes = self.store.config(guild.id)["timeout_minutes"]
            await member.timeout(dt.timedelta(minutes=minutes), reason=f"Radius Guard: {reason}")
            result.append(f"{minutes}分タイムアウト")
        except discord.HTTPException as e:
            result.append(f"タイムアウト失敗: HTTP {e.status}")
        return " / ".join(result)

    async def on_message(self, message):
        if not message.guild or message.author.bot or message.webhook_id:
            return
        await self.check_message(message)

    async def on_message_edit(self, before, after):
        if after.guild and not after.author.bot and before.content != after.content:
            await self.check_message(after)

    async def check_message(self, message):
        g, m = message.guild, message.author
        cfg = self.store.config(g.id)
        if not cfg["enabled"] or self.exempt(g, m):
            return
        spam = self.windows.hit(("spam", g.id, m.id), cfg["spam_seconds"], cfg["spam_limit"])
        mentions = len(set(u.id for u in message.mentions)) + len(set(r.id for r in message.role_mentions))
        if not spam and mentions < cfg["mention_limit"] and not message.mention_everyone:
            return
        key = (g.id, m.id)
        if key in self.pending:
            try:
                await message.delete()
            except discord.HTTPException:
                pass
            return
        self.pending.add(key)
        try:
            reason = "連投" if spam else "大量メンション"
            # Respond before deletion/history work to reduce the time to containment.
            outcome = await self.contain(g, m, reason)
            deleted = 0
            candidates = [x for x in (self.cached_messages or []) if x.guild and x.guild.id == g.id
                          and x.author.id == m.id and (discord.utils.utcnow() - x.created_at).total_seconds() < 60]
            if all(x.id != message.id for x in candidates):
                candidates.append(message)
            for item in candidates[-30:]:
                try:
                    await item.delete()
                    deleted += 1
                except discord.HTTPException:
                    pass
            await self.record(g, reason, m.id, f"{outcome} / メッセージ{deleted}件削除")
        finally:
            self.pending.discard(key)

    async def on_member_join(self, member):
        g, cfg = member.guild, self.store.config(member.guild.id)
        if member.bot or not cfg["enabled"]:
            return
        burst = self.windows.hit(("join", g.id), cfg["join_seconds"], cfg["join_limit"])
        if burst:
            self.store.put(g.id, "join_hold_until", time.time() + cfg["join_hold_minutes"] * 60)
        if self.store.get(g.id, "join_hold_until", 0) <= time.time():
            return
        targets = [member]
        if burst:
            cutoff = discord.utils.utcnow() - dt.timedelta(seconds=cfg["join_seconds"])
            targets = [m for m in g.members if not m.bot and m.joined_at and m.joined_at >= cutoff]
        for target in targets:
            key = (g.id, target.id)
            if self.join_treated.get(key, 0) > time.monotonic():
                continue
            self.join_treated[key] = time.monotonic() + cfg["timeout_minutes"] * 60
            if len(self.join_treated) > 20000:
                self.join_treated.popitem(last=False)
            result = await self.contain(g, target, "大量入室")
            await self.record(g, "大量入室", target.id, result)

    async def on_audit_log_entry_create(self, entry):
        if entry.id in self.seen_audit:
            return
        self.seen_audit[entry.id] = True
        if len(self.seen_audit) > 10000:
            self.seen_audit.popitem(last=False)
        g, actor_id = entry.guild, entry.user_id
        cfg = self.store.config(g.id)
        if not cfg["enabled"] or not actor_id or actor_id in (g.owner_id, self.user.id):
            return
        action = entry.action.name
        # Combine destructive actions so alternating delete/ban/kick cannot evade thresholds.
        destructive = action in {"channel_delete", "role_delete", "ban", "kick"}
        escalation = False
        if action == "role_update":
            p = getattr(entry.after, "permissions", None)
            before = getattr(entry.before, "permissions", None) or discord.Permissions.none()
            escalation = p is not None and any(getattr(p, x) and not getattr(before, x) for x in DANGEROUS)
        if action == "member_role_update":
            escalation = any(dangerous(r.permissions) for r in getattr(entry.after, "roles", []) if hasattr(r, "permissions"))
        if escalation:
            key = (g.id, actor_id)
            q = self.recent_grants.pop(key, deque(maxlen=100))
            now = time.monotonic()
            while q and q[0][0] < now - cfg["audit_seconds"]:
                q.popleft()
            q.append((now, entry))
            self.recent_grants[key] = q
            if len(self.recent_grants) > 2000:
                self.recent_grants.popitem(last=False)
        forbidden = (action == "bot_add" and cfg["block_bots"]) or (action == "webhook_create" and cfg["block_webhooks"])
        hit = (destructive or escalation) and self.windows.hit(("audit", g.id, actor_id), cfg["audit_seconds"], cfg["audit_limit"])
        if not hit and not forbidden:
            if destructive or escalation:
                await self.record(g, "管理操作の監視", actor_id, f"{action} / 閾値未満")
            return
        # Freeze scheduled snapshots until the administrator explicitly resumes them.
        self.store.put(g.id, "backup_frozen", True)
        async with self.actor_locks[(g.id, actor_id)]:
            try:
                actor = await g.fetch_member(actor_id)
            except discord.HTTPException:
                actor = None
            outcome = await self.contain(g, actor, "管理操作の異常", strip=True) if actor else "実行者を取得できません"
            cleanup = []
            grants = self.recent_grants.pop((g.id, actor_id), [])
            for at, grant in reversed(grants):
                if at < time.monotonic() - cfg["audit_seconds"]:
                    continue
                try:
                    if grant.action.name == "role_update":
                        role = g.get_role(grant.target.id)
                        if role and role < g.me.top_role and not role.managed:
                            p = discord.Permissions(role.permissions.value)
                            old = getattr(grant.before, "permissions", None) or discord.Permissions.none()
                            new = getattr(grant.after, "permissions", None)
                            if new:
                                for flag in DANGEROUS:
                                    if getattr(new, flag) and not getattr(old, flag):
                                        setattr(p, flag, False)
                                await role.edit(permissions=p, reason="Radius Guard: 危険な権限付与の取消")
                                cleanup.append(f"危険な権限を取消: {role.id}")
                    elif grant.action.name == "member_role_update":
                        target = await g.fetch_member(grant.target.id)
                        if not self.exempt(g, target) and target.top_role < g.me.top_role:
                            for added in getattr(grant.after, "roles", []):
                                role = g.get_role(added.id)
                                if role and dangerous(role.permissions) and not role.managed and role < g.me.top_role:
                                    await target.remove_roles(role, reason="Radius Guard: 危険な権限付与の取消")
                                    cleanup.append(f"付与ロールを取消: {target.id}/{role.id}")
                except discord.HTTPException as e:
                    cleanup.append(f"権限取消失敗: HTTP {e.status}")
            if forbidden:
                try:
                    if action == "bot_add":
                        target = await g.fetch_member(entry.target.id)
                        if target.top_role < g.me.top_role and not self.exempt(g, target):
                            await target.kick(reason="Radius Guard: Bot追加禁止")
                            cleanup.append("追加Botを退出")
                        else:
                            cleanup.append("追加Botの退出失敗: ロール順位")
                    else:
                        for hook in await g.webhooks():
                            if hook.id == entry.target.id:
                                await hook.delete(reason="Radius Guard: Webhook追加禁止")
                                cleanup.append("Webhookを削除")
                except discord.HTTPException as e:
                    cleanup.append(f"追加物の削除失敗: HTTP {e.status}")
            await self.record(g, "管理荒らし検知", actor_id, f"{action} / {outcome} / {' / '.join(cleanup)}")

    async def backup(self, guild):
        data = {"roles": [], "channels": []}
        for r in guild.roles:
            if r.managed:
                continue
            data["roles"].append(dict(id=str(r.id), name=r.name, permissions=r.permissions.value,
                                      colour=r.colour.value, hoist=r.hoist, mentionable=r.mentionable,
                                      position=r.position, default=r.is_default()))
        for c in guild.channels:
            if not isinstance(c, SUPPORTED_CHANNELS):
                continue
            overwrites = []
            for target, overwrite in c.overwrites.items():
                allow, deny = overwrite.pair()
                overwrites.append(dict(id=str(target.id), role=isinstance(target, discord.Role),
                                       allow=allow.value, deny=deny.value))
            data["channels"].append(dict(id=str(c.id), name=c.name, type=c.type.value,
                category=str(c.category_id) if c.category_id else None, position=c.position,
                overwrites=overwrites, topic=getattr(c, "topic", None), nsfw=getattr(c, "nsfw", False),
                slowmode=getattr(c, "slowmode_delay", 0), bitrate=getattr(c, "bitrate", 64000),
                user_limit=getattr(c, "user_limit", 0)))
        sid = self.store.snapshot(guild.id, data)
        self.last_backup[guild.id] = time.monotonic()
        return sid

    async def restore(self, guild, sid):
        """Recreate missing entities only. Persist remaps immediately for resumable retries."""
        data = self.store.load_snapshot(guild.id, sid)
        mapping = self.store.get(guild.id, f"restore:{sid}", {})
        created_roles, created_channels = {}, {}
        results = []
        def resolve(old):
            return int(mapping.get(str(old), old))
        def checkpoint(old, new):
            mapping[str(old)] = str(new)
            self.store.put(guild.id, f"restore:{sid}", mapping)
        for r in sorted(data["roles"], key=lambda x: x["position"]):
            if r["default"] or guild.get_role(resolve(r["id"])):
                continue
            try:
                # Recreated roles deliberately have no members; a human reassigns them after verification.
                created = await guild.create_role(name=r["name"], permissions=discord.Permissions(r["permissions"]),
                    colour=discord.Colour(r["colour"]), hoist=r["hoist"], mentionable=r["mentionable"], reason="Radius Guard: 復旧")
                checkpoint(r["id"], created.id)
                created_roles[created.id] = created
                results.append(f"ロール作成: {r['name']}")
            except discord.HTTPException as e:
                results.append(f"ロール失敗 {r['name']}: HTTP {e.status}")
        for c in sorted(data["channels"], key=lambda x: (x["type"] != 4, x["position"])):
            if guild.get_channel(resolve(c["id"])):
                continue
            try:
                overwrites, missing = {}, []
                for ow in c["overwrites"]:
                    target = (created_roles.get(resolve(ow["id"])) or guild.get_role(resolve(ow["id"]))) if ow["role"] else guild.get_member(int(ow["id"]))
                    if target:
                        overwrites[target] = discord.PermissionOverwrite.from_pair(discord.Permissions(ow["allow"]), discord.Permissions(ow["deny"]))
                    else:
                        missing.append(ow["id"])
                if missing:
                    results.append(f"チャンネル保留 {c['name']}: 権限対象のロール・メンバーが見つかりません")
                    continue
                category = (created_channels.get(resolve(c["category"])) or guild.get_channel(resolve(c["category"]))) if c["category"] else None
                if c["category"] and not isinstance(category, discord.CategoryChannel):
                    results.append(f"チャンネル保留 {c['name']}: カテゴリ未復旧")
                    continue
                kw = dict(name=c["name"], overwrites=overwrites, position=c["position"], reason="Radius Guard: 復旧")
                if c["type"] == 4:
                    created = await guild.create_category(**kw)
                elif c["type"] in (0, 5):
                    created = await guild.create_text_channel(**kw, category=category, topic=c["topic"], nsfw=c["nsfw"], slowmode_delay=c["slowmode"])
                elif c["type"] == 2:
                    created = await guild.create_voice_channel(**kw, category=category, bitrate=min(c["bitrate"], guild.bitrate_limit), user_limit=c["user_limit"])
                else:
                    continue
                checkpoint(c["id"], created.id)
                created_channels[created.id] = created
                results.append(f"チャンネル作成: {c['name']}")
            except discord.HTTPException as e:
                results.append(f"チャンネル失敗 {c['name']}: HTTP {e.status}")
        await self.record(guild, "復旧", "管理者", "\n".join(results) or "不足している構成はありません")
        return results

    async def lockdown(self, guild, unlock=False):
        saved = self.store.get(guild.id, "lockdown", {})
        results = []
        for c in guild.channels:
            if not isinstance(c, SUPPORTED_CHANNELS) or isinstance(c, discord.CategoryChannel):
                continue
            if unlock:
                targets = [(target_id, flags) for key, flags in saved.items()
                           for cid, target_id in [key.split(":")] if cid == str(c.id)]
            else:
                targets = [(str(x.id), None) for x in {guild.default_role, *c.overwrites.keys()}
                           if not isinstance(x, discord.Role) or not x.permissions.administrator]
            for target_id, old_flags in targets:
                key = f"{c.id}:{target_id}"
                target = guild.get_role(int(target_id)) or guild.get_member(int(target_id))
                if not target:
                    results.append(f"対象不明: {key}")
                    continue
                ow = c.overwrites_for(target)
                if not unlock:
                    # Repeated lock never replaces the original state.
                    if key not in saved:
                        saved[key] = {flag: getattr(ow, flag) for flag in SEND_FLAGS}
                        self.store.put(guild.id, "lockdown", saved)
                    for flag in SEND_FLAGS:
                        setattr(ow, flag, False)
                else:
                    for flag, value in old_flags.items():
                        # Preserve intervening administrator edits to non-lock values.
                        if getattr(ow, flag) is False:
                            setattr(ow, flag, value)
                try:
                    await c.set_permissions(target, overwrite=None if ow.is_empty() else ow, reason="Radius Guard: 緊急ロック解除" if unlock else "Radius Guard: 緊急ロック")
                    if unlock:
                        saved.pop(key, None)
                        self.store.put(guild.id, "lockdown", saved)
                except discord.HTTPException as e:
                    results.append(f"{c.name} / {target_id}: HTTP {e.status}")
        await self.record(guild, "緊急ロック解除" if unlock else "緊急ロック", "管理者", "\n".join(results) or "処理完了（管理者・Webhookは制限対象外）")
        return results

    @tasks.loop(minutes=5)
    async def maintenance(self):
        for g in self.guilds:
            if self.store.get(g.id, "backup_frozen", False) or self.store.get(g.id, "lockdown", {}):
                continue
            if time.monotonic() - self.last_backup.get(g.id, 0) < 21600:
                continue
            try:
                async with self.locks[g.id]:
                    await self.backup(g)
            except Exception:
                LOG.exception("Scheduled backup failed for %s", g.id)

    @maintenance.before_loop
    async def before_maintenance(self):
        await self.wait_until_ready()

    def register_commands(self):
        @self.tree.command(name="guard", description="サーバー保護の状況を確認")
        @app_commands.guild_only()
        @app_commands.default_permissions(administrator=True)
        async def status(i: discord.Interaction):
            if not i.user.guild_permissions.administrator:
                return await i.response.send_message("管理者限定です", ephemeral=True)
            cfg = self.store.config(i.guild_id)
            await i.response.send_message(f"保護: {'有効' if cfg['enabled'] else '停止'}\nBotロールは保護対象の管理ロールより上に配置してください。\n設定・履歴・復旧は管理画面から操作できます。", ephemeral=True)

        @self.tree.command(name="guard_lock", description="緊急ロック（サーバー所有者限定）")
        @app_commands.guild_only()
        async def lock(i: discord.Interaction):
            if i.user.id != i.guild.owner_id:
                return await i.response.send_message("所有者限定です", ephemeral=True)
            await i.response.defer(ephemeral=True, thinking=True)
            async with self.locks[i.guild_id]:
                errors = await self.lockdown(i.guild)
            await i.followup.send("ロック処理完了。管理画面で失敗履歴を確認してください。" if errors else "ロックしました。管理者権限・Webhookは対象外です。", ephemeral=True)

        @self.tree.command(name="guard_unlock", description="緊急ロック解除（サーバー所有者限定）")
        @app_commands.guild_only()
        async def unlock(i: discord.Interaction):
            if i.user.id != i.guild.owner_id:
                return await i.response.send_message("所有者限定です", ephemeral=True)
            await i.response.defer(ephemeral=True, thinking=True)
            async with self.locks[i.guild_id]:
                errors = await self.lockdown(i.guild, unlock=True)
            await i.followup.send("解除処理完了。失敗がある場合は管理画面で確認してください。" if errors else "解除しました。", ephemeral=True)
