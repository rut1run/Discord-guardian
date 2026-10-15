"""Loopback-first owner dashboard, sharing the Discord bot's event loop."""
import asyncio
import hashlib
import hmac
import json
import logging
import os
import ipaddress
import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import web
from dotenv import load_dotenv
import discord

from core import Store, Windows, validate_config
from guard import Guard

BASE = Path(__file__).resolve().parent


def make_app(bot, password, origin, pages_origin=None, trusted_proxy=False):
    sessions = {}
    attempts = Windows(max_keys=2000)
    password_gate = asyncio.Semaphore(2)
    salt = secrets.token_bytes(16)
    expected = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    parsed = urlsplit(origin)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.path not in ("", "/"):
        raise ValueError("PUBLIC_ORIGINには管理画面のオリジンを指定してください")
    origin = origin.rstrip("/")
    allowed_origins = {origin}
    if pages_origin:
        pages = urlsplit(pages_origin)
        if pages.scheme != 'https' or not pages.netloc or pages.path not in ('', '/') or pages.username or pages.password:
            raise ValueError('PAGES_ORIGINにはHTTPSのオリジンを指定してください')
        pages_origin = pages_origin.rstrip('/')
        allowed_origins.add(pages_origin)

    @web.middleware
    async def security(req, handler):
        try:
            if req.host != parsed.netloc:
                raise web.HTTPForbidden(text="Hostが一致しません。PUBLIC_ORIGINのURLで開いてください")
            request_origin = req.headers.get('Origin')
            if request_origin and request_origin not in allowed_origins:
                raise web.HTTPForbidden(text="Originが一致しません")
            if req.method != "GET" and request_origin not in allowed_origins:
                raise web.HTTPForbidden(text="Originが一致しません")
            if req.method == 'OPTIONS':
                response = web.Response(status=204)
            else:
                response = None
            client_ip = req.remote or 'unknown'
            if trusted_proxy and client_ip in ('127.0.0.1', '::1'):
                try:
                    client_ip = str(ipaddress.ip_address(req.headers.get('X-Real-IP', '')))
                except ValueError:
                    pass
            req['client_ip'] = client_ip
            now = time.time()
            for key in list(sessions):
                if sessions[key]["expires"] < now:
                    del sessions[key]
            if req.method != 'OPTIONS' and req.path.startswith("/api/") and req.path not in ('/api/login', '/api/health'):
                authorization = req.headers.get('Authorization', '')
                token = authorization[7:] if authorization.startswith('Bearer ') else req.cookies.get('rg_session', '')
                session = sessions.get(token)
                if not session:
                    raise web.HTTPUnauthorized(text="ログインしてください")
                if req.method != "GET" and not hmac.compare_digest(req.headers.get("X-CSRF-Token", ""), session["csrf"]):
                    raise web.HTTPForbidden(text="CSRF検証に失敗しました")
                req["session"] = session
                req['session_token'] = token
            if response is None:
                response = await handler(req)
        except web.HTTPException as exc:
            response = web.json_response({"error": exc.text}, status=exc.status)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            response = web.json_response({"error": str(exc)}, status=400)
        except discord.HTTPException as exc:
            response = web.json_response({"error": f"Discord APIで失敗しました（HTTP {exc.status}）。Bot権限とロール順位を確認してください"}, status=502)
        except Exception:
            logging.exception("Dashboard request failed")
            response = web.json_response({"error": "処理に失敗しました。起動コンソールを確認してください"}, status=500)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        if req.headers.get('Origin') in allowed_origins:
            response.headers.update({'Access-Control-Allow-Origin': req.headers['Origin'],
                'Vary': 'Origin', 'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS'})
        return response

    app = web.Application(middlewares=[security], client_max_size=16384)

    async def login(req):
        if attempts.hit(("login", req['client_ip']), 300, 11):
            raise web.HTTPTooManyRequests(text="試行回数が多いため5分待ってください")
        # Global throttle bounds expensive password hashing even through many IPs.
        if attempts.hit("global-login", 60, 101):
            raise web.HTTPTooManyRequests(text="時間を置いて再試行してください")
        body = await req.json()
        provided = body.get("password", "")
        if not isinstance(provided, str) or len(provided) > 1024:
            raise web.HTTPUnauthorized(text="パスワードが違います")
        async with password_gate:
            actual = await asyncio.to_thread(hashlib.scrypt, provided.encode(), salt=salt, n=16384, r=8, p=1)
        if not hmac.compare_digest(expected, actual):
            raise web.HTTPUnauthorized(text="パスワードが違います")
        if len(sessions) >= 100:
            sessions.pop(next(iter(sessions)))
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        sessions[token] = dict(csrf=csrf, expires=time.time() + 3600 * 8)
        data = {'csrf': csrf}
        if pages_origin and req.headers.get('Origin') == pages_origin:
            data['token'] = token
        response = web.json_response(data)
        response.set_cookie("rg_session", token, httponly=True, secure=parsed.scheme == "https", samesite="Strict", max_age=3600 * 8, path="/")
        return response

    async def logout(req):
        sessions.pop(req['session_token'], None)
        response = web.json_response({"ok": True})
        response.del_cookie("rg_session")
        return response

    async def me(req):
        return web.json_response({"csrf": req["session"]["csrf"], "ready": bot.is_ready(),
                                  "guilds": [dict(id=str(g.id), name=g.name, members=g.member_count) for g in bot.guilds]})

    def guild(req):
        if not bot.is_ready():
            raise web.HTTPServiceUnavailable(text="BotがDiscordに接続していません")
        g = bot.get_guild(int(req.match_info["gid"]))
        if not g:
            raise web.HTTPNotFound(text="Bot未導入のサーバーです")
        return g

    async def details(req):
        g = guild(req)
        cfg = bot.store.config(g.id)
        checks = {p: getattr(g.me.guild_permissions, p) for p in
                  ("view_audit_log", "manage_roles", "manage_channels", "moderate_members", "manage_messages", "kick_members", "manage_webhooks")}
        return web.json_response(dict(id=str(g.id), name=g.name, config=cfg,
            checks=checks, bot_role_position=g.me.top_role.position,
            higher_roles=[r.name for r in g.roles if r >= g.me.top_role and r.id != g.me.top_role.id],
            events=bot.store.events(g.id), snapshots=bot.store.snapshots(g.id),
            frozen=bot.store.get(g.id, "backup_frozen", False),
            locked=bool(bot.store.get(g.id, "lockdown", {})),
            join_hold_until=bot.store.get(g.id, "join_hold_until", 0),
            channels=[dict(id=str(c.id), name=c.name) for c in g.text_channels]))

    async def settings(req):
        g = guild(req)
        data = validate_config(await req.json())
        cid = data.get("log_channel_id", "")
        if cid and not isinstance(g.get_channel(int(cid)), discord.TextChannel):
            raise ValueError("このサーバーのテキストチャンネルを指定してください")
        bot.store.put(g.id, "config", bot.store.config(g.id) | data)
        bot.store.incident(g.id, "設定変更", "管理者", "保護設定を更新しました")
        return web.json_response({"ok": True})

    async def action(req):
        g = guild(req)
        name = req.match_info["action"]
        if name not in ("backup", "restore", "lock", "unlock", "resume", "release"):
            raise web.HTTPNotFound()
        body = await req.json()
        if body.get("confirm") != str(g.id):
            raise ValueError("対象サーバーの確認に失敗しました")
        if bot.locks[g.id].locked():
            raise web.HTTPConflict(text="このサーバーの処理が進行中です")
        async with bot.locks[g.id]:
            if name == "backup":
                result = {"snapshot_id": await bot.backup(g)}
            elif name == "restore":
                result = {"results": await bot.restore(g, int(body["snapshot_id"]))}
            elif name in ("lock", "unlock"):
                result = {"errors": await bot.lockdown(g, unlock=name == "unlock")}
            elif name == "resume":
                bot.store.put(g.id, "backup_frozen", False)
                result = {"ok": True}
            else:
                bot.store.put(g.id, "join_hold_until", 0)
                result = {"ok": True}
        return web.json_response(result)

    async def index(req):
        return web.FileResponse(BASE / "web" / "index.html")

    async def health(req):
        return web.json_response({'ok': True, 'discord': bot.is_ready()})

    async def preflight(req):
        return web.Response(status=204)

    app.router.add_get("/", index)
    app.router.add_static("/assets/", BASE / "web", show_index=False)
    app.router.add_post("/api/login", login)
    app.router.add_get('/api/health', health)
    app.router.add_route('OPTIONS', '/api/{path:.*}', preflight)
    app.router.add_post("/api/logout", logout)
    app.router.add_get("/api/me", me)
    app.router.add_get("/api/guilds/{gid}", details)
    app.router.add_put("/api/guilds/{gid}/settings", settings)
    app.router.add_post("/api/guilds/{gid}/{action}", action)
    return app


async def main():
    os.umask(0o077)
    load_dotenv(BASE / ".env")
    token, password = os.getenv("DISCORD_TOKEN", ""), os.getenv("ADMIN_PASSWORD", "")
    if not token or len(password) < 16:
        raise SystemExit("先に python setup_guard.py を実行してください（管理パスワードは16文字以上必要）")
    port = int(os.getenv("PORT", "8787"))
    origin = os.getenv("PUBLIC_ORIGIN", f"http://127.0.0.1:{port}")
    db = Store(Path(os.getenv('DATA_DIR', str(BASE / 'data'))) / 'guard.db')
    bot = Guard(db)
    app = make_app(bot, password, origin, pages_origin=os.getenv('PAGES_ORIGIN'), trusted_proxy=os.getenv('TRUST_LOCAL_PROXY')=='1')
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, os.getenv("BIND_HOST", "127.0.0.1"), port).start()
    print(f"管理画面: {origin}", flush=True)
    try:
        async with bot:
            await bot.start(token)
    finally:
        await runner.cleanup()
        db.db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
