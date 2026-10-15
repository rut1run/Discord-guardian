"""Interactive local setup. Secrets never need to be sent through chat."""
import getpass
import os
from pathlib import Path
import secrets

BASE = Path(__file__).resolve().parent

if __name__ == "__main__":
    target = BASE / ".env"
    if target.exists():
        raise SystemExit(".envは作成済みです。変更する場合は直接編集してください。")
    print("Discord Developer PortalのBotトークンを入力してください（入力は表示されません）。")
    token = getpass.getpass("Bot token: ").strip()
    if not token or any(c in token for c in "\n\r'\" "):
        raise SystemExit("トークンの形式が不正です")
    password = secrets.token_urlsafe(24)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(f"DISCORD_TOKEN={token}\nADMIN_PASSWORD={password}\nBIND_HOST=127.0.0.1\nPORT=8787\nPUBLIC_ORIGIN=http://127.0.0.1:8787\n")
    (BASE / "data").mkdir(mode=0o700, exist_ok=True)
    print(f"\n設定完了。管理パスワード: {password}\nこのパスワードを手元に保存してください。\npython server.py で起動します。")
