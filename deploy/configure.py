import getpass
import os
import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit


def main():
    if os.geteuid() != 0:
        raise SystemExit('sudoで実行してください')
    target = Path('/etc/radius-guard.env')
    if target.exists():
        raise SystemExit('設定済みです。変更は sudo nano /etc/radius-guard.env で行ってください')
    host = input('APIホスト名 [entry-systems.duckdns.org]: ').strip() or 'entry-systems.duckdns.org'
    if not re.fullmatch(r'[a-z0-9.-]+', host):
        raise SystemExit('ホスト名が不正です')
    page = input('GitHub Pages URL [https://rut1run.github.io/Discord-guardian/]: ').strip() or 'https://rut1run.github.io/Discord-guardian/'
    url = urlsplit(page)
    if url.scheme != 'https' or not url.hostname or not url.hostname.endswith('.github.io') or url.username or url.password or url.port not in (None,443) or url.query or url.fragment:
        raise SystemExit('GitHub PagesのHTTPS URLを指定してください')
    token = getpass.getpass('新しいGuard Botのトークン（非表示）: ').strip()
    if not token or re.search(r"[\s'\"\\]", token):
        raise SystemExit('トークンの形式が不正です')
    password = secrets.token_urlsafe(24)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(f'DISCORD_TOKEN={token}\nADMIN_PASSWORD={password}\nBIND_HOST=127.0.0.1\nPORT=8791\nPUBLIC_ORIGIN=https://{host}\nPAGES_ORIGIN=https://{url.netloc}\nTRUST_LOCAL_PROXY=1\nDATA_DIR=/var/lib/radius-guard\n')
    print(f'\nAPI接続先: https://{host}/radius-guard\n管理画面: {page}\n管理パスワード: {password}\nこのパスワードを手元に保存してください。チャットに送る必要はありません。')


if __name__ == '__main__':
    main()
