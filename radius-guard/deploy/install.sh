#!/usr/bin/env bash
set -euo pipefail
if [[ "$EUID" -ne 0 ]]; then
  echo 'sudo bash deploy/install.sh で実行してください。'
  exit 1
fi
source_dir="$(cd -- "$(dirname -- "$0")/.." && pwd)"
for command_name in python3 nginx systemctl tar; do
  command -v "$command_name" >/dev/null || { echo "$command_name が必要です。"; exit 1; }
done
if [[ "$source_dir" == /opt/radius-guard ]]; then
  echo '/opt/radius-guardとは別の作業フォルダから実行してください。'
  exit 1
fi
python3 - <<'PY'
import socket
with socket.socket() as check:
 try:
  check.bind(('127.0.0.1',8791))
 except OSError:
  raise SystemExit('8791番ポートが使用中です。Guardが稼働中なら、まず sudo systemctl stop radius-guard を実行してから更新してください。')
info={line.split(':')[0]:int(line.split()[1]) for line in open('/proc/meminfo') if line.startswith('MemAvailable:')}
if info.get('MemAvailable',0)<350*1024:
 raise SystemExit('空きメモリが350MiB未満のため導入を停止しました。既存Botを守るため空き容量を確認してください。')
PY
if ! id radius-guard >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/radius-guard --shell /usr/sbin/nologin radius-guard
fi
install -d -o root -g root -m 755 /opt/radius-guard
install -d -o radius-guard -g radius-guard -m 700 /var/lib/radius-guard
tar -C "$source_dir" --exclude=.env --exclude=.venv --exclude=data --exclude=.git --exclude=__pycache__ --exclude=guard-cloud.json -cf - . | tar -C /opt/radius-guard -xf -
python3 -m venv /opt/radius-guard/.venv
/opt/radius-guard/.venv/bin/python -m pip install -r /opt/radius-guard/requirements.txt
if [[ ! -f /etc/radius-guard.env ]]; then
  python3 /opt/radius-guard/deploy/configure.py
fi
api_host="$(python3 - <<'PY'
from pathlib import Path
from urllib.parse import urlsplit
for line in Path('/etc/radius-guard.env').read_text().splitlines():
 if line.startswith('PUBLIC_ORIGIN='):
  print(urlsplit(line.split('=',1)[1]).hostname)
  break
PY
)"
install -d -m 755 /etc/nginx/snippets
if [[ -e /etc/nginx/snippets/radius-guard.conf ]] && ! cmp -s /etc/nginx/snippets/radius-guard.conf /opt/radius-guard/deploy/nginx-location.conf; then
  echo '/etc/nginx/snippets/radius-guard.confが既存の内容と異なるため停止しました。'
  exit 1
fi
install -m 644 /opt/radius-guard/deploy/nginx-location.conf /etc/nginx/snippets/radius-guard.conf
python3 /opt/radius-guard/deploy/nginx_patch.py "$api_host"
install -m 644 /opt/radius-guard/deploy/radius-guard.service /etc/systemd/system/radius-guard.service
systemctl daemon-reload
systemctl enable --now radius-guard.service
echo 'Guardを追加しました。Entry Systemのサービスは変更していません。'
systemctl --no-pager --full status radius-guard.service || true
