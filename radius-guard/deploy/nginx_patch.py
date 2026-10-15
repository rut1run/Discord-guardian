"""Add one isolated location include to the existing HTTPS virtual host."""
import argparse
import re
import shutil
import subprocess
import time
from pathlib import Path

INCLUDE = 'include /etc/nginx/snippets/radius-guard.conf;'


def masked(text):
    # Preserve offsets while ignoring braces in comments and quoted strings.
    chars = list(text)
    quote, comment, escape = None, False, False
    for i, c in enumerate(text):
        if comment:
            if c == '\n':
                comment = False
            else:
                chars[i] = ' '
        elif quote:
            chars[i] = ' '
            if escape:
                escape = False
            elif c == '\\':
                escape = True
            elif c == quote:
                quote = None
        elif c == '#':
            chars[i] = ' '
            comment = True
        elif c in ('"', "'"):
            chars[i] = ' '
            quote = c
    return ''.join(chars)


def patch(text, hostname):
    clean = masked(text)
    candidates = []
    for match in re.finditer(r'\bserver\s*\{', clean):
        start = match.end()
        depth, end = 1, start
        while end < len(clean) and depth:
            depth += (clean[end] == '{') - (clean[end] == '}')
            end += 1
        if depth:
            raise ValueError('Nginx設定の括弧が一致しません')
        block = clean[start:end-1]
        names = re.findall(r'\bserver_name\s+([^;]+);', block)
        listeners = re.findall(r'\blisten\s+([^;]+);', block)
        if any(hostname in nameset.split() for nameset in names) and any(re.search(r'(?:^|:)443(?:\s|$)', x) for x in listeners):
            present = INCLUDE in clean[start:end]
            if re.search(r'\blocation\s+(?:\^~\s+)?/radius-guard/', block):
                raise ValueError('/radius-guard/の既存設定があります。自動変更を停止しました')
            candidates.append((end-1, present))
    if len(candidates) != 1:
        raise ValueError('対象のHTTPS serverブロックが一意に見つかりません。設定は変更していません')
    end, present = candidates[0]
    if present:
        return text
    return text[:end] + '\n    ' + INCLUDE + '\n' + text[end:]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('hostname')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9.-]+', args.hostname):
        raise SystemExit('ホスト名が不正です')
    candidates = []
    for path in Path('/etc/nginx/sites-enabled').iterdir():
        if not path.is_file():
            continue
        resolved = path.resolve()
        text = resolved.read_text()
        try:
            replacement = patch(text, args.hostname)
        except ValueError:
            continue
        candidates.append((resolved, text, replacement))
    unique = {p: (text, replacement) for p, text, replacement in candidates}
    if len(unique) != 1:
        raise SystemExit('HTTPS設定を特定できません。Nginxは変更していません。deploy/nginx-location.confを手動で対象server内に追加してください。')
    path, (old, new) = next(iter(unique.items()))
    if old == new:
        print('Nginx設定は追加済みです')
        return
    backup = path.with_name(path.name + f'.guard-backup-{time.time_ns()}')
    shutil.copy2(path, backup)
    path.write_text(new)
    try:
        subprocess.run(['nginx', '-t'], check=True)
        subprocess.run(['systemctl', 'reload', 'nginx'], check=True)
    except subprocess.CalledProcessError:
        path.write_text(old)
        subprocess.run(['nginx', '-t'], check=False)
        subprocess.run(['systemctl', 'reload', 'nginx'], check=False)
        raise SystemExit('Nginx検証に失敗したため元の設定に戻しました')
    print('Guard APIの経路を追加しました。元の設定: ' + str(backup))


if __name__ == '__main__':
    main()
