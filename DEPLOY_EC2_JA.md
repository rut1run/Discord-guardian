# Entry Systemと同じEC2へ追加する手順

管理画面はGitHub Pages、Bot・API・データは既存EC2で運用します。新規のVPSや独自ドメインは契約しません。
AWSの既存契約・無料枠・転送量等による費用はAWS側の利用状況によります。追加インスタンスや有料プランへの変更を行うスクリプトは含みません。

## 構成

| 用途 | 配置 |
| --- | --- |
| ソース | 新しいGitHubリポジトリ `Discord-guardian` |
| 管理画面 | リポジトリの `docs/` → GitHub Pages |
| Bot・API | 既存Ubuntu EC2内 `/opt/radius-guard` |
| API待受 | `127.0.0.1:8791` |
| 公開API | `https://entry-systems.duckdns.org/radius-guard/api/` |
| 自動起動 | `radius-guard.service` |
| 秘密情報 | `/etc/radius-guard.env`、rootのみ読取可 |
| データ | `/var/lib/radius-guard/guard.db` |

Entry Systemの `entry-bot`・`entry-web`、既存のBotトークン・DBは変更しません。Guardのコードは専用ユーザーで実行し、メモリ256MiB・CPU40%を上限にしています。大規模サーバーでは上限と既存サービスの余力を個別に確認してください。

## 1. GitHubへアップロード

1. `rut1run`のGitHubで **Discord-guardian** という新しい**Public**リポジトリを作成します。
2. このZIPを展開し、`radius-guard`フォルダ**内のファイル・フォルダ**をすべてアップロードします。外側の `radius-guard` フォルダごとはアップロードしないでください。ルートに `server.py` と `docs` がある形にします。
3. Settings → Pages → Build and deployment で、Sourceを **Deploy from a branch**、Branchを **main**、フォルダを **/docs** にして保存します。
4. 公開後、`https://rut1run.github.io/Discord-guardian/` を開きます。

リポジトリ名や所有者を変える場合は、実際のPages URLを手順3のEC2設定で入力してください。APIのドメインを変える場合は `docs/config.js` の `apiBase` も修正します。API接続先はログイン画面でも変更できます。
GitHubに置くファイルにBotトークン・管理パスワードは含まれません。

## 2. 新しいGuard Botを作成

Discord Developer Portal → New Applicationで専用Botを作成します。**Entry SystemのBotトークンは再利用しません。**
Botの **SERVER MEMBERS INTENT** と **MESSAGE CONTENT INTENT** をONにします。
`bot` と `applications.commands` スコープで、README_JA.mdに記載の権限を付けてサーバーへ招待します。
Discord側でBotのロールを保護する管理ロールより上に置きます。

## 3. 既存EC2でインストール

Entry Systemのときと同じUbuntuのSSH画面で実行します。

```bash
cd ~
git clone https://github.com/rut1run/Discord-guardian.git radius-guard-src
cd ~/radius-guard-src
sudo bash deploy/install.sh
```

入力内容:

1. APIホスト名 → 既存の `entry-systems.duckdns.org` が使えている場合はEnter。
2. GitHub Pages URL → `https://rut1run.github.io/Discord-guardian/` の場合はEnter。
3. **新しいGuard Botのトークン** → 自分のSSH画面で入力。入力文字は表示されません。

最後に**管理パスワード**が表示されます。手元に保存してください。
インストーラーは空きメモリ350MiB未満・8791番ポート使用中・既存のGuard用Nginx設定との衝突がある場合に停止します。
Nginxの既存HTTPS設定にGuard専用の経路だけを追加し、`nginx -t`成功後にreloadします。失敗した場合は変更したserver設定を元に戻します。既存Entry Systemのサービスは再起動しません。

Pythonのvenvが未導入というエラーの場合だけ、`sudo apt install python3-venv` を実行して再試行してください。

## 4. 確認

```bash
sudo systemctl status radius-guard --no-pager
sudo journalctl -u radius-guard -n 40 --no-pager
curl https://entry-systems.duckdns.org/radius-guard/api/health
systemctl is-active entry-bot entry-web
```

APIの応答が `{"ok": true, "discord": true}` ならDiscord接続まで完了しています。`discord:false` は起動直後または接続待ちです。
GitHub Pagesの画面で、EC2で発行した管理パスワードを入力してログインします。
Pagesは画面だけを公開し、サーバー情報・設定・履歴はAPIの認証後に取得します。ログイン情報はメモリ内のみで保持し、ページ更新時にはログインし直します。

## 5. 最初に設定すること

1. 保護設定で管理者専用の通知チャンネルを選択。
2. Botの権限表示とロール順位を確認。
3. テストサーバーで連投→タイムアウト、バックアップ→テストチャンネル削除→復旧を確認。
4. 通常運用へ移行。

BotはEC2内で常時稼働するので、自分のPCは閉じられます。管理画面を閉じても監視は継続します。

## 更新

```bash
cd ~/radius-guard-src
git pull --ff-only
sudo systemctl stop radius-guard
sudo bash deploy/install.sh
```

停止するのはGuardだけです。設定とDBはコードとは別の場所に残ります。
管理パスワードやトークンの変更は `sudo nano /etc/radius-guard.env` → `sudo systemctl restart radius-guard` で反映します。
GitHub PagesのURLを変えた場合は `PAGES_ORIGIN` を実際の `https://ユーザー名.github.io` に合わせて再起動してください。

## Nginx設定を自動特定できない場合

インストーラーは既存のHTTPS server設定を一意に確認できないと自動変更しません。
対象ドメインのHTTPS serverブロック内に、次の1行を手動で追加します。

```nginx
include /etc/nginx/snippets/radius-guard.conf;
```

`sudo nginx -t` で成功を確認してから `sudo systemctl reload nginx` を実行し、インストーラーを再実行します。既存の `/api/` や `/` のlocationは置き換えません。

## 停止・取り外し

Guardだけを止める場合は `sudo systemctl disable --now radius-guard` を実行します。
API経路も外す場合は、追加した `include /etc/nginx/snippets/radius-guard.conf;` の1行だけを削除してNginx設定を検証・reloadします。Entry Systemの設定全体を古いバックアップに戻す操作は避けてください。
DBや秘密情報を削除するコマンドはこの手順には含めません。
