# 承認診断 v1（opt-in）

## 目的と非目的

`<sandbox: approval-required …>` は **UI 表示回数ではない**。executor が provider を呼ぶ前に出すマーカーであり、保存済み grant の hit では UI を開かない。一つの承認 request が scope / duration / action / host confirmation の複数 selector を開く場合もある。従来のマーカーと権限判定は変更しない。

この診断は provider、stored-grant lookup、selector、応答、grant 保存、retry を別イベントにする。権限の根拠、監査完全性の保証、host fallback、新しい grant の種類は追加しない。元調査の過去セッションについて、UI 回数や当時の extension revision を遡って確定するものではない。

## 有効化・保存・プライバシー

Pi 起動前に `PI_SELECTIVE_SANDBOX_APPROVAL_DIAGNOSTICS=1` を設定する。既定は無効。設定後は reload / 再起動が必要。子プロセスでもこの環境変数が有効なときに子側の診断を記録する。

保存先は `<getAgentDir()>/pi-selective-sandbox/approvals/diagnostics/<ランダム UUID>.jsonl`。既存の deny-protected approvals root の内側で、workspace や session transcript には記録しない。ファイルは extension instance ごとに exclusive create、0600、ディレクトリは0700。同名ファイルを共有 append しない。安全でないディレクトリ、symlink、書込失敗では診断だけを停止する。診断保存のために保護を緩めたり書込先を変更したりしない。

記録するのは、固定 enum、数値、ランダム ID、capability 種別と一時的な HMAC identity のみ。

- command 本文・command/input digest・tool input・ファイル内容・stdout/stderr・denial message・token/credential・UI title/choices・例外文字列は保存しない。
- scope（パス / network endpoint）と project identity は、extension instance ごとのランダム鍵による domain-separated HMAC-SHA256。鍵を永続化せず、raw path、hostname、cwd、session ID、bridge nonce を保存しない。raw scope を記録する opt-in は設けない。
- scope identity は同じ instance 内の完全一致だけを表す。別プロセス / reload 間の equality、path の親子関係、同じコマンドであることは hash から推測しない。host command の hash も保存しない。
- HMAC でも等値関係、イベント時刻、アクセス種別は機微情報になり得るため、収集は明示 opt-in、共有前に確認する。

保存上限は instance あたり 4 MiB、未完了 queue は256イベント。上限超過は破棄する。各 file write の準備で最終ディレクトリの種別・mode・owner を確認する。初回と、その後の書込時に最大1日おきに、最終更新が7日より古い UUID 名の診断 JSONL だけを削除する。**停止中・無効化後の自動削除や厳密な7日 TTL は保証しない**。不要になったら利用者が診断ディレクトリを削除する。多数 instance の合計容量上限は別途設定していない。

書込、cleanup、sink は権限フローから await しない。例外・reject は診断内で吸収し、判断、lookup 順序、同期 session grant 操作、既存の validation / deny-root / sandbox retry / host confirmation を変更しない。shutdown 時にも診断完了のために承認フローを待たせない。クラッシュ、書込失敗、容量・queue上限で欠測し得る。ログがないことは「UI がなかった」証拠ではない。

## 相関

全イベントに `version=1`, `emitterId`, `sequence`, `time`, `originId`, `operationId`, `requestId`, `attempt`, `actor`, `tool` を付ける。

- `originId`: 診断 instance のランダム ID。scope/project HMAC の equality domain。
- `operationId`: bash の一回の execute（full command の retry を含む）。native は provider request ごと。
- `attempt`: bash は最初の sandbox 実行が0、widen retry ごとに1増える。native は0。
- `requestId`: 各 denial/承認のランダム ID。同じ attempt の executor と provider を結ぶ。grant.load は初回 attempt の ID。
- `actor=parent|child`: 要求の発生元。top-level/headless standalone も parent 扱い。`tool=bash|native` は入力内容からでなく request 種別から決める。
- `selectorId`: 一つの UI API invocation / child dispatch の ID。一つの request に複数あり得る。
- 子側は `selector.dispatch`、親側は同じ相関 ID で `selector.open` を記録する。親側の `emitterId` は親 instance、`originId` は子 instance のままである。

bridge の相関 metadata は UUID / 小さい整数 / 固定 enum の allowlist をコピーするだけで、承認には使わない。壊れていても既存 request は拒否しない。既存256 KiB transport 上限を超える場合は metadata **だけ**省略する。metadata がない旧 child / near-limit request は親の診断で相関した UI 回数に含まれない。

## イベント

| event | 意味 |
| --- | --- |
| `provider.start` | provider 呼出。prepared `scopes` と raw observed targets の HMAC を分離、project は HMAC |
| `lookup.start` / `lookup` | 実際に評価した stored-grant lookup。`authority=resource / host`, `duration=session / project`, `outcome=hit / miss / skipped / error` |
| `grant.load` | bash の初回実行へ既存 resource grants を投入するために読んだ集合。duration 別。load は covers lookup ではない |
| `coverage` | prepared candidate に現在の bash grant が適用されるか。既存の containment / endpoint 完全一致判定を表示する。stored-grant の exact lookup と別物 |
| `provider.skip` | UI が利用できない headless request。grant hit ならこの前に返る |
| `selector.dispatch` | 子側からの selector 転送。**UI 回数に加えない** |
| `selector.open` | local / 親側で UI API を実際に呼ぶ直前。親 queue に入っただけでは出さない |
| `selector.render` | custom TUI の最初の render が完了。一つの selector に一度だけ |
| `selector.response` | selector の selected / dismissed / aborted / timeout / error。選択文字列は記録しない |
| `bridge.response` | 子側 transport の selected / dismissed / aborted / timeout / unavailable。UI 応答とは別。timeout は既存 deadline による |
| `approval.selection` | validation 済み resource scope と duration、または exact-command confirmation 後の host duration。保存前の選択 |
| `persist` | resource/host と session/project の保存成功・失敗。session はメモリ保存、project は既存 store の保存処理。Once は保存しない |
| `provider.response` | 最終 allow / deny / aborted / error。allow の authority と duration、選択された scope identity |
| `attempt.denial` | 今回の observed targets と直前の denial targets の比較 |
| `retry` | widen / host replay、covered-only / policy / limit による抑止、または承認拒否。実行許可の判断は既存処理のまま |

lookup 順序は host-project → host-session → resource-project → resource-session（native は resource のみ）。最初の hit で short circuit するため、後続にイベントがないことを miss と解釈しない。eligibility がなければ skipped。lookup 自体が throw した場合は error として記録し、元の例外をそのまま伝播する。store が元々内部で read error を空集合扱いする場合は既存の意味で miss となるので、disk 健全性までは証明しない。

`approval.selection` は provider の最終応答や retry を意味しない。例えば project 保存失敗では persist/error → provider/deny で終わる。`duration=once` は永続化なし、session はその instance の session store、project は以降のセッションでも使える既存 store である。

`attempt.denial.relation`:
- `first`: 最初の observed denial set。
- `same`: 直前と完全に同じ set。
- `new`: 直前と重複しない set。
- `mixed`: 部分重複、追加または一部消失。

比較は observed target の kind/resource 完全一致で、prepared Git/parent scope や選択された ancestor とは別。same は「許可を忘れた」証拠ではない。covered telemetry なら再承認せず終わる場合もある。新しい別の tool invocation は別 operation であり、上記 relation は引き継がない（同じ origin の scope identity は比較可能）。

## UI 表示の証拠と集計

built-in select / RPC は描画完了や人間が見たという acknowledgement を提供しない。`selector.open` は **実 UI API invocation の回数**であり、verified pixel visibility ではない。RPC client が画面に出したかは不明。custom の `selector.render` は別の強い証拠だが、注視の証明ではない。UI が throw した場合も open は残るので、response/error と合わせて読む。

```sh
node scripts/summarize-approval-diagnostics.mjs \
  "$HOME/.pi/agent/pi-selective-sandbox/approvals/diagnostics/"*.jsonl
```

スクリプトは明示指定したファイルだけを読み、`emitterId/sequence` で重複を除外する。出力に raw identity を出さず、provider 回数、selector invocation 数、custom 初回 render 数、UI を呼んだ request 数、child dispatch、lookup、保存結果、retry target relation を分離する。応答・lookup・保存結果は actor / tool / authority / duration / outcome 別。

- `approval-required` 行は JSONL 診断ではなく、UI として数えない。
- selector 数と論理承認 request 数を足し合わせない。child dispatch と親 invocation を二重計上しない。
- 応答の duration は最終 allow に対するもの。複数 selector の表示時点の authority / duration を後から推定しない。
- 壊れた行は invalidLines として集計し、知らない値をそのまま出力しない。
- emitter の sequence 欠落、対応する start/response 不在、grant.load / provider.start のない attempt、親側だけの記録は欠測の可能性。集計は常に best-effort の下限であり、全 session の完全な UI 履歴ではない。

## 検証

`src/test/approval-telemetry.test.ts` は headless、pre-abort / selecting abort、stored grant hit、resource/host、bash/native、project 保存成功/失敗、lookup 例外、sink throw/reject/書込不能、既存実行順・markers 維持、retry same/new/mixed/covered、bridge timeout、metadata 上限・不正値、custom 初回描画、private JSONL / retention、集計の非二重計上を検証する。既存の executor / widening / native mutation / subagent approval テストも合わせて実行する。

この workspace の検証結果:

- `npm run check` / `npm run build`: 成功。
- 承認・executor・widening・native mutation・subagent の重点テスト: 128/128 成功。
- 既存 `macOSTestFiles` の5ファイルを除いた unit/fixture subset: 278/278 成功（全体テスト成功の代替ではない）。
- 変更途中の `npm test`: 286件中273成功、実 macOS integration 13件失敗。`sandbox-exec: sandbox_apply: Operation not permitted` など、sandbox 内からの OS 実行制約が発生。専用 `macos_sandbox_test` のホスト実行は承認されず、実行していない。最終版の OS integration 成功は未確認。
- 独立 read-only review: 初回・最終差分とも指摘なし。

実 macOS sandbox と platform trust の確認は、通常のホスト端末で既存の `npm run test:macos` を実行する必要がある。sandbox 内での `sandbox-exec: sandbox_apply: Operation not permitted` は診断実装の成功の証拠でも OS integration 成功でもない。保護を無効化して再試行しない。
