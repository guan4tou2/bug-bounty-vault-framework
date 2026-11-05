#!/usr/bin/env python3
"""check_asg_status_consistency.py — ASG 與 Finding 檔的 status 一致性，**分三類**。

為什麼需要這支（2026-09-27 量測）：
  全 vault 有 55 處 ASG findings 條目的 status 與 Finding 檔的 status 不同。
  一律報「不一致」沒有用 —— 它們其實是三種性質完全不同的東西：

    1. 詞彙不同、意思相同（~28）：`validated` ↔ `verified`、
       `false_positive` ↔ `not-vulnerable`。**不是錯**，只是兩套詞彙沒有宣告對應。
    2. 圖過期（~20）：ASG 還寫 `suspected`，Finding 檔已 `verified`。
       圖沒跟上驗證進度。
    3. 真矛盾（少數）：ASG `false_positive`（此平台不適用）
       vs 檔案 `verified`（漏洞是真的）。

  第 3 類揭露 schema 缺陷：**`false_positive` 被超載**，同時表達
  「不是真漏洞」與「真實但此平台不適用」。後者在詞彙裡沒有對應值 ——
  這也是當初發明 `structurally_inapplicable` 時
  實際在補的洞，只是當時沒意識到是通案。

  本腳本只**分類與呈報**，不自動改資料 —— resolution 依賴 target 的領域知識
  （某個 `suspected` 是圖過期還是當初刻意保守，只有挖過的人知道）。

用法：python3 automation/check_asg_status_consistency.py [<target>]
退出碼：0 = 無矛盾（第 3 類為 0）；1 = 有矛盾
        —— 第 1/2 類只呈報不影響退出碼，避免噪音蓋過真問題。
"""
import argparse
import os
import asg
import pathlib
import re
import sys

try:
    import yaml
except ImportError:
    print("需要 PyYAML", file=sys.stderr)
    sys.exit(2)

# 兩套詞彙的語意分組。同組＝意思相同，跨組才可能是問題。
CONFIRMED = {
    # ASG 側
    "validated", "code-confirmed", "build-verified", "proven", "confirmed",
    # Finding 檔側
    "verified", "ready", "submitted", "accepted",
}
DISPROVED = {
    # ASG 側
    "false_positive", "refuted", "disproved",
    # Finding 檔側
    "not-vulnerable", "na", "n/a", "duplicate", "fixed", "fixed_upstream",
    "killed", "verified-not-exploitable", "withdrawn",
}
# 「漏洞是真的，但此平台不適用」——不屬於 confirmed 也不屬於 disproved。
# 少了這一組，只能拿 false_positive 硬套，於是與 Finding 檔的 verified 直接矛盾
# （實測曾出現這種真矛盾）。它與 confirmed 相容：
# finding 成立，只是打不到這個平台的出貨面。
PLATFORM_SCOPED = {"platform_not_applicable", "structurally_inapplicable"}
TENTATIVE = {
    "suspected", "discovered", "source_confirmed", "hypothesis", "on_hold", "pending",
    "tested", "adversary_verified",
}

# ── path `status` 受控詞彙（issue #18 part 2）──
# 造新詞應是有意識的動作，不是打字副作用。新增前先加進這個集合。
# 分隔符正規化為底線（membership 測試會做同樣正規化），故 `code-confirmed` == `code_confirmed`。
ALLOWED_PATH_STATUS = {
    # —— 成立（依驗證強度）——
    "proven", "validated", "live_verified", "asan_verified", "build_verified",
    "code_confirmed", "source_confirmed",
    # —— 暫定 / 部分 ——
    "hypothesis", "suspected", "partial",
    # —— 收斂為否定 ——
    "dead_end", "withdrawn", "downgraded", "false_positive",
    # —— 真實但不適用（與 confirmed 相容）——
    #   platform_not_applicable = 目標平台的 binary 不含此碼（如 macOS 不含 SRP）
    #   structurally_inapplicable = 串鏈前提在此架構下結構性不成立（如 C4 cups-browsed）
    #   兩者語意不同，刻意不合併（#18 part 1 待決 → 決定：保留兩者並註明）
    "not_applicable", "platform_not_applicable", "structurally_inapplicable", "scope_exhausted",
    # —— 阻斷 / 已修 / 不可達 ——
    "confirmed", "blocked", "disputed", "needs_evidence", "tested", "adversary_verified",
    "blocked_no_input", "endpoint_unreachable", "endpoint_patched", "fixed_upstream",
}


def group(s: str) -> str:
    # 連字號與底線一律正規化：`source-confirmed` 與 `source_confirmed` 是同一個值，
    # 分隔符樣式不該製造誤報（初版就是這樣把 3 筆同義值報成「真矛盾」）。
    s = (s or "").strip().lower().replace("-", "_")
    if s in CONFIRMED:
        return "confirmed"
    if s in DISPROVED:
        return "disproved"
    if s in TENTATIVE:
        return "tentative"
    if s in PLATFORM_SCOPED:
        return "platform-scoped"
    return "unknown"


def _norm(x: str) -> str:
    return x.strip().lower().replace("-", "_")


CONFIRMED = {_norm(x) for x in CONFIRMED}
DISPROVED = {_norm(x) for x in DISPROVED}
TENTATIVE = {_norm(x) for x in TENTATIVE}
PLATFORM_SCOPED = {_norm(x) for x in PLATFORM_SCOPED}


def load_graph(p: pathlib.Path):
    return asg.read_state(p.parent)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?")
    a = ap.parse_args()

    root = asg.vault_root() / "01 - Targets"
    vocab, stale, contra, nostatus, pathvals = [], [], [], [], {}

    for t in sorted(x for x in root.iterdir() if x.is_dir()):
        if a.target and t.name != a.target:
            continue
        gf = t / f"Attack Surface Graph - {t.name}.md"
        if not gf.is_file() and not (t / ".state/asg-events.jsonl").exists():
            continue
        try:
            g = load_graph(gf)
        except Exception as e:
            print(f"  {t.name}: ASG 解析失敗 {e}", file=sys.stderr)
            return 2
        if not g:
            continue

        for p in g.get("paths") or []:
            s = str(p.get("status", "")).strip()
            if not s:
                nostatus.append((t.name, str(p.get("name", "?"))[:56]))
            else:
                pathvals.setdefault(s, 0)
                pathvals[s] += 1

        # Index each Finding file BOTH by its frontmatter finding_id AND by its resolved
        # path. A ledger finding is matched to its file by the `doc` link FIRST, falling
        # back to id — because the id schemes can differ. 2026-10-09: one target's ledger used
        # slug-ids (a service slug) linked via `doc:` to a finding's file; matching by
        # id alone made the file look un-represented, which read as「圖落後」drift and drove
        # a duplicate-finding「fix」. Following the explicit link is the fix for the whole
        # class of id-scheme mismatch (same reason check_ledger_doc_drift already does it).
        filestat: dict[str, str] = {}      # frontmatter finding_id -> status
        filestat_by_path: dict[pathlib.Path, str] = {}
        fdir = t / "Findings"
        if fdir.is_dir():
            for ff in fdir.glob("*.md"):
                txt = ff.read_text(encoding="utf-8", errors="replace")
                fid = re.search(r"^finding_id:\s*\"?([^\"\n]+)", txt, re.M)
                st = re.search(r"^status:\s*\"?([^\"\n]+)", txt, re.M)
                if not st:
                    continue
                status = st.group(1).strip()
                filestat_by_path[ff.resolve()] = status
                if fid:
                    filestat[fid.group(1).strip()] = status

        for fi in g.get("findings") or []:
            fid = str(fi.get("id", "")).strip()
            gs = str(fi.get("status", "")).strip()
            # A withdrawn/retracted ledger finding asserts nothing, so it cannot
            # contradict a Finding file — skip it. This matters once matching follows the
            # `doc` link: a retracted slug-id finding still points at a (verified) file,
            # and without this guard that reads as a false「真矛盾」(2026-10-09 rebuild).
            if group(gs) == "disproved" and gs.strip().lower() in ("withdrawn", "retracted", "dead_end"):
                continue
            doc = str(fi.get("doc") or "").strip()
            linked = (t / doc).resolve() if doc else None
            fs = (filestat_by_path.get(linked) if linked is not None else None) or filestat.get(fid)
            if not fs or not gs or gs == fs:
                continue
            gg, fg = group(gs), group(fs)
            row = (t.name, fid, gs, fs)
            if gg == fg or {gg, fg} == {"platform-scoped", "confirmed"}:
                vocab.append(row)                       # 同組、或「成立但此平台不適用」⇒ 相容
            elif {gg, fg} == {"confirmed", "disproved"}:
                contra.append(row)                      # 直接衝突
            elif gg == "tentative" and fg == "confirmed":
                stale.append(row)                       # 圖落後於檔案
            else:
                contra.append(row)                      # 其餘跨組一律當可疑

    print("=" * 66)
    print("  ASG ↔ Finding 檔 status 一致性（分三類）")
    print("=" * 66)

    print(f"\n🔴 真矛盾 {len(contra)} 筆 —— 一邊說成立、一邊說不成立，必須有一邊是錯的")
    for t, fid, gs, fs in contra:
        print(f"     {t} {fid}: ASG={gs} / 檔={fs}")
    if not contra:
        print("     （無）")

    print(f"\n🟠 圖落後 {len(stale)} 筆 —— Finding 已驗證，ASG 仍寫 tentative")
    for t, fid, gs, fs in stale[:12]:
        print(f"     {t} {fid}: ASG={gs} / 檔={fs}")
    if len(stale) > 12:
        print(f"     …另 {len(stale)-12} 筆")
    if not stale:
        print("     （無）")

    print(f"\n⚪ 僅詞彙不同 {len(vocab)} 筆 —— 語意同組，**不是錯**，缺的是宣告對應表")
    seen = {}
    for _, _, gs, fs in vocab:
        seen[(gs, fs)] = seen.get((gs, fs), 0) + 1
    for (gs, fs), n in sorted(seen.items(), key=lambda kv: -kv[1]):
        print(f"     ASG={gs} ↔ 檔={fs}  ×{n}")
    if not vocab:
        print("     （無）")

    print(f"\n⚪ path 無 status {len(nostatus)} 條 —— 衍生工具無法分類")
    for t, n in nostatus[:8]:
        print(f"     {t}: {n}")
    if len(nostatus) > 8:
        print(f"     …另 {len(nostatus)-8} 條")

    print(f"\n⚪ 使用中的 path status 值（受控詞彙驗證，warn-only 不影響退出碼）")
    off_vocab = []
    for k, v in sorted(pathvals.items(), key=lambda kv: -kv[1]):
        norm = (k or "").strip().lower().replace("-", "_")
        mark = "" if norm in ALLOWED_PATH_STATUS else "  ⚠️ 非受控詞彙（疑似造詞/打錯字）"
        if mark:
            off_vocab.append(k)
        print(f"     {k:28} {v}{mark}")
    if off_vocab:
        print(f"\n     ⚠️ {len(off_vocab)} 個 path status 不在受控集 → 若為刻意新增，請先加進")
        print(f"        check_asg_status_consistency.py 的 ALLOWED_PATH_STATUS（造新詞應是有意識的動作）")

    print("\n" + "-" * 66)
    if contra:
        print("""  🔴 只有第一類需要立刻處理。判準：

  注意 `false_positive` 是**超載**的 —— 它同時被用來表達
    (a)「不是真漏洞」          與
    (b)「漏洞是真的，但此平台不適用」
  (b) 的正確表達不是 false_positive（那會讓 Finding 檔的 verified 看起來像錯的），
  而是保留 finding 為 confirmed、在 path/note 標明平台界定
  （參考 Chain C4 用的 structurally_inapplicable）。

  第 2 類（圖落後）與第 3 類（詞彙）不影響退出碼 —— 噪音不該蓋過真問題。
  resolution 依賴 target 領域知識，本腳本不自動改。""")
        print("=" * 66)
        return 1
    print("  ✅ 無真矛盾")
    print("=" * 66)
    return 0


if __name__ == "__main__":
    sys.exit(main())
