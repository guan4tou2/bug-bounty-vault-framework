#!/usr/bin/env python3
"""kb_retrieval.py — KB 檢索的單一核心：語料定義 + lexical + semantic。

2026-09-22 建立。起因是稽核發現同一個 KB 有**四個各自為政的檢索器**，
每個都自己定義「KB 是什麼」，於是各自有不同的盲區：

  experience_search (MCP)  非遞迴 glob → 看不到 wiki/、Lessons/（實測 264/796 檔）
  kb_connector.kb_documents  只掃根目錄前綴 + wiki/，本文截斷 4000 字元
  surface_kb.sh            自己維護一份技術指紋字典
  lesson_rank.py           只看 Lessons/

修一個不會修到其他三個——這才是根本問題，比「要不要加 embedding」更重要。
本模組提供 `corpus()` 當唯一的語料定義，四個入口改成薄呼叫端。

## lexical 與 semantic 的分工（不是誰取代誰）

`kb_connector.kb_documents` 的原始 docstring 寫得對：
「intentionally lexical and auditable so a worker can see why a document was
selected **without trusting an opaque embedding score**」。這個設計意圖保留。

實測 TF-IDF 的邊界（2026-09-22，503 篇語料）：

    "actuator"                              → 0.695  單一術語最強
    "SharedPreferences delegate default"    → 0.242  用對術語就命中 LL-324
    "hardcoded credential 是不是產品預設值"   → 完全沒命中 LL-324（同一件事，口語問法）
    "IDOR 跨租戶"                            → 0.075  答案對但訊號極弱

**關鍵詞檢索在你已經知道術語時有效，在你不知道時失效——而後者正是你需要檢索的時候。**
所以 semantic 是**增補召回通道**，不是替換：
  - lexical 命中 → `why` 帶 `matched_terms`，可稽核，權重較高
  - semantic 命中 → `why` 標明 `semantic`，附相似度，讓人自己判斷要不要信
  - 兩者都命中 → 分數相加，排最前

## 降級保證

模型／venv 不在時 `semantic()` 回空、`search()` 仍完整走 lexical。
hunt loop 是熱路徑，**絕不能因為 embedding 沒裝好就壞掉**。
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

from gen_lesson_index import INACTIVE_STATUSES, fm_of

VAULT_ROOT = Path(os.environ.get("VAULT_ROOT", Path(__file__).resolve().parents[1]))
KB_DIR = VAULT_ROOT / "09 - Knowledge Base"
INDEX_DIR = VAULT_ROOT / "automation" / ".kb_index"
EMBED_PY = VAULT_ROOT / ".venv-kb" / "bin" / "python"
EMBED_MODEL = "minishlab/potion-multilingual-128M"

# 排除：歸檔（已被取代的舊版）、暫存、打詐通報（是操作記錄不是可複用知識）
SKIP_PARTS = {"_archive", "_staging", "_backups", "Writeups", "Anti-Fraud"}

PREFIX_TYPE = [
    ("Pattern", "pattern"), ("Checklist", "checklist"), ("Playbook", "playbook"),
    ("Reference Card", "reference"), ("Tool", "tool"), ("Skill", "skill"),
    ("Resource", "resource"), ("Ledger", "ledger"), ("Backlog", "backlog"),
    ("Article", "reference"), ("Lesson", "lesson"),
]

# 出現在句子裡但沒有篩選力的英文詞——字面命中它們等於隨機挑文件
_STOP = {"app", "api", "web", "http", "https", "the", "and", "for", "with", "this",
         "that", "from", "have", "were", "been", "just", "like", "what", "when",
         "site", "page", "host", "user", "data", "file", "code", "test", "some"}

_TITLE_RE = re.compile(r'^title:\s*"?(.+?)"?\s*$', re.M)
# trigger：「什麼情況下需要這篇」。2026-09-23 加——KB 記的都是結論，
# 而查詢是處境，兩者詞彙對不上正是檢索漏接的主因（見 kb_eval.py）。
_TRIGGER_RE = re.compile(r'^trigger:\s*"?(.+?)"?\s*$', re.M)
_SUMMARY_RE = re.compile(r'^summary:\s*"?(.+?)"?\s*$', re.M)


def _doc_type(path: Path, rel: str) -> str:
    """型別優先看目錄再看檔名前綴——wiki/ 的頁沒有前綴慣例，只能靠目錄認。"""
    if rel.startswith("Lessons/"):
        return "lesson"
    if rel.startswith("wiki/"):
        return "wiki"
    if rel.startswith("References/"):
        return "reference"
    for prefix, kind in PREFIX_TYPE:
        if path.stem.startswith(prefix):
            return kind
    return ""


_corpus_cache: dict[bool, tuple[str, list[dict]]] = {}
_EXPECTED_REPR_VERSION = 2  # lifecycle/type-aware corpus; invalidates old projections
_last_index_status = "not-used"


def _write_receipt(query: str) -> None:
    """Write a receipt so wiki_before_web_gate.sh knows KB was consulted.

    PRIMARY receipt is PROJECT-LOCAL, not TMPDIR-keyed: this CLI runs under the Bash
    tool's TMPDIR, but the WebSearch/WebFetch PreToolUse hook runs with a DIFFERENT
    (or unset) TMPDIR, so a TMPDIR-only receipt was never found by the gate — it
    blocked 100% of web searches (a dead gate). The project path is derived the same
    way on both sides (CLAUDE_PROJECT_DIR, else the vault root above automation/), so
    writer and reader always agree. The gate applies a freshness window to keep it
    session-ish. The legacy TMPDIR receipt is still written for back-compat.
    """
    import os
    import tempfile
    import time
    stamp = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {query[:180]}"
    root = os.environ.get("CLAUDE_PROJECT_DIR")
    proj_root = Path(root) if root else Path(__file__).resolve().parents[1]
    try:
        d = proj_root / "automation" / "active_sessions"
        d.mkdir(parents=True, exist_ok=True)
        (d / ".kb_queried").write_text(stamp, encoding="utf-8")
    except OSError:
        pass
    with suppress(OSError):  # back-compat
        (Path(tempfile.gettempdir()) / "bb_kb_queried").write_text(stamp, encoding="utf-8")


def corpus(refresh: bool = False, root: Path | None = None,
           include_history: bool = False) -> list[dict]:
    """KB 語料的唯一定義。所有檢索入口都該從這裡拿文件，不要自己 glob。

    `root` 覆寫語料根目錄（測試用 tmp_path 隔離語料，呼叫端也可指定別的 KB）。
    只有預設 root 會用快取——覆寫時每次重掃，因為 tmp 目錄的內容隨測試而變。
    """
    global _corpus_cache
    base = root or KB_DIR
    use_cache = root is None
    files = []
    state = hashlib.sha256(str(base).encode())
    for md in sorted(base.rglob("*.md")):
        rel = md.relative_to(base)
        skip = SKIP_PARTS - ({"_archive"} if include_history else set())
        if skip & set(rel.parts) or not _doc_type(md, rel.as_posix()):
            continue
        stat = md.stat()
        state.update(f"{rel}:{stat.st_mtime_ns}:{stat.st_size}".encode())
        files.append(md)
    signature = state.hexdigest()
    cached = _corpus_cache.get(include_history) if isinstance(_corpus_cache, dict) else None
    if use_cache and cached and cached[0] == signature and not refresh:
        return cached[1]
    docs = []
    for md in files:
        rel = md.relative_to(base)
        kind = _doc_type(md, rel.as_posix())
        if not kind:
            continue
        try:
            text = md.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        try:
            fm = fm_of(text) if text.startswith("---") else {}
        except ValueError as exc:
            print(f"[kb_retrieval] 略過無法解析的 {rel}: {exc}", file=sys.stderr)
            continue
        status = str(fm.get("status", "active")).lower()
        if not include_history and status in INACTIVE_STATUSES:
            continue
        explicit_type = str(fm.get("type", "")).lower()
        if explicit_type in {"reference", "rule"}:
            kind = explicit_type
        front = text.split("---", 2)[1] if text.startswith("---") else text[:1200]
        tm, sm = _TITLE_RE.search(front), _SUMMARY_RE.search(front)
        tr = _TRIGGER_RE.search(front)
        docs.append({
            "doc_id": md.stem,
            "path": rel.as_posix(),
            "type": kind,
            "title": str(fm.get("title") or (tm.group(1) if tm else md.stem)),
            "summary": str(fm.get("summary") or (sm.group(1) if sm else "")),
            "trigger": str(fm.get("trigger") or (tr.group(1) if tr else "")),
            "status": status,
            "text": text,
            "mtime": md.stat().st_mtime,
        })
    if use_cache:
        if not isinstance(_corpus_cache, dict):
            _corpus_cache = {}
        _corpus_cache[include_history] = (signature, docs)
    return docs


def _tokenize(text: str) -> list[str]:
    return re.findall(r'[a-z]{2,}|[一-鿿]+', text.lower())


def lexical(terms: list[str], docs: list[dict] | None = None,
            doc_type: str = "", limit: int = 5, root: Path | None = None,
            include_history: bool = False) -> list[dict]:
    """可稽核的字面比對。標題命中權重 3，內文 1，`why` 保留是哪些詞命中。

    這是 kb_connector.kb_documents 的評分法，原樣保留——它的價值在於
    worker 看得到「為什麼選這篇」，不必相信一個不透明的分數。
    """
    want = [t.lower().strip() for t in terms if t and t.strip()]
    if not want:
        return []
    out = []
    for d in docs if docs is not None else corpus(root=root, include_history=include_history):
        if not include_history and d.get("status") in INACTIVE_STATUSES:
            continue
        if d["doc_id"] in _NAV:
            continue
        if doc_type and d["type"] != doc_type:
            continue
        hay_title = f"{d['doc_id']} {d['title']}".lower()
        hay_body = d["text"].lower()
        score, matched = 0, []
        for term in want:
            if term in hay_title:
                score += 3
                matched.append(term)
            elif term in hay_body:
                score += 1
                matched.append(term)
        if score:
            out.append({**{k: d[k] for k in ("doc_id", "path", "type", "title", "summary")},
                        "score": float(score), "channel": "lexical",
                        "why": f"字面命中 {sorted(set(matched))}"})
    return sorted(out, key=lambda h: (-h["score"], h["doc_id"]))[:limit]


# --- semantic ---

def _embed_available() -> bool:
    return EMBED_PY.is_file()


def _corpus_fingerprint(docs: list[dict]) -> str:
    h = hashlib.sha256(f"representation:{_EXPECTED_REPR_VERSION}".encode())
    for d in docs:
        for key in ("path", "mtime", "type", "status", "text"):
            h.update(str(d.get(key, "")).encode())
    return h.hexdigest()[:16]


def _index_incompatible(index: dict) -> str | None:
    if not isinstance(index, dict):
        return "index must be an object"
    if index.get("repr_version") != _EXPECTED_REPR_VERSION:
        return "repr_version mismatch"
    if index.get("model") != EMBED_MODEL:
        return "model mismatch"
    paths, vectors = index.get("paths"), index.get("vectors")
    if not isinstance(paths, list) or not isinstance(vectors, list) or len(paths) != len(vectors):
        return "path/vector count mismatch"
    if not paths or any(not isinstance(path, str) for path in paths) or len(set(paths)) != len(paths):
        return "empty or duplicate paths"
    dim = index.get("embed_dim")
    if not isinstance(dim, int) or dim < 1:
        return "invalid embed_dim"
    for vector in vectors:
        if not isinstance(vector, list) or len(vector) != dim:
            return "stored vector dim mismatch"
        if any(not isinstance(x, (float, int)) or not math.isfinite(x) for x in vector):
            return "invalid vector values"
        if not any(vector):
            return "zero vector"
    hubness = index.get("hubness", {})
    if not isinstance(hubness, dict) or any(not isinstance(v, (float, int)) or not math.isfinite(v)
                                          for v in hubness.values()):
        return "invalid hubness"
    return None


def _index_unavailable(reason: str) -> None:
    global _last_index_status
    _last_index_status = reason if reason in {"no-index", "model-unavailable"} else "stale:" + reason
    print(f"[kb_retrieval] index unavailable: {reason}; lexical 仍可使用", file=sys.stderr)


def last_index_status() -> str:
    return _last_index_status


def _embed_texts(texts: list[str]) -> list[list[float]] | None:
    """在 .venv-kb 子行程裡編碼。主行程不需要裝 numpy/tokenizers。"""
    if not _embed_available():
        return None
    script = (
        "import sys, json, os\n"
        "os.environ.setdefault('HF_HOME', os.path.join(os.path.dirname(os.path.dirname("
        "os.path.dirname(sys.executable))), '.venv-kb', 'hf'))\n"
        "from model2vec import StaticModel\n"
        f"m = StaticModel.from_pretrained({EMBED_MODEL!r})\n"
        "texts = json.load(sys.stdin)\n"
        "print(json.dumps(m.encode(texts, show_progress_bar=False).tolist()))\n"
    )
    # HF_HUB_OFFLINE：模型抓過就存在 .venv-kb/hf/，檢索不該依賴網路。
    # 沒有這個旗標時 from_pretrained 會去 huggingface.co 查更新，在 sandbox 裡直接被擋掉。
    env = {**os.environ,
           "HF_HOME": str(VAULT_ROOT / ".venv-kb" / "hf"),
           "HF_HUB_OFFLINE": "1",
           "HF_HUB_DISABLE_XET": "1"}
    try:
        r = subprocess.run([str(EMBED_PY), "-c", script], input=json.dumps(texts),
                           capture_output=True, text=True, timeout=600, env=env)
        if r.returncode != 0:
            return None
        return json.loads(r.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None


def build_embed_index(force: bool = False, include_history: bool = False) -> dict:
    """建立／更新 embedding 索引。語料指紋沒變就不重建。"""
    docs = corpus(include_history=include_history)
    if not docs:
        return {"status": "unavailable", "reason": "empty corpus"}
    fp = _corpus_fingerprint(docs)
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    cache = INDEX_DIR / ("embeddings-history.json" if include_history else "embeddings.json")
    if cache.is_file() and not force:
        try:
            old = json.loads(cache.read_text())
            if not _index_incompatible(old) and old.get("fingerprint") == fp:
                return {"status": "current", "docs": len(old["paths"])}
        except (OSError, ValueError, KeyError):
            pass
    # 編碼對象：標題 + summary + 前 2000 字元本文。整篇丟進靜態 embedding 會被
    # 長尾雜訊稀釋，標題與摘要才是這篇在講什麼。
    # trigger 放最前面（而且因為短，權重自然高）：它和查詢同屬「處境」語域，
    # title/summary 屬「結論」語域。靜態 embedding 是詞向量平均，放前面沒有位置
    # 效果，但少了長尾稀釋——所以短而準的 trigger 天然佔比高。
    texts = [f"{(d.get('trigger') or '')}。{d['title']}。{d['summary']}。{d['text'][:2000]}"
             for d in docs]
    vecs = _embed_texts(texts)
    if not vecs:
        return {"status": "unavailable", "reason": "缺 .venv-kb 或模型未下載"}
    paths = [d["path"] for d in docs]
    index = {"fingerprint": fp, "model": EMBED_MODEL,
             "repr_version": _EXPECTED_REPR_VERSION, "embed_dim": len(vecs[0]),
             "paths": paths, "vectors": vecs}
    issue = _index_incompatible(index)
    if issue:
        return {"status": "unavailable", "reason": issue}
    index["hubness"] = _hubness(paths, vecs)
    cache.write_text(json.dumps(index))
    return {"status": "rebuilt", "docs": len(docs)}


def _hubness(paths: list[str], vecs: list[list[float]]) -> dict[str, float]:
    """每篇文件「對所有文件的平均相似度」超出全體平均的部分。

    靜態 embedding 下，長而主題廣的文件（索引頁、綜合型 lesson）會落在語料中心，
    對任何查詢都中等相似，於是在每個查詢裡都冒出來。kb_eval 實測 `Playbook Index`
    和 LL-315 出現在幾乎每一筆結果的前三名。

    這是 embedding 版的 IDF：檢索時把這個值減掉，只獎勵「特別像這個查詢」，
    不獎勵「像所有東西」。抽樣算（步進 4）——精度夠，全配對太慢。
    """
    norms = [sum(x * x for x in v) ** 0.5 or 1.0 for v in vecs]
    sample = list(range(0, len(vecs), 4)) or [0]
    means = []
    for i in range(len(vecs)):
        tot = sum(sum(a * b for a, b in zip(vecs[i], vecs[j], strict=True)) / (norms[i] * norms[j])
                  for j in sample if j != i)
        means.append(tot / max(1, len(sample) - (1 if i in sample else 0)))
    overall = sum(means) / len(means)
    return {p: round(max(0.0, m - overall), 4) for p, m in zip(paths, means, strict=True)}


# 導航頁：它們的內容就是「所有主題的清單」，embedding 因此落在語料正中央，
# 對任何查詢都中等相似。它們是目錄不是知識，檢索時排除。
_NAV = {"KB Catalogue", "Knowledge Base Index", "Pattern Index", "Playbook Index",
        "Checklist Index", "Lessons Learned", "index", "README", "Wiki Schema"}


def semantic(query: str, doc_type: str = "", limit: int = 5,
             min_score: float = 0.35, root: Path | None = None,
             include_history: bool = False) -> list[dict]:
    """語意召回。沒有索引或模型就回空——呼叫端的 lexical 結果不受影響。

    索引只為預設 KB 建；指定 root（例如測試的 tmp 語料）時直接回空，
    讓呼叫端完全退回 lexical，而不是拿別的語料的向量亂配。"""
    if root is not None:
        return []
    global _last_index_status
    cache = INDEX_DIR / ("embeddings-history.json" if include_history else "embeddings.json")
    if not cache.is_file():
        _index_unavailable("no-index")
        return []
    try:
        idx = json.loads(cache.read_text())
    except (OSError, ValueError):
        _index_unavailable("invalid JSON")
        return []
    docs = corpus(include_history=include_history)
    issue = _index_incompatible(idx)
    if not issue and idx.get("fingerprint") != _corpus_fingerprint(docs):
        issue = "corpus fingerprint mismatch; run --build-index"
    if issue:
        _index_unavailable(issue)
        return []
    qv = _embed_texts([query])
    if not qv:
        _index_unavailable("model-unavailable")
        return []
    q = qv[0]
    if len(q) != idx["embed_dim"] or any(not isinstance(x, (float, int)) or not math.isfinite(x) for x in q):
        _index_unavailable("query vector dim/values mismatch")
        return []
    if not any(q):
        _index_unavailable("zero query vector")
        return []
    qn = sum(x * x for x in q) ** 0.5 or 1.0
    by_path = {d["path"]: d for d in docs}
    _last_index_status = "current"
    hub = idx.get("hubness", {})
    out = []
    for path, vec in zip(idx["paths"], idx["vectors"], strict=True):
        d = by_path.get(path)
        if not d or (doc_type and d["type"] != doc_type):
            continue
        if d["doc_id"] in _NAV:
            continue
        vn = sum(x * x for x in vec) ** 0.5 or 1.0
        sim = sum(a * b for a, b in zip(q, vec, strict=True)) / (qn * vn)
        # hub 懲罰只改**排序**，不改**去留**。第一版把它也套在門檻上，hit@1 從 3 升到 5
        # 但 hit@5 從 9 掉到 8、漏接從 4 變 6——被減分的合法結果直接掉到門檻以下。
        # hubness 回答的是「這篇是不是對誰都像」，不是「這篇相不相關」。
        if sim >= min_score:
            rank_score = sim - hub.get(path, 0.0)
            out.append({**{k: d[k] for k in ("doc_id", "path", "type", "title", "summary")},
                        "score": round(rank_score, 4), "raw_sim": round(sim, 4),
                        "channel": "semantic",
                        "why": f"語意相似 {sim:.2f}（非字面命中）"})
    return sorted(out, key=lambda h: -h["score"])[:limit]


# --- 第三訊號（graph）：試過，量測說不要 ---
#
# 2026-09-23 做了 arXiv 2506.00049 的 tri-modal（dense + sparse + graph），
# 兩種圖都試過，結論都是不要接進檢索：
#
# 1. **embedding 相似度圖**（kb_graph.py，951 條邊）：零新增資訊。
#    邊是從同一批向量算的，所以「圖鄰居」依定義就是「語意覺得像」——
#    實測 LL-325 的 13 個鄰居有 12 個已經在語意 top-30 裡（92% 重疊）。
#
# 2. **wikilink 引用圖**（人工寫的，1205 條邊，與 embedding 圖只重疊 131 條 = 11%）：
#    確實是獨立訊號，但接上去 **hit@1/@5 完全沒動**。掃過權重：
#
#        weight ≤0.95  hit@1 5  hit@5 8  漏 6   （與基線相同——鄰居排不進前十）
#        weight 1.05   hit@1 3  hit@5 8  漏 5   （擠掉正確的直接命中）
#        weight 1.2    hit@1 2  hit@5 6  漏 6   （明顯更差）
#
#    任何看得見效果的權重，損失的精確度都大於換來的召回。
#
# 誠實邊界：kb_eval 只有 14 題，而且沒有一題是「正解是某個明顯命中的鄰居」
# 這種形狀——圖展開真正該發揮作用的場景。所以這是「在這組評測上沒有效益」，
# 不是「圖一定沒用」。要重做這個實驗：kb_graph.py 仍在，圖也還在
# automation/.kb_index/，補幾題那種形狀的 case 再測。

def search(query: str = "", terms: list[str] | None = None, doc_type: str = "",
           limit: int = 5, root: Path | None = None,
           include_history: bool = False) -> list[dict]:
    """混合檢索。lexical 與 semantic 各自跑，同一篇兩邊都中就相加並保留兩個理由。

    lexical 分數是 3/1 的整數計分，semantic 是 0–1 的相似度，量綱不同；
    lexical 先除以 3 正規化到「命中幾個關鍵詞」的量級，再與相似度相加。
    這個權重是拍的，不是調出來的——真要調得有 query log。
    """
    # 2026-09-22 kb_eval 實測：對自然語言查詢自動抽詞會害事。中文被 `[一-鿿]+`
    # 切成「這個寫死在」這種整串，當關鍵詞沒有意義；而混在句子裡的英文常用字
    # （app、api）會字面命中一堆不相干的文件並拿到滿分，把正解擠出前十。
    # 純語意 hit@5 9/14，自動抽詞的混合反而掉到 5 miss。
    # 所以：呼叫端明講的 terms（ASG 的 tech[]、指紋）才走字面通道；
    # 沒明講時只從 query 撿「像術語」的詞——長度 ≥4 的 ASCII，或帶數字/連字號。
    # 2026-09-23：呼叫端**沒有明講** terms 時，完全不跑字面通道。
    # 掃過權重（lexical 分數除以 3/6/10/20/50/1000）：hit@1 一路是 7、hit@5 一路是 8，
    # 只有權重等同關閉（/1000）時 hit@5 才回到純語意的 9。**任何權重下字面通道
    # 對自然語言查詢都沒有正貢獻**，最好的情況是持平，其餘是把正解擠下去——
    # 一個標題字面命中就是 3/3=1.0，壓過任何語意分數（上限約 0.7）。
    #
    # 明講 terms 的呼叫端（ASG 的 tech[]、surface_kb 的技術指紋）照舊走字面通道，
    # 那裡的詞是術語不是句子，`why` 也才能給出可稽核的 matched_terms。
    explicit_terms = terms is not None
    lex = (lexical(terms, doc_type=doc_type, limit=limit * 2, root=root, include_history=include_history)
           if explicit_terms and terms else [])
    sem = semantic(query, doc_type=doc_type, limit=limit * 2, root=root,
                   include_history=include_history) if query else []
    if query and not explicit_terms and not sem and (root is not None or last_index_status() != "current"):
        lex = lexical([query], doc_type=doc_type, limit=limit * 2, root=root,
                      include_history=include_history)
    merged: dict[str, dict] = {}
    for h in lex:
        merged[h["path"]] = {**h, "score": h["score"] / 3.0, "channels": ["lexical"]}
    for h in sem:
        if h["path"] in merged:
            m = merged[h["path"]]
            m["score"] += h["score"]
            m["channels"].append("semantic")
            m["why"] += f"；{h['why']}"
        else:
            merged[h["path"]] = {**h, "channels": ["semantic"]}
    for m in merged.values():
        m.pop("channel", None)
    _write_receipt(query)
    return sorted(merged.values(), key=lambda h: -h["score"])[:limit]


def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="KB 檢索（lexical + semantic 混合）")
    p.add_argument("query", nargs="*", help="查詢字串")
    p.add_argument("--type", default="", help="限定型別 lesson/pattern/wiki/…")
    p.add_argument("--limit", type=int, default=8)
    p.add_argument("--build-index", action="store_true", help="重建 embedding 索引")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--include-history", action="store_true", help="包括退役狀態與 _archive/；不改現行預設")
    a = p.parse_args()
    if a.build_index:
        result = build_embed_index(force=True, include_history=a.include_history)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result.get("status") in {"rebuilt", "current"} else 2
    if a.stats:
        import collections
        docs = corpus(include_history=a.include_history)
        c = collections.Counter(d["type"] for d in docs)
        print(f"語料 {len(docs)} 篇：{dict(c)}")
        print(f"embedding 索引：{'有' if (INDEX_DIR / 'embeddings.json').is_file() else '無'}"
              f"｜模型環境：{'有' if _embed_available() else '無'}")
        return 0
    if not a.query:
        p.print_help()
        return 1
    for h in search(" ".join(a.query), doc_type=a.type, limit=a.limit, include_history=a.include_history):
        print(f"{h['score']:.3f}  [{h['type']}] {h['title'][:64]}")
        print(f"        {h['why']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
