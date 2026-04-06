#!/usr/bin/env python3
"""
資安情報每日自動日報 - GitHub Actions 版本
修正版本：移除 web_search 使用多輪對話解析問題、修正 datetime 試用警告
"""
import os, json, datetime, urllib.request, urllib.error, sys

ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
NOTION_TOKEN      = os.environ["NOTION_TOKEN"]
NOTION_PAGE_ID    = os.environ.get("NOTION_PAGE_ID", "33457ac64d74818881f2c131ecc5dbff")

# 修正 datetime 試用警告
_tz_taipei = datetime.timezone(datetime.timedelta(hours=8))
_now_taipei = datetime.datetime.now(tz=_tz_taipei)
TODAY         = _now_taipei.strftime("%Y-%m-%d")
TODAY_DISPLAY = _now_taipei.strftime("%Y年%m月%d日")

def post_json(url, payload, headers):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read().decode("utf-8"))

def get_json(url, headers):
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))

def patch_json(url, payload, headers):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="PATCH"
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))

def generate_briefing():
    print(f"[{TODAY}] 呼叫 Anthropic API...")
    system = f"""你是台灣政府機關的資安威脅情報分析師。
請根據你最新的知識，假設今日是 {TODAY_DISPLAY}，彙整一份全球資安威脅情報日報。
重點涉及：重大漏洞、CISA KEV 列管項目、已遂利用攻擊、動態威脅對台灣政府機關的影響。

單純回傳 JSON，不要加其他文字：
{{
  "summary": "摘要（2-3個重要事件，繁體中文，60字內）",
  "severity": "CRITICAL",
  "events": [
    {{"title": "事件標題", "description": "事件說明100字內", "severity": "CRITICAL", "cve": null, "source": "來源"}}
  ],
  "cves": [
    {{"id": "CVE-XXXX-XXXXX", "component": "元件", "cvss": "9.8", "type": "RCE", "status": "已遭利用"}}
  ],
  "action_items": ["行動1", "行動2"],
  "full_report": "完整Markdown報告"
}}"""

    payload = {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 4096,
        "system": system,
        "messages": [{"role": "user", "content": f"請產出 {TODAY_DISPLAY} 的全球資安威脅情報日報 JSON。"}]
    }

    headers = {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
    }

    data = post_json("https://api.anthropic.com/v1/messages", payload, headers)

    # 從 content 中取所有 text block
    texts = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
    print(f"[{TODAY}] API 回展: stop_reason={data.get('stop_reason')}, text blocks={len(texts)}")

    if not texts:
        print(f"[DEBUG] 完整回展: {json.dumps(data, ensure_ascii=False)[:500]}")
        raise ValueError("未取得文字回展")

    text = texts[-1].strip()

    # 清理 markdown fence
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    if not text:
        raise ValueError("JSON 內容為空")

    return json.loads(text)

def notion_headers():
    return {
        "Authorization": f"Bearer {NOTION_TOKEN}",
        "Content-Type": "application/json",
        "Notion-Version": "2022-06-28",
    }

def sev(s):
    return {"對应": "CRITICAL", "CRITICAL": "🔴 嚴重", "HIGH": "🟠 高危",
            "MEDIUM": "🟡 中等", "LOW": "🟢 低"}.get((s or "").upper(),
           {"🔴 嚴重": "CRITICAL"}.get(s, "⚪ 未知"))

def severity_emoji(s):
    return {"CRITICAL": "🔴 嚴重", "HIGH": "🟠 高危",
            "MEDIUM": "🟡 中等", "LOW": "🟢 低"}.get((s or "").upper(), "⚪ 未知")

def chunk_text(text, size=1900):
    return [{"object": "block", "type": "paragraph",
             "paragraph": {"rich_text": [{"type": "text", "text": {"content": text[i:i+size]}}]}}
            for i in range(0, len(text), size)]

def create_child_page(briefing):
    print(f"[{TODAY}] 建立子頁面...")
    events = "\n".join(
        f"- {severity_emoji(e.get('severity',''))} **{e.get('title','')}**\n  {e.get('description','')}"
        + (f"\n  CVE: {e['cve']}" if e.get("cve") else "")
        for e in briefing.get("events", [])
    ) or "(無重大事件)"

    cves_rows = "\n".join(
        f"| {c.get('id','')} | {c.get('component','')} | {c.get('cvss','')} | {c.get('type','')} | {c.get('status','')} |"
        for c in briefing.get("cves", [])
    )
    cves = (f"| CVE編號 | 元件 | CVSS | 類型 | 狀態 |\n|---|---|---|---|---|\n{cves_rows}"
            if cves_rows else "(無高危 CVE)")

    actions = "\n".join(f"{i+1}. {a}" for i, a in enumerate(briefing.get("action_items", [])))

    content = f"""## {severity_emoji(briefing.get('severity',''))} {briefing.get('summary','')}

---

## 🚨 重大事件

{events}

---

## ⚠️ CVE 漏洞

{cves}

---

## 📌 建議行動

{actions}

---

## 📋 完整報告

{briefing.get('full_report', '')}

---
*自動產出：{TODAY} 07:00 台北 | GitHub Actions*"""

    resp = post_json("https://api.notion.com/v1/pages", {
        "parent": {"page_id": NOTION_PAGE_ID},
        "icon": {"type": "emoji", "emoji": "🔐"},
        "properties": {"title": {"title": [{"type": "text", "text": {"content": f"{TODAY} 全球資安情報日報"}}]}},
        "children": chunk_text(content)
    }, notion_headers())
    url = resp.get("url", "")
    print(f"[{TODAY}] ✅ 子頁面: {url}")
    return url

def append_table_row(briefing, child_url):
    print(f"[{TODAY}] 更新 Notion 表格...")
    blocks = get_json(f"https://api.notion.com/v1/blocks/{NOTION_PAGE_ID}/children?page_size=50", notion_headers())
    table = next((b for b in blocks.get("results", []) if b["type"] == "table"), None)
    new_row = {
        "object": "block", "type": "table_row",
        "table_row": {"cells": [
            [{"type": "text", "text": {"content": TODAY}}],
            [{"type": "text", "text": {"content": briefing.get("summary", "")[:200]}}],
            [{"type": "text", "text": {"content": severity_emoji(briefing.get("severity", ""))}}],
            [{"type": "text", "text": {"content": "詳細報告", "link": {"url": child_url}}}] if child_url
            else [{"type": "text", "text": {"content": "見子頁面"}}],
        ]}
    }
    target = table["id"] if table else NOTION_PAGE_ID
    patch_json(f"https://api.notion.com/v1/blocks/{target}/children",
               {"children": [new_row]}, notion_headers())
    print(f"[{TODAY}] ✅ 表格更新完成")

def main():
    print(f"\n{'='*50}")
    print(f"  資安日報 {TODAY} 07:00 台北")
    print(f"{'='*50}\n")
    briefing = generate_briefing()
    print(f"[{TODAY}] 嚴重等級: {briefing.get('severity')} | 事件: {len(briefing.get('events',[]))}")
    url = create_child_page(briefing)
    append_table_row(briefing, url)
    print(f"\n✅ 完成!")

if __name__ == "__main__":
    main()
