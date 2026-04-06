#!/usr/bin/env python3
"""
資安情報每日自動日報
GitHub Actions 版本 — 無執行時間限制，完全免費
使用 Python 標準函式庫 urllib，無需安裝任何套件
"""

import os, json, datetime, urllib.request, urllib.error, sys

ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
NOTION_TOKEN      = os.environ["NOTION_TOKEN"]
NOTION_PAGE_ID    = os.environ.get("NOTION_PAGE_ID", "33457ac64d74818881f2c131ecc5dbff")

TODAY         = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y-%m-%d")
TODAY_DISPLAY = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%Y年%m月%d日")

def api_call(url, payload, headers):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.loads(r.read().decode())

def generate_briefing():
    print(f"[{TODAY}] 呼叫 Anthropic API 產出日報...")
    system = f"""你是台灣政府機關的資安威脅情報分析師。
請搜尋並彙整今日（{TODAY_DISPLAY}）過去24小時內，全球主要資安媒體的重要新聞事件。
重點來源：The Hacker News、BleepingComputer、SecurityWeek、CISA KEV、Check Point Research、Cybernews。

嚴格只輸出 JSON，不輸出其他文字，格式如下：
{{
  "summary": "本日最重要 2-3 個事件摘要（繁體中文，60字內）",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "events": [
    {{
      "title": "事件標題（繁體中文）",
      "description": "事件說明（100字內）",
      "severity": "CRITICAL|HIGH|MEDIUM",
      "cve": "CVE-XXXX-XXXXX 或 null",
      "source": "來源媒體"
    }}
  ],
  "cves": [
    {{
      "id": "CVE-XXXX-XXXXX",
      "component": "影響元件",
      "cvss": "分數",
      "type": "漏洞類型",
      "status": "已遭利用/CISA KEV/修補中"
    }}
  ],
  "action_items": ["行動項目1", "行動項目2", "行動項目3"],
  "full_report": "完整繁體中文 Markdown 日報（含所有分析細節）"
}}"""

    data = api_call(
        "https://api.anthropic.com/v1/messages",
        {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 4096,
            "system": system,
            "tools": [{"type": "web_search_20250305", "name": "web_search"}],
            "messages": [{"role": "user", "content": f"請搜尋 {TODAY_DISPLAY} 過去24小時的全球資安威脅情報，輸出 JSON 格式報告。"}]
        },
        {
            "Content-Type": "application/json",
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
        }
    )

    text = next(
        (b["text"] for b in reversed(data.get("content", [])) if b.get("type") == "text"),
        ""
    ).strip()
    for fence in ["```json", "```"]:
        if text.startswith(fence):
            text = text[len(fence):]
    text = text.rstrip("`").strip()
    return json.loads(text)

def notion_headers():
    return {
        "Authorization": f"Bearer {NOTION_TOKEN}",
        "Content-Type": "application/json",
        "Notion-Version": "2022-06-28",
    }

def severity_emoji(s):
    return {"🔴 嚴重": "CRITICAL", "🟠 高危": "HIGH", "🟡 中等": "MEDIUM", "🟢 低": "LOW"}.get(
        (s or "").upper(), "⚪ 未知"
    )

def severity_emoji(s):
    m = {"CRITICAL": "🔴 嚴重", "HIGH": "🟠 高危", "MEDIUM": "🟡 中等", "LOW": "🟢 低"}
    return m.get((s or "").upper(), "⚪ 未知")

def chunk_text(text, size=1900):
    return [
        {"object": "block", "type": "paragraph",
         "paragraph": {"rich_text": [{"type": "text", "text": {"content": text[i:i+size]}}]}}
        for i in range(0, len(text), size)
    ]

def create_child_page(briefing):
    print(f"[{TODAY}] 建立 Notion 子頁面...")
    events_md = "\n".join(
        f"- {severity_emoji(e['severity'])} **{e['title']}**\n  {e['description']}"
        + (f"\n  CVE: {e['cve']}" if e.get("cve") else "")
        for e in briefing.get("events", [])
    ) or "(今日無重大事件)"

    cves_md = (
        "| CVE 編號 | 元件 | CVSS | 類型 | 狀態 |\n|---|---|---|---|---|\n"
        + "\n".join(f"| {c['id']} | {c['component']} | {c['cvss']} | {c['type']} | {c['status']} |"
                    for c in briefing.get("cves", []))
    ) if briefing.get("cves") else "(今日無高危 CVE)"

    actions_md = "\n".join(f"{i+1}. {a}" for i, a in enumerate(briefing.get("action_items", [])))
    content = f"""## {severity_emoji(briefing['severity'])} 今日威脅態勢

{briefing.get('summary', '')}

---

## 重大事件

{events_md}

---

## CVE 高危漏洞

{cves_md}

---

## 建議行動

{actions_md}

---

## 完整分析報告

{briefing.get('full_report', '')}

---

*自動產出：{TODAY} 07:00 台北時間 | GitHub Actions*"""

    data = api_call(
        "https://api.notion.com/v1/pages",
        {
            "parent": {"page_id": NOTION_PAGE_ID},
            "icon": {"type": "emoji", "emoji": "🔐"},
            "properties": {
                "title": {"title": [{"type": "text", "text": {"content": f"{TODAY} 全球資安情報日報"}}]}
            },
            "children": chunk_text(content)
        },
        notion_headers()
    )
    url = data.get("url", "")
    print(f"[{TODAY}] ✅ 子頁面：{url}")
    return url

def append_table_row(briefing, child_url):
    print(f"[{TODAY}] 更新 Notion 主頁面表格...")
    req = urllib.request.Request(
        f"https://api.notion.com/v1/blocks/{NOTION_PAGE_ID}/children?page_size=50",
        headers=notion_headers(),
        method="GET"
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        blocks = json.loads(r.read().decode())

    table = next((b for b in blocks.get("results", []) if b["type"] == "table"), None)
    new_row = {
        "object": "block", "type": "table_row",
        "table_row": {
            "cells": [
                [{"type": "text", "text": {"content": TODAY}}],
                [{"type": "text", "text": {"content": briefing.get("summary", "")}}],
                [{"type": "text", "text": {"content": severity_emoji(briefing.get("severity", ""))}}],
                [{"type": "text", "text": {"content": "詳細報告", "link": {"url": child_url}}}]
                if child_url else
                [{"type": "text", "text": {"content": "見子頁面"}}],
            ]
        }
    }
    target_id = table["id"] if table else NOTION_PAGE_ID
    req2 = urllib.request.Request(
        f"https://api.notion.com/v1/blocks/{target_id}/children",
        data=json.dumps({"children": [new_row]}).encode(),
        headers=notion_headers(),
        method="PATCH"
    )
    with urllib.request.urlopen(req2, timeout=30) as r:
        r.read()
    print(f"[{TODAY}] ✅ 表格更新完成")

def main():
    print(f"\n{'='*55}")
    print(f"  資安情報日報  |  {TODAY} 07:00 台北時間")
    print(f"{'='*55}\n")
    briefing  = generate_briefing()
    print(f"[{TODAY}] 嚴重等級：{briefing.get('severity')} | 事件數：{len(briefing.get('events', []))}")
    child_url = create_child_page(briefing)
    append_table_row(briefing, child_url)
    print(f"\n✅ 完成！")

if __name__ == "__main__":
    main()
