#!/usr/bin/env python3
"""
資安情報每日自動日報 - GitHub Actions 版本 (全盤優化版)
特點：
1. OSINT 資訊蒐集 (RSS Feed Parsing) 以減少幻覺
2. Anthropic Tool Use (Function Calling) 強制穩定輸出 JSON Schema
3. 新增獨立欄位：台灣影響評估
4. 原生 Notion Blocks API 排版，避免長字串硬切斷導致破版
"""
import os
import json
import datetime
import time
import requests
import feedparser

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
NOTION_TOKEN      = os.environ.get("NOTION_TOKEN", "")
NOTION_PAGE_ID    = os.environ.get("NOTION_PAGE_ID", "33457ac64d74818881f2c131ecc5dbff")

_tz_taipei = datetime.timezone(datetime.timedelta(hours=8))
_now_taipei = datetime.datetime.now(tz=_tz_taipei)
TODAY         = _now_taipei.strftime("%Y-%m-%d")
TODAY_DISPLAY = _now_taipei.strftime("%Y年%m月%d日")

# ==========================================
# 模組 1: OSINT 資訊蒐集 (RSS Feed Parsing)
# ==========================================
def fetch_rss_news():
    print(f"[{TODAY}] 正在抓取最新 RSS 資安新聞...")
    feeds = [
        {"name": "iThome 資安", "url": "https://www.ithome.com.tw/rss/security"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"}
    ]
    
    news_items = []
    for f in feeds:
        try:
            parsed = feedparser.parse(f["url"])
            count = 0
            for entry in parsed.entries:
                # 簡單過濾：只取發布時間在 48 小時內的新聞 (簡易判斷: 假設 RSS 都是照新舊排，取前 5 筆)
                if count >= 5: break
                title = entry.get("title", "")
                summary = entry.get("summary", "")[:200]  # 截斷摘要避免過長
                news_items.append(f"【{f['name']}】: {title}\n摘要: {summary}")
                count += 1
        except Exception as e:
            print(f"抓取 {f['name']} 失敗: {e}")

    context = "\n\n".join(news_items)
    print(f"[{TODAY}] 抓取完成，共 {len(news_items)} 篇參考新聞。")
    return context

# ==========================================
# 模組 2: Anthropic API & Tool Use 解析
# ==========================================
def generate_briefing(news_context, retries=2):
    print(f"[{TODAY}] 呼叫 Anthropic API 產生格式化報告...")
    
    system_prompt = f"""你是台灣政府機關的頂級資安威脅情報分析師。
今天是 {TODAY_DISPLAY}。你將收到今日最新的全球資安新聞（由 RSS 抓取）。
請根據這些真實新聞進行分析、摘要、過濾，並填入規定的格式中輸出。
如果新聞中提及重大漏洞 (CVE)、已遂利用情形、或是與台灣基礎設施及政府機關有關的威脅（例如 APT 攻擊、網釣攻擊、勒索軟體），請特別突顯並放入影響評估中。如果你覺得需要補充你的專業知識，請合併說明，但切勿瞎掰沒有發生的事件。"""

    tools = [
        {
            "name": "generate_daily_briefing",
            "description": "產生結構化的資安威脅日報",
            "input_schema": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string", "description": "摘要（2-3個重要事件綜合描述，繁體中文，100字內）"},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"], "description": "今日整體嚴重等級"},
                    "events": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string", "description": "事件標題"},
                                "description": {"type": "string", "description": "事件說明 100 字內（繁體中文）"},
                                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                                "cve": {"type": "string", "description": "相關 CVE，若無填 null"},
                                "cisa_kev_listed": {"type": "boolean", "description": "是否被 CISA KEV 列管為已遭利用漏洞"},
                                "source": {"type": "string", "description": "資訊來源(可填報紙或機構名稱)"}
                            },
                            "required": ["title", "description", "severity", "cisa_kev_listed"]
                        }
                    },
                    "cves": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string", "description": "CVE ID，如 CVE-2024-XXXX"},
                                "component": {"type": "string", "description": "受影響元件/軟體"},
                                "cvss": {"type": "string", "description": "評分，如 9.8"},
                                "type": {"type": "string", "description": "類型，如 RCE, XSS"},
                                "status": {"type": "string", "description": "如 '已遭利用' 或 '尚未修補' 等"}
                            },
                            "required": ["id", "component", "cvss", "type", "status"]
                        }
                    },
                    "taiwan_impact_assessment": {
                        "type": "string", 
                        "description": "針對今日情報對台灣政府機關及企業的在地影響專案評估（繁體中文，約100-200字）"
                    },
                    "action_items": {
                        "type": "array",
                        "items": {"type": "string", "description": "建議資安團隊採取的防護行動（繁體中文）"}
                    }
                },
                "required": ["summary", "severity", "events", "cves", "taiwan_impact_assessment", "action_items"]
            }
        }
    ]

    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    
    payload = {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 4096,
        "system": system_prompt,
        "tools": tools,
        "tool_choice": {"type": "tool", "name": "generate_daily_briefing"},
        "messages": [
            {
                "role": "user", 
                "content": f"以下是今日抓取到的資安新聞摘要，請呼叫 generate_daily_briefing 工具來產出 {TODAY_DISPLAY} 日報：\n\n<news>\n{news_context}\n</news>"
            }
        ]
    }

    for attempt in range(retries):
        try:
            resp = requests.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers, timeout=120)
            resp.raise_for_status()
            data = resp.json()
            
            for content in data.get("content", []):
                if content.get("type") == "tool_use" and content.get("name") == "generate_daily_briefing":
                    print(f"[{TODAY}] 解析成功！")
                    return content.get("input", {})
            
            raise ValueError("API 未回傳預期的 tool_use 內容。")
            
        except Exception as e:
            print(f"[{TODAY}] 第 {attempt+1} 次 API 呼叫/解析失敗: {e}")
            if attempt < retries - 1:
                time.sleep(3)
            else:
                raise

# ==========================================
# 模組 3: Notion API (Blocks API 改寫)
# ==========================================
def notion_headers():
    return {
        "Authorization": f"Bearer {NOTION_TOKEN}",
        "Content-Type": "application/json",
        "Notion-Version": "2022-06-28",
    }

def severity_emoji(s):
    return {"CRITICAL": "🔴 嚴重", "HIGH": "🟠 高危",
            "MEDIUM": "🟡 中等", "LOW": "🟢 低"}.get((s or "").upper(), "⚪ 未知")

def create_heading(level, text):
    headers = {1: "heading_1", 2: "heading_2", 3: "heading_3"}
    t = headers.get(level, "heading_2")
    return {
        "object": "block",
        "type": t,
        t: {"rich_text": [{"type": "text", "text": {"content": text}}]}
    }

def create_paragraph(text, color="default"):
    return {
        "object": "block",
        "type": "paragraph",
        "paragraph": {
            "rich_text": [{"type": "text", "text": {"content": text}}],
            "color": color
        }
    }

def create_bullet_item(text):
    return {
        "object": "block",
        "type": "bulleted_list_item",
        "bulleted_list_item": {"rich_text": [{"type": "text", "text": {"content": text}}]}
    }

def create_table(headers, rows):
    # Table block
    tb = {
        "object": "block",
        "type": "table",
        "table": {
            "table_width": len(headers),
            "has_column_header": True,
            "has_row_header": False,
            "children": []
        }
    }
    
    def make_row(cells):
        return {
            "type": "table_row",
            "table_row": {
                "cells": [[{"type": "text", "text": {"content": str(cell)}}] for cell in cells]
            }
        }
    
    tb["table"]["children"].append(make_row(headers))
    for r in rows:
        tb["table"]["children"].append(make_row(r))
        
    return tb

def create_child_page(briefing):
    print(f"[{TODAY}] 建立 Notion 子頁面...")
    
    blocks = []
    
    # -- 標題與摘要 --
    summary = briefing.get('summary', '')
    sev = severity_emoji(briefing.get('severity', ''))
    blocks.append(create_heading(2, f"{sev} 核心摘要"))
    blocks.append(create_paragraph(summary))
    blocks.append({"object": "block", "type": "divider", "divider": {}})
    
    # -- 台灣當地影響評估 --
    impact = briefing.get('taiwan_impact_assessment', '')
    if impact:
        blocks.append(create_heading(2, "🇹🇼 台灣政府與企業影響評估"))
        blocks.append(create_paragraph(impact, color="purple_background"))
        blocks.append({"object": "block", "type": "divider", "divider": {}})

    # -- 重大事件 --
    blocks.append(create_heading(2, "🚨 今日重大事件"))
    events = briefing.get("events", [])
    if events:
        for e in events:
            text = f"{severity_emoji(e.get('severity',''))} {e.get('title','')} \n{e.get('description','')}"
            if e.get("cisa_kev_listed"):
                text += " [⚠️ 列入 CISA KEV 已被利用]"
            if e.get("cve"):
                text += f" (CVE: {e.get('cve')})"
            if e.get("source"):
                text += f" - 來源:{e.get('source')}"
            blocks.append(create_bullet_item(text))
    else:
        blocks.append(create_paragraph("(無重大事件)"))
        
    blocks.append({"object": "block", "type": "divider", "divider": {}})

    # -- CVE 漏洞 --
    blocks.append(create_heading(2, "⚠️ 焦點 CVE 漏洞"))
    cves = briefing.get("cves", [])
    if cves:
        headers = ["CVE編號", "元件", "CVSS", "類型", "狀態"]
        rows = [
            [c.get("id",""), c.get("component",""), c.get("cvss",""), c.get("type",""), c.get("status","")] 
            for c in cves
        ]
        blocks.append(create_table(headers, rows))
    else:
        blocks.append(create_paragraph("(無高危 CVE)"))

    blocks.append({"object": "block", "type": "divider", "divider": {}})

    # -- 建議行動 --
    blocks.append(create_heading(2, "📌 建議防護行動"))
    actions = briefing.get("action_items", [])
    if actions:
        for a in actions:
            blocks.append(create_bullet_item(a))
    else:
        blocks.append(create_paragraph("(無特殊建議)"))

    blocks.append({"object": "block", "type": "divider", "divider": {}})
    blocks.append(create_paragraph(f"自動產出：{TODAY} 07:00 台北 | GitHub Actions & Claude-3.5-Sonnet (加入RSS來源)", color="gray"))

    # 送出建立請求
    parent_data = {
        "parent": {"page_id": NOTION_PAGE_ID},
        "icon": {"type": "emoji", "emoji": "🔐"},
        "properties": {"title": {"title": [{"type": "text", "text": {"content": f"{TODAY} 全球資安情報日報"}}]}},
        "children": blocks
    }
    
    resp = requests.post("https://api.notion.com/v1/pages", json=parent_data, headers=notion_headers())
    if resp.status_code != 200:
        print(f"[ERROR] 建立子頁面失敗: {resp.text}")
        return ""
    
    url = resp.json().get("url", "")
    print(f"[{TODAY}] ✅ 子頁面建立成功: {url}")
    return url

def append_table_row(briefing, child_url):
    print(f"[{TODAY}] 更新 Notion 主頁表格...")
    
    # 嘗試取得主頁面子區塊的 Table
    resp = requests.get(f"https://api.notion.com/v1/blocks/{NOTION_PAGE_ID}/children?page_size=50", headers=notion_headers())
    blocks = resp.json().get("results", [])
    table = next((b for b in blocks if b["type"] == "table"), None)
    
    if not table:
        print(f"[{TODAY}] ⚠️ 找不到表格，跳過新增列。")
        return

    new_row = {
        "object": "block",
        "type": "table_row",
        "table_row": {"cells": [
            [{"type": "text", "text": {"content": TODAY}}],
            [{"type": "text", "text": {"content": briefing.get("summary", "")[:200]}}],
            [{"type": "text", "text": {"content": severity_emoji(briefing.get("severity", ""))}}],
            [{"type": "text", "text": {"content": "詳細報告", "link": {"url": child_url}}}] if child_url
            else [{"type": "text", "text": {"content": "見子頁面"}}],
        ]}
    }
    
    target_id = table["id"]
    patch_resp = requests.patch(
        f"https://api.notion.com/v1/blocks/{target_id}/children",
        json={"children": [new_row]}, 
        headers=notion_headers()
    )
    
    if patch_resp.status_code == 200:
        print(f"[{TODAY}] ✅ 表格更新完成")
    else:
        print(f"[ERROR] 更新表格失敗: {patch_resp.text}")

def main():
    print(f"\n{'='*50}")
    print(f"  資安日報 {TODAY} 07:00 台北")
    print(f"{'='*50}\n")
    
    # 執行流程
    news_context = fetch_rss_news()
    briefing = generate_briefing(news_context)
    
    print(f"[{TODAY}] 嚴重等級: {briefing.get('severity')} | 事件數: {len(briefing.get('events',[]))}")
    
    url = create_child_page(briefing)
    if url:
        append_table_row(briefing, url)
        
    print(f"\n✅ 流程全部完成!")

if __name__ == "__main__":
    main()
