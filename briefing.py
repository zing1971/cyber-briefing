#!/usr/bin/env python3
"""
資安情報每日自動日報 - GitHub Actions 版本 (全盤優化版 V2)
特點：
1. 擴大資料庫：增加 CISA, Dark Reading 等全球權威來源
2. 時效限制：嚴格過濾 24 小時內的新聞
3. URL 追溯：抓取原文連結並強制 LLM 提供，寫入 Notion 時轉為藍字超連結
"""
import os
import json
import datetime
import calendar
import time
import requests
import feedparser
import anthropic

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
NOTION_TOKEN      = os.environ.get("NOTION_TOKEN", "")
NOTION_PAGE_ID    = os.environ.get("NOTION_PAGE_ID", "33457ac64d74818881f2c131ecc5dbff")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")

_tz_taipei = datetime.timezone(datetime.timedelta(hours=8))
_now_taipei = datetime.datetime.now(tz=_tz_taipei)
TODAY         = _now_taipei.strftime("%Y-%m-%d")
TODAY_DISPLAY = _now_taipei.strftime("%Y年%m月%d日")

# ==========================================
# 模組 1: OSINT 資訊蒐集 (RSS Feed Parsing)
# ==========================================
def fetch_rss_news():
    print(f"[{TODAY}] 正在抓取過去 24 小時內的最新 RSS 資安新聞...")
    feeds = [
        {"name": "CISA Alerts", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
        {"name": "iThome 資安", "url": "https://www.ithome.com.tw/rss/security"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
        {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"},
        {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/"},
        {"name": "CyberScoop", "url": "https://cyberscoop.com/feed/"},
        {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml"}
    ]
    
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    twenty_four_hours_ago = now_utc - datetime.timedelta(hours=24)
    
    news_items = []
    
    for f in feeds:
        try:
            parsed = feedparser.parse(f["url"])
            count = 0
            for entry in parsed.entries:
                # 若能成功解析發布時間，則檢查是否在 24 小時內
                include_entry = False
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    entry_time = datetime.datetime.fromtimestamp(calendar.timegm(entry.published_parsed), datetime.timezone.utc)
                    if entry_time >= twenty_four_hours_ago:
                        include_entry = True
                else:
                    # 如果 RSS 沒有時間標籤，則預設取前 2 篇避免資料量過大
                    if count < 2:
                        include_entry = True
                
                if include_entry:
                    title = entry.get("title", "")
                    link = entry.get("link", "")
                    summary = entry.get("summary", "")[:200]
                    news_items.append(f"【{f['name']}】: {title}\nURL: {link}\n摘要: {summary}")
                    count += 1
                
                if count >= 8: # 每來源最多取 8 篇，保護 LLM Token 數
                    break
        except Exception as e:
            print(f"抓取 {f['name']} 失敗: {e}")

    context = "\n\n".join(news_items)
    print(f"[{TODAY}] 抓取完成，共 {len(news_items)} 篇有效參考新聞。")
    return context

# ==========================================
# 模組 2: Anthropic API & Tool Use 解析
# ==========================================
def generate_briefing(news_context, retries=2):
    print(f"[{TODAY}] 呼叫 Anthropic API 產生格式化報告...")
    
    system_prompt = f"""你是台灣政府機關的頂級資安威脅情報分析師。
今天是 {TODAY_DISPLAY}。你將收到過去 24 小時最新的全球資安新聞（由 RSS 抓取，附帶原始 URL）。
請根據這些真實新聞進行分析、摘要、過濾，並填入規定的格式中輸出。
要求：
1. 重大漏洞 (CVE)、已遂利用情形、或是與台灣基礎設施有關的威脅請優先列入。
2. 切勿瞎掰沒有發生的事件或無中生有。
3. 務必從提供的內容中提取對應的真實 URL 作為來源連結 (`source_url` 與 `reference_url`)，如果真的沒有就留空。"""

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
                                "source": {"type": "string", "description": "資訊來源媒體"},
                                "source_url": {"type": "string", "description": "對應的新聞原始 URL 連結"}
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
                                "status": {"type": "string", "description": "如 '已遭利用' 或 '尚未修補' 等"},
                                "reference_url": {"type": "string", "description": "有關此漏洞的參考連結"}
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

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    for attempt in range(retries):
        try:
            print(f"[{TODAY}] 正在呼叫 Claude API (claude-3-5-haiku-latest)...")
            response = client.messages.create(
                model="claude-3-5-haiku-latest",
                max_tokens=4096,
                system=system_prompt,
                tools=tools,
                tool_choice={"type": "tool", "name": "generate_daily_briefing"},
                messages=[
                    {
                        "role": "user",
                        "content": f"以下是今日抓取到的資安新聞摘要，請呼叫 generate_daily_briefing 工具來產出 {TODAY_DISPLAY} 日報：\n\n<news>\n{news_context}\n</news>"
                    }
                ]
            )

            for block in response.content:
                if block.type == "tool_use" and block.name == "generate_daily_briefing":
                    print(f"[{TODAY}] 解析成功！")
                    return block.input

            raise ValueError("API 未回傳預期的 tool_use 內容。")

        except anthropic.APIStatusError as e:
            print(f"[{TODAY}] 第 {attempt+1} 次 API 呼叫失敗 (HTTP {e.status_code}): {e.message}")
            if attempt < retries - 1:
                time.sleep(3)
            else:
                raise
        except Exception as e:
            print(f"[{TODAY}] 第 {attempt+1} 次錯誤: {e}")
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

def create_custom_bullet_item(rich_text_array):
    """
    rich_text_array 為 dict 陣列，例如: 
    [{"text": {"content": "文字", "link": {"url": "https..."}}}]
    """
    # 確保格式正確符合 Notion API
    formatted_array = []
    for rt in rich_text_array:
        item = {"type": "text", "text": {"content": rt.get("content", "")}}
        if rt.get("url"):
            item["text"]["link"] = {"url": rt.get("url")}
        if rt.get("bold"):
            item["annotations"] = {"bold": True}
        formatted_array.append(item)

    return {
        "object": "block",
        "type": "bulleted_list_item",
        "bulleted_list_item": {"rich_text": formatted_array}
    }

def create_table(headers, rows_dict):
    """
    rows_dict 為列表的列表，格式舉例:
    [ [ {"content": "Id", "url": "https..."} , ... ] ]
    """
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
    
    # Header row (純文字)
    header_cells = [[{"type": "text", "text": {"content": str(cell)}}] for cell in headers]
    tb["table"]["children"].append({"type": "table_row", "table_row": {"cells": header_cells}})
    
    # Data rows (可以包含 href/URL)
    for row in rows_dict:
        cells = []
        for cell in row:
            txt_obj = {"type": "text", "text": {"content": str(cell.get("content", ""))}}
            if cell.get("url"):
                txt_obj["text"]["link"] = {"url": cell.get("url")}
            cells.append([txt_obj])
        tb["table"]["children"].append({"type": "table_row", "table_row": {"cells": cells}})
        
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
            # 建立 Rich Text 陣列
            rt = []
            
            # 第一段：Emoji + 標題 (檢查有沒有超連結)
            title_text = f"{severity_emoji(e.get('severity',''))} {e.get('title','')} "
            rt.append({"content": title_text, "bold": True, "url": e.get("source_url")})
            
            # 第二段：描述
            desc_text = f"\n{e.get('description','')} "
            rt.append({"content": desc_text})
            
            # 第三段：警告標籤或來源
            meta_text = ""
            if e.get("cisa_kev_listed"):
                meta_text += "[⚠️ 列入 CISA KEV 已被利用] "
            if e.get("cve"):
                meta_text += f"(CVE: {e.get('cve')}) "
            if e.get("source"):
                meta_text += f"來源:{e.get('source')} "
                
            if meta_text:
                rt.append({"content": meta_text})
            
            blocks.append(create_custom_bullet_item(rt))
    else:
        blocks.append(create_paragraph("(無重大事件)"))
        
    blocks.append({"object": "block", "type": "divider", "divider": {}})

    # -- CVE 漏洞 --
    blocks.append(create_heading(2, "⚠️ 焦點 CVE 漏洞"))
    cves = briefing.get("cves", [])
    if cves:
        headers = ["CVE編號", "元件", "CVSS", "類型", "狀態"]
        rows = []
        for c in cves:
            # 第一欄 ID 加上 URL 超連結
            id_cell = {"content": c.get("id","")}
            if c.get("reference_url"):
                id_cell["url"] = c.get("reference_url")
                
            rows.append([
                id_cell,
                {"content": c.get("component","")},
                {"content": c.get("cvss","")},
                {"content": c.get("type","")},
                {"content": c.get("status","")}
            ])
        blocks.append(create_table(headers, rows))
    else:
        blocks.append(create_paragraph("(無高危 CVE)"))

    blocks.append({"object": "block", "type": "divider", "divider": {}})

    # -- 建議行動 --
    blocks.append(create_heading(2, "📌 建議防護行動"))
    actions = briefing.get("action_items", [])
    if actions:
        for a in actions:
            # 沿用稍早建立的 Custom bullet，但這只有單純的文字
            blocks.append(create_custom_bullet_item([{"content": a}]))
    else:
        blocks.append(create_paragraph("(無特殊建議)"))

    blocks.append({"object": "block", "type": "divider", "divider": {}})
    blocks.append(create_paragraph(f"自動產出：{TODAY} 07:00 台北 | GitHub Actions & Claude-Sonnet", color="gray"))

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

def send_telegram_message(briefing, notion_url):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[{TODAY}] 未設定 Telegram Token 或 Chat ID，略過 Telegram 通知。")
        return
        
    print(f"[{TODAY}] 準備發送 Telegram 通知...")
    
    # 建構訊息內容
    sev = severity_emoji(briefing.get('severity', ''))
    summary = briefing.get('summary', '')
    impact = briefing.get('taiwan_impact_assessment', '')
    events = briefing.get('events', [])
    
    msg = f"🛡️ <b>資安威脅日報 ({TODAY})</b>\n\n"
    msg += f"<b>{sev} 核心摘要:</b>\n{summary}\n\n"
    
    if impact:
        msg += f"<b>🇹🇼 台灣影響評估:</b>\n{impact}\n\n"
        
    if events:
        msg += "<b>🚨 今日重大事件:</b>\n"
        for i, e in enumerate(events[:3]): # 取前三則
            src_url = e.get('source_url', '')
            title = e.get('title', '')
            title_html = f"<a href='{src_url}'>{title}</a>" if src_url else title
            msg += f"• {severity_emoji(e.get('severity',''))} {title_html}\n"
    
    if notion_url:
        msg += f"\n📂 <b>查看完整報告：</b>\n<a href='{notion_url}'>點擊前往 Notion</a>"
        
    # 發送請求
    tg_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    
    # 參考 ai-secretary，自動切割超過 4096 字元的長訊息
    MAX_LEN = 4000 # 留點 buffer
    chunks = [msg[i:i + MAX_LEN] for i in range(0, len(msg), MAX_LEN)]
    
    for idx, chunk in enumerate(chunks):
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": chunk,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        
        try:
            resp = requests.post(tg_url, json=payload, timeout=20)
            resp.raise_for_status()
            print(f"[{TODAY}] ✅ Telegram 發送成功 (段落 {idx+1}/{len(chunks)})")
        except Exception as e:
            print(f"[ERROR] Telegram 發送失敗 (段落 {idx+1}): {e}")
            if 'resp' in locals():
                print(f"詳細錯誤: {resp.text}")

def main():
    print(f"\n{'='*50}")
    print(f"  資安日報 {TODAY} 07:00 台北")
    print(f"{'='*50}\n")
    
    news_context = fetch_rss_news()
    briefing = generate_briefing(news_context)
    
    print(f"[{TODAY}] 嚴重等級: {briefing.get('severity')} | 事件數: {len(briefing.get('events',[]))}")
    
    url = create_child_page(briefing)
    if url:
        append_table_row(briefing, url)
        
    # 發送 Telegram 通知
    send_telegram_message(briefing, url)
        
    print(f"\n✅ 流程全部完成!")

if __name__ == "__main__":
    main()
