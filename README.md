# 資安情報每日日報 — GitHub Actions 版

每日台灣時間 07:00 自動執行，完全免費。

## 部署步驟

### 1. 建立 GitHub 私有 Repo
前往 https://github.com/new，建立私有 repo（如 `cyber-briefing`）

### 2. 上傳這兩個檔案
```
briefing.py
.github/workflows/daily-briefing.yml
```

### 3. 設定 Secrets
Repo → Settings → Secrets and variables → Actions → New repository secret

| 名稱 | 值 |
|---|---|
| `ANTHROPIC_API_KEY` | sk-ant-... |
| `NOTION_TOKEN` | ntn_... |
| `NOTION_PAGE_ID` | 33457ac64d74818881f2c131ecc5dbff |

### 4. 手動觸發測試
Repo → Actions → 資安情報每日日報 → Run workflow

## 費用
- GitHub Actions 私有 repo：每月 2,000 分鐘免費
- 本案每月消耗：約 90 分鐘（每日 3 分鐘 × 30 天）
- **實際費用：$0**
