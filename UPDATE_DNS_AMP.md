# ✅ DNS 放大攻擊更新完成

## 已完成的修改

### 1. 攻擊端 (attack_server.py)

#### 新增 DNS 放大攻擊函數
```python
def dns_amplification_attack(target_ip, target_port, duration, attack_type='dns-amp'):
    """DNS 放大攻擊 - 使用大型 DNS 查詢"""
    - 支持多種 DNS 查詢類型 (ANY, TXT, MX, DNSSEC)
    - 使用隨機源端口
    - 記錄延遲和統計
```

#### 更新的配置
- 將 `'combo'` 改為 `'dns-amp'`
- 延遲追蹤字典更新
- API 端點支持 `dns-amp` 攻擊類型

### 2. 前端界面 (attack_control.html)

#### 按鈕更新
- **舊**: 🔥 組合攻擊 (combo)
- **新**: 📡 DNS 放大攻擊 (dns-amp)

#### CSS 樣式
- 將 `.btn-combo` 改為 `.btn-dns`
- 保持橙色邊框 (#f59e0b)

#### JavaScript
- 延遲追蹤數據結構更新為 `dns-amp`
- 選中狀態樣式更新

### 3. 監控端 (muti_server.py)

#### 攻擊記錄優化
- **舊**: 保留最近 100 條，顯示 20 條
- **新**: 保留最近 50 條，全部顯示

#### HTML 界面 (attack_monitor.html)
- 標題更新: "最近 20 條" → "最近 50 條"
- 滾動條樣式已存在，可以流暢滾動查看

---

## 測試步驟

### 1. 啟動監控服務器
```bash
cd C:\Users\User\Desktop\Programm\topic\DDos\server
python muti_server.py
```
- 訪問: http://localhost:8888
- 檢查攻擊事件列表是否可以滾動

### 2. 啟動攻擊控制台
```bash
cd C:\Users\User\Desktop\Programm\topic\DDos\dos
python attack_server.py
```
- 訪問: http://localhost:5000
- **按 Ctrl + Shift + R** 強制刷新瀏覽器緩存

### 3. 測試 DNS 放大攻擊
1. 在攻擊控制台中，點擊 **📡 DNS 放大攻擊** 按鈕
2. 按鈕應變成藍色（選中狀態）
3. 設置目標:
   - IP: `127.0.0.1` (本機測試)
   - 端口: `8000`
   - UDP 端口: `9001`
4. 點擊 **▶️ 開始攻擊**

### 4. 驗證監控界面
在 http://localhost:8888 查看:
- ✅ 攻擊事件列表顯示 DNS 相關記錄
- ✅ 列表可以向下滾動
- ✅ 最多保留 50 條記錄
- ✅ 實時更新

---

## DNS 放大攻擊特點

### 攻擊原理
DNS 放大攻擊利用 DNS 協議的特性，發送小的查詢請求得到大的響應包：

**查詢類型:**
1. **ANY 記錄** - 返回所有類型記錄（已被多數 DNS 服務器禁用）
2. **TXT 記錄** - 文本記錄，可能包含大量數據
3. **MX 記錄** - 郵件交換記錄
4. **DNSSEC** - DNSSEC 相關記錄，響應通常較大

### 攻擊效果
- 🚀 放大倍數: 10-100 倍
- 📊 小查詢 (60 bytes) → 大響應 (600-4000 bytes)
- 🎯 消耗目標帶寬和 DNS 處理能力

### 防禦措施
- 🛡️ 限制 DNS 查詢速率
- 🔒 禁用 ANY 查詢
- 📡 使用 Response Rate Limiting (RRL)

---

## 監控界面優化

### 攻擊事件顯示
```
最近 50 條記錄
↓ 可滾動查看
│ [2025-12-01 14:23:45] DNS Packet 來源: 127.0.0.1
│ [2025-12-01 14:23:46] DNS Packet 來源: 127.0.0.1
│ ...
↓
```

### 滾動條樣式
- 寬度: 6px
- 顏色: 半透明白色
- 圓角設計
- 自動隱藏（不滾動時）

---

## 注意事項

### ⚠️ 重要
1. **清除瀏覽器緩存**: 前端修改後必須 **Ctrl + Shift + R**
2. **端口配置**: DNS 標準端口是 53，測試時使用 9001
3. **合法性**: 僅用於授權的測試環境
4. **性能**: DNS 攻擊可能消耗大量帶寬

### 🔧 故障排除

**問題**: 點擊 DNS 放大攻擊按鈕沒反應
- **解決**: Ctrl + Shift + R 清除緩存，檢查 Console 錯誤

**問題**: 監控界面不顯示攻擊
- **解決**: 檢查目標 IP 和端口是否正確，確認服務器運行中

**問題**: 攻擊事件列表不滾動
- **解決**: 檢查是否有足夠多的記錄（至少 10 條以上才會出現滾動條）

---

## 代碼對比

### 攻擊類型選擇（attack_server.py）

**舊代碼:**
```python
elif attack_type == 'combo':
    # SYN + HTTP + Slowloris 組合
```

**新代碼:**
```python
elif attack_type == 'dns-amp':
    # DNS 放大攻擊
    for ip_type, ip_addr in resolved_ips:
        for _ in range(threads_per_ip):
            t = threading.Thread(target=dns_amplification_attack, ...)
```

### 前端按鈕（attack_control.html）

**舊代碼:**
```html
<button class="attack-button btn-combo" data-attack="combo">
    <div class="icon">🔥</div>
    <div class="name">組合攻擊</div>
```

**新代碼:**
```html
<button class="attack-button btn-dns" data-attack="dns-amp">
    <div class="icon">📡</div>
    <div class="name">DNS 放大攻擊</div>
```

---

## 測試清單

- [ ] 攻擊控制台啟動成功
- [ ] 監控界面啟動成功
- [ ] DNS 放大攻擊按鈕顯示正確
- [ ] 點擊按鈕變藍色（選中狀態）
- [ ] 開始攻擊後有延遲顯示
- [ ] 監控界面收到 DNS 攻擊記錄
- [ ] 攻擊事件列表可以滾動
- [ ] 最多保留 50 條記錄
- [ ] 滾動條樣式美觀

---

## 下一步建議

### 功能擴展
1. **DNS 查詢自定義** - 允許用戶指定查詢域名
2. **放大倍數統計** - 顯示查詢/響應大小比例
3. **多 DNS 服務器** - 使用多個公共 DNS 進行測試
4. **EDNS0 支持** - 使用 EDNS0 擴展獲得更大響應

### 性能優化
1. **異步 I/O** - 使用 asyncio 提高併發性能
2. **批量發送** - 一次發送多個 DNS 查詢
3. **連接池** - 重用 socket 連接

### 監控增強
1. **圖表顯示** - 添加攻擊趨勢圖表
2. **攻擊分類** - 按攻擊類型分組顯示
3. **導出功能** - 導出攻擊日誌為 CSV/JSON
