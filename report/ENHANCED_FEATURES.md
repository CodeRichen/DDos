# DDoS 測試系統 - 增強功能說明

## 🎯 新增功能概覽

### 1. **獨立請求計數系統** ✅
**問題**: 原版依賴 TCP 連接數統計，會被 HTTP/2/QUIC 的連接復用機制影響，無法準確反映實際請求數量。

**解決方案**:
- 每個 HTTP 請求獨立計數（不管是否復用連接）
- 分離追蹤：
  - `requests`: 實際發送的請求總數
  - `connections`: TCP 連接數（可能被復用）
  - `successful_requests`: 成功完成的請求
  - `failed_requests`: 失敗的請求

**技術實現**:
```python
# 每次 HTTP 請求都會調用
increment_stat('requests')  # 不管連接狀態
```

---

### 2. **HTTP/2 支持** ✅
**功能**: 使用 `httpx` 庫原生支持 HTTP/2 協議測試。

**優勢**:
- 單個 TCP 連接多路復用
- 更真實地模擬現代瀏覽器行為
- 測試 CDN/負載均衡器的 HTTP/2 處理能力

**技術實現**:
```python
# 啟用 HTTP/2 客戶端
client = httpx.Client(http2=True, timeout=3.0)
response = client.request(method, url, headers=headers)

# 檢測 HTTP 版本
if response.http_version == "HTTP/2":
    increment_stat('http2_requests')
```

**統計顯示**:
- `http2_requests`: HTTP/2 協議的請求數

---

### 3. **QUIC/HTTP3 模擬** ✅
**功能**: UDP 攻擊中 50% 的包會模擬 QUIC 協議格式。

**QUIC 特徵**:
- 基於 UDP（端口 443）
- Long Header 格式（0xC0 + flags）
- Connection ID（16 bytes）
- 初始包大小 ~1200 bytes

**技術實現**:
```python
if random.random() > 0.5 and size >= 1200:
    payload = bytearray(size)
    payload[0] = 0xC0 | random.randint(0, 15)  # Long header
    payload[1:5] = random.randbytes(4)  # Version
    payload[5:21] = random.randbytes(16)  # Destination Connection ID
    payload[21:] = random.randbytes(size - 21)
    increment_stat('http3_requests')
```

**統計顯示**:
- `http3_requests`: QUIC/HTTP3 模擬包數量

---

### 4. **動態源端口分配** ✅
**問題**: 使用固定源端口會被防火牆/CDN 識別為同一客戶端，容易被限速或封鎖。

**解決方案**:
- 每個連接/請求綁定隨機源端口（10000-65535）
- 追蹤使用的唯一源端口數量
- 模擬來自不同客戶端的流量

**技術實現**:
```python
# SYN Flood / Slowloris
source_port = random.randint(10000, 65535)
sock.bind(('', source_port))
track_source_port(source_port)

# UDP Flood（每個包不同源端口）
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
source_port = random.randint(10000, 65535)
sock.bind(('', source_port))
```

**統計顯示**:
- `unique_source_ports`: 使用的不同源端口總數

**效果**:
- 突破單 IP 的速率限制
- 增加防火牆的追蹤難度
- 更分散的流量特徵

---

### 5. **多 IP DNS 解析** ✅
**功能**: 自動解析目標域名的所有 A/AAAA 記錄，對每個 IP 分別發起攻擊。

**應用場景**:
- CDN 服務（多個邊緣節點）
- 負載均衡集群
- 多數據中心部署
- IPv4/IPv6 雙棧測試

**技術實現**:
```python
def resolve_target_ips(target_host):
    ips = []
    # 解析 A 記錄（IPv4）
    answers = dns.resolver.resolve(target_host, 'A')
    for rdata in answers:
        ips.append(('ipv4', str(rdata)))
    
    # 解析 AAAA 記錄（IPv6）
    answers = dns.resolver.resolve(target_host, 'AAAA')
    for rdata in answers:
        ips.append(('ipv6', str(rdata)))
    
    return ips

# 平均分配線程到不同 IP
threads_per_ip = max(1, thread_count // len(resolved_ips))

for ip_type, ip_addr in resolved_ips:
    for _ in range(threads_per_ip):
        t = threading.Thread(target=attack_func, args=(ip_addr, ...))
```

**統計顯示**:
- `resolved_ips_count`: DNS 解析到的 IP 數量
- 日誌顯示: `DNS 解析: ipv4:1.2.3.4, ipv4:5.6.7.8`

**優勢**:
- 測試所有後端伺服器
- 發現負載均衡問題
- IPv6 兼容性測試

---

### 6. **智能重試機制** ✅
**功能**: 請求失敗時自動重試（最多 2 次），所有嘗試都計入統計。

**重試策略**:
```python
max_retries = 2
retry_count = 0

while retry_count <= max_retries and not success:
    try:
        increment_stat('requests')  # 每次嘗試都計數
        response = client.request(...)
        increment_stat('successful_requests')
        success = True
    except Exception as e:
        retry_count += 1
        increment_stat('retries')
        
        if retry_count > max_retries:
            add_error(f"HTTP {type(e).__name__}")
            increment_stat('failed_requests')
        else:
            time.sleep(0.05)  # 重試前等待 50ms
```

**統計顯示**:
- `requests`: 包含所有重試的總請求數
- `retries`: 重試次數
- `successful_requests`: 最終成功的請求
- `failed_requests`: 全部重試後仍失敗的請求

**計算公式**:
```
requests = successful_requests + failed_requests + retries
```

---

## 📊 完整統計面板

新的控制台顯示 **8 個統計卡片**:

| 統計項 | 說明 | 技術意義 |
|--------|------|----------|
| **發送封包** | 底層網絡包（TCP/UDP） | 網絡層壓力 |
| **實際請求數** | 應用層請求總數 | 真實負載 |
| **成功/失敗** | 請求完成情況 | 可用性指標 |
| **HTTP/2 請求** | 多路復用協議 | 現代 Web 測試 |
| **HTTP/3 (QUIC)** | UDP 加密傳輸 | 新一代協議 |
| **重試次數** | 失敗後重試 | 可靠性測試 |
| **源端口數** | 使用的唯一端口 | 分散程度 |
| **目標 IP 數** | DNS 解析結果 | 覆蓋範圍 |

---

## 🛠️ 安裝依賴

```bash
pip install flask flask-cors httpx dnspython requests
```

**依賴說明**:
- `httpx`: HTTP/2 客戶端支持
- `dnspython`: DNS 解析（A/AAAA 記錄）
- `requests`: HTTP/1.1 回退方案
- `flask` + `flask-cors`: Web 服務器

---

## 🚀 使用示例

### 測試 CDN 服務（多 IP）
```
目標 IP: example.com
TCP 端口: 443
線程數: 100
持續時間: 60s
攻擊類型: HTTP GET

結果:
- DNS 解析: ipv4:104.21.1.1, ipv4:172.67.1.1, ipv6:2606:4700::1
- 目標 IP 數: 3
- 實際請求數: 15,000+
- HTTP/2 請求: 12,000+
- 源端口數: 8,500+
```

### 測試 QUIC 支持
```
攻擊類型: UDP Flood
UDP 端口: 443

結果:
- 發送封包: 50,000
- HTTP/3 (QUIC): 25,000  ← 約 50% 是 QUIC 格式
- 源端口數: 35,000+
```

### 壓力測試負載均衡
```
目標: loadbalancer.local
DNS 解析: 192.168.1.10, 192.168.1.11, 192.168.1.12
線程數: 300 (每個 IP 100 線程)

統計:
- 實際請求數: 45,000
- 成功/失敗: 40,000/5,000  ← 發現 IP3 故障率高
- 重試次數: 8,000
```

---

## 🔍 技術對比

| 功能 | 原版 | 增強版 |
|------|------|--------|
| 請求計數 | 依賴 TCP 連接 | 獨立計數每個請求 |
| HTTP 協議 | HTTP/1.1 only | HTTP/1.1 + HTTP/2 |
| QUIC/HTTP3 | ❌ | ✅ UDP 模擬 |
| 源端口 | 系統自動分配 | 隨機綁定 + 追蹤 |
| DNS 解析 | 單 IP | 多 IP（A/AAAA） |
| 重試機制 | ❌ | ✅ 最多 2 次 |
| 統計維度 | 3 項 | 11 項 |

---

## ⚠️ 注意事項

1. **HTTP/2 需要伺服器支持**
   - 如果目標不支持 HTTP/2，會自動降級到 HTTP/1.1
   - 檢查 `http2_requests` 統計確認是否使用 HTTP/2

2. **QUIC 是模擬格式**
   - 只模擬包結構，不是真正的 QUIC 加密連接
   - 用於測試 UDP 層防護，不會建立完整的 QUIC 會話

3. **源端口可能衝突**
   - 短時間大量連接可能遇到端口耗盡
   - 系統會自動回退到系統分配端口

4. **DNS 解析延遲**
   - 首次啟動會進行 DNS 查詢
   - 可能增加 1-3 秒延遲

5. **IPv6 測試**
   - 需要本機和目標都支持 IPv6
   - 如果不支持，AAAA 記錄會被忽略

---

## 📈 效能提升

相比原版的改進:

- **請求精度**: 100% 準確（不受連接復用影響）
- **協議覆蓋**: HTTP/1.1 + HTTP/2 + HTTP/3 (QUIC)
- **分散性**: 使用數千個不同源端口
- **覆蓋範圍**: 同時測試多個後端 IP
- **可靠性**: 自動重試機制
- **可觀測性**: 11 個統計維度

---

## 🎓 學習資源

### HTTP/2 vs HTTP/1.1
- 單個 TCP 連接多路復用（multiplexing）
- 二進制幀（binary framing）
- 伺服器推送（server push）

### QUIC 特點
- 基於 UDP（0-RTT 握手）
- 內建加密（TLS 1.3）
- 連接遷移（connection migration）

### DNS 負載均衡
- Round-robin DNS
- GeoDNS（地理位置路由）
- 健康檢查和自動故障轉移

---

## 📝 後續建議

可進一步擴展的功能:

1. **真實 HTTP/3 支持**
   - 使用 `aioquic` 或 `quiche` 庫
   - 完整的 QUIC 握手和加密

2. **WebSocket 攻擊**
   - 長連接保持
   - 心跳包測試

3. **分佈式攻擊**
   - 多節點協調
   - 跨地域測試

4. **智能流量模式**
   - 模擬真實用戶行為
   - 動態調整請求速率

5. **報告生成**
   - 匯出 CSV/JSON 統計
   - 圖表可視化

---

**版本**: v2.0 Enhanced  
**更新日期**: 2025-12-01  
**作者**: GitHub Copilot AI Assistant
