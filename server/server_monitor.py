"""
伺服器監控模組
負責系統資源監控、性能記錄和報告生成
"""
import time
import threading
import psutil
from datetime import datetime
from collections import deque

# 全局變數
system_stats = {
    'cpu_percent': 0,
    'memory_percent': 0,
    'network_sent': 0,
    'network_recv': 0,
    'network_sent_rate': 0,
    'network_recv_rate': 0,
}
stats_lock = threading.Lock()

# 性能統計記錄 (每5秒記錄一次)
performance_records = []
performance_lock = threading.Lock()

# 封包類型統計 (按方法)
packet_stats_method = {
    'GET': 0,
    'POST': 0,
    'PUT': 0,
    'DELETE': 0,
    'HEAD': 0,
    'OPTIONS': 0,
    'other_method': 0,
}

# 封包類型統計 (按路徑)
packet_stats_path = {
    'root': 0,  # / 根路徑
    'favicon': 0,
    'static': 0,  # 靜態資源
    'api': 0,  # API 請求
    'other_path': 0,
}

# 封包組合統計 (方法+路徑)
packet_combinations = {}
packet_stats_lock = threading.Lock()

# 每個請求的詳細操作記錄
request_operations = []
operations_lock = threading.Lock()

# 獨特的標頭組合記錄
unique_header_combinations = {}
header_combination_lock = threading.Lock()

def format_bytes(bytes_value):
    """將字節數轉換為可讀格式"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def get_current_stats():
    """獲取當前系統狀態 (供監控頁面使用)"""
    with stats_lock:
        return system_stats.copy()
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def system_monitor_thread():
    """背景線程: 監控系統資源使用情況"""
    global system_stats
    
    # 初始化網路計數器
    net_io_start = psutil.net_io_counters()
    last_sent = net_io_start.bytes_sent
    last_recv = net_io_start.bytes_recv
    last_time = time.time()
    
    while True:
        try:
            # 獲取 CPU 使用率 (1秒內的平均值)
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # 獲取記憶體使用率
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # 獲取網路 I/O
            net_io = psutil.net_io_counters()
            current_time = time.time()
            time_delta = current_time - last_time
            
            # 計算網路傳輸速率 (bytes/s)
            sent_rate = (net_io.bytes_sent - last_sent) / time_delta if time_delta > 0 else 0
            recv_rate = (net_io.bytes_recv - last_recv) / time_delta if time_delta > 0 else 0
            
            # 更新全局變數
            with stats_lock:
                system_stats['cpu_percent'] = cpu_percent
                system_stats['memory_percent'] = memory_percent
                system_stats['network_sent'] = net_io.bytes_sent
                system_stats['network_recv'] = net_io.bytes_recv
                system_stats['network_sent_rate'] = sent_rate
                system_stats['network_recv_rate'] = recv_rate
            
            # 更新計數器
            last_sent = net_io.bytes_sent
            last_recv = net_io.bytes_recv
            last_time = current_time
            
        except Exception as e:
            print(f"[系統監控錯誤] {e}")
            time.sleep(1)

def performance_record_thread(request_count_func, start_time):
    """
    背景線程: 每5秒記錄一次性能數據
    request_count_func: 返回當前請求總數的函數
    start_time: 伺服器啟動時間
    """
    global performance_records
    last_request_count = 0
    last_packet_stats_method = packet_stats_method.copy()
    last_packet_stats_path = packet_stats_path.copy()
    last_packet_combinations = packet_combinations.copy()
    
    while True:
        try:
            time.sleep(5)  # 每5秒記錄一次
            
            with stats_lock:
                cpu = system_stats['cpu_percent']
                memory = system_stats['memory_percent']
                sent_rate = system_stats['network_sent_rate']
                recv_rate = system_stats['network_recv_rate']
            
            current_requests = request_count_func()
            
            with packet_stats_lock:
                method_snapshot = packet_stats_method.copy()
                path_snapshot = packet_stats_path.copy()
                combo_snapshot = packet_combinations.copy()
            
            # 計算這5秒內的請求數
            requests_in_period = current_requests - last_request_count
            
            # 計算這5秒內各類型封包的數量
            period_method_stats = {}
            for key in method_snapshot:
                period_method_stats[key] = method_snapshot[key] - last_packet_stats_method.get(key, 0)
            
            period_path_stats = {}
            for key in path_snapshot:
                period_path_stats[key] = path_snapshot[key] - last_packet_stats_path.get(key, 0)
            
            period_combo_stats = {}
            for key in combo_snapshot:
                period_combo_stats[key] = combo_snapshot[key] - last_packet_combinations.get(key, 0)
            
            last_request_count = current_requests
            last_packet_stats_method = method_snapshot.copy()
            last_packet_stats_path = path_snapshot.copy()
            last_packet_combinations = combo_snapshot.copy()
            
            # 記錄性能數據
            record = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'uptime': time.time() - start_time,
                'total_requests': current_requests,
                'requests_in_period': requests_in_period,
                'cpu_percent': cpu,
                'memory_percent': memory,
                'network_sent_rate': sent_rate,
                'network_recv_rate': recv_rate,
                'method_stats_total': method_snapshot.copy(),
                'path_stats_total': path_snapshot.copy(),
                'combo_stats_total': combo_snapshot.copy(),
                'method_stats_period': period_method_stats,
                'path_stats_period': period_path_stats,
                'combo_stats_period': period_combo_stats,
            }
            
            with performance_lock:
                performance_records.append(record)
            
        except Exception as e:
            print(f"[性能記錄錯誤] {e}")

def record_unique_headers(headers_dict):
    """記錄獨特的標頭組合"""
    # 創建標頭指紋 (排除動態值)
    header_signature = tuple(sorted(headers_dict.keys()))
    
    with header_combination_lock:
        if header_signature not in unique_header_combinations:
            unique_header_combinations[header_signature] = {
                'headers': headers_dict.copy(),
                'count': 1,
                'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
        else:
            unique_header_combinations[header_signature]['count'] += 1

def analyze_packet_requirements(method, path, headers):
    """
    分析封包要求伺服器執行的底層操作
    返回操作列表和封包特徵
    """
    operations = []
    features = {
        'method': method,
        'path_type': 'other',
        'requires_parsing': False,
        'requires_processing': False,
        'requires_response': True,
    }
    
    # 1. TCP 連接層操作
    operations.append("[TCP層] 接受客戶端連接 (三次握手已完成)")
    operations.append("[TCP層] 從 socket 讀取數據流")
    
    # 2. HTTP 協議層操作
    operations.append(f"[HTTP層] 解析請求行: {method} {path} HTTP/1.1")
    operations.append(f"[HTTP層] 解析請求標頭 ({len(headers)} 個欄位)")
    
    # 分析標頭內容
    if 'Content-Length' in headers:
        content_len = headers['Content-Length']
        operations.append(f"[HTTP層] 準備接收請求主體 ({content_len} bytes)")
        features['requires_parsing'] = True
    
    if 'Connection' in headers:
        conn_type = headers['Connection']
        operations.append(f"[HTTP層] 連接管理: {conn_type}")
    
    # 3. 路徑分析與路由
    if path == '/' or path == '':
        features['path_type'] = 'root'
        operations.append("[路由] 匹配根路徑 '/'")
        operations.append("[處理] 生成完整 HTML 頁面 (~5KB)")
        features['requires_processing'] = True
    elif path == '/favicon.ico':
        features['path_type'] = 'favicon'
        operations.append("[路由] 匹配 favicon 請求")
        operations.append("[處理] 返回 204 No Content (無資源)")
        features['requires_processing'] = False
    elif path.startswith('/api/'):
        features['path_type'] = 'api'
        operations.append(f"[路由] 匹配 API 端點: {path}")
        operations.append("[處理] 執行業務邏輯")
        operations.append("[處理] 序列化 JSON 響應")
        features['requires_processing'] = True
    elif any(path.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.gif']):
        features['path_type'] = 'static'
        ext = path.split('.')[-1]
        operations.append(f"[路由] 匹配靜態資源: .{ext}")
        operations.append(f"[I/O] 從磁盤讀取文件")
        operations.append(f"[處理] 設置 MIME 類型")
        features['requires_processing'] = True
    else:
        features['path_type'] = 'other'
        operations.append(f"[路由] 處理未知路徑: {path}")
        operations.append("[處理] 生成錯誤響應或默認頁面")
    
    # 4. 方法特定操作
    if method == 'GET':
        operations.append("[方法] GET - 只讀操作,不修改伺服器狀態")
    elif method == 'POST':
        operations.append("[方法] POST - 創建資源")
        operations.append("[處理] 解析請求主體數據")
        operations.append("[處理] 數據驗證")
        operations.append("[I/O] 寫入數據庫/文件")
        features['requires_parsing'] = True
    elif method == 'PUT':
        operations.append("[方法] PUT - 更新資源")
        operations.append("[處理] 解析請求主體數據")
        operations.append("[I/O] 更新數據庫/文件")
        features['requires_parsing'] = True
    elif method == 'DELETE':
        operations.append("[方法] DELETE - 刪除資源")
        operations.append("[I/O] 從數據庫/文件系統刪除")
    
    # 5. 資源監控
    operations.append("[監控] 記錄請求到日誌")
    operations.append("[監控] 更新統計計數器")
    operations.append("[監控] 檢查系統資源使用")
    
    # 6. 響應生成
    operations.append("[響應] 構建 HTTP 狀態行")
    operations.append("[響應] 添加響應標頭")
    operations.append("[響應] 編碼響應主體")
    
    # 7. TCP 發送
    operations.append("[TCP層] 將響應寫入 socket")
    operations.append("[TCP層] 刷新輸出緩衝區")
    
    return operations, features

def update_packet_stats(method, path, headers=None):
    """更新封包統計"""
    if headers is None:
        headers = {}
    
    with packet_stats_lock:
        # 統計請求方法
        if method in packet_stats_method:
            packet_stats_method[method] += 1
        else:
            packet_stats_method['other_method'] += 1
        
        # 統計請求路徑類型
        if path == '/' or path == '':
            path_type = 'root'
            packet_stats_path['root'] += 1
        elif path == '/favicon.ico':
            path_type = 'favicon'
            packet_stats_path['favicon'] += 1
        elif path.startswith('/api/'):
            path_type = 'api'
            packet_stats_path['api'] += 1
        elif any(path.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.gif', '.ico']):
            path_type = 'static'
            packet_stats_path['static'] += 1
        else:
            path_type = 'other_path'
            packet_stats_path['other_path'] += 1
        
        # 統計組合 (方法+路徑類型)
        combo_key = f"{method}+{path_type}"
        packet_combinations[combo_key] = packet_combinations.get(combo_key, 0) + 1

def generate_final_report(request_count, start_time, blocked_count=0, block_reasons=None, blocked_ips=None, output_dir='.'):
    """生成最終分析報告
    
    Args:
        request_count: 允許通過的請求數量
        start_time: 伺服器啟動時間
        blocked_count: 被攔截的請求數量 (選用)
        block_reasons: 攔截原因字典 {原因: 次數} (選用)
        blocked_ips: 被攔截的IP字典 {IP: 次數} (選用)
        output_dir: 報告輸出目錄
    """
    import os
    report_path = os.path.join(output_dir, 'performance_report.txt')
    
    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("="*150 + "\n")
            f.write("DDoS 測試伺服器 - 性能分析報告\n".center(150))
            f.write("="*150 + "\n\n")
            
            # 基本統計
            total_time = time.time() - start_time
            total_all_requests = request_count + blocked_count
            
            f.write(f"[基本統計]\n")
            f.write(f"  啟動時間: {datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  結束時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  總運行時間: {total_time:.2f} 秒 ({total_time/60:.2f} 分鐘)\n")
            f.write(f"  總請求數 (含攔截): {total_all_requests}\n")
            f.write(f"  允許通過: {request_count} ({request_count/total_all_requests*100:.1f}%)\n" if total_all_requests > 0 else f"  允許通過: {request_count}\n")
            f.write(f"  已攔截: {blocked_count} ({blocked_count/total_all_requests*100:.1f}%)\n" if total_all_requests > 0 else f"  已攔截: {blocked_count}\n")
            f.write(f"  平均請求速率: {total_all_requests/total_time:.2f} 請求/秒\n\n")
            
            # 伺服器資源競爭數據
            f.write(f"[伺服器資源競爭分析]\n")
            if performance_records:
                cpu_values = [d['cpu_percent'] for d in performance_records if 'cpu_percent' in d]
                memory_values = [d['memory_percent'] for d in performance_records if 'memory_percent' in d]
                network_sent_values = [d['network_sent_rate'] for d in performance_records if 'network_sent_rate' in d]
                network_recv_values = [d['network_recv_rate'] for d in performance_records if 'network_recv_rate' in d]
                
                if cpu_values:
                    avg_cpu = sum(cpu_values) / len(cpu_values)
                    max_cpu = max(cpu_values)
                    min_cpu = min(cpu_values)
                    f.write(f"  CPU 使用率:\n")
                    f.write(f"    平均: {avg_cpu:.2f}%\n")
                    f.write(f"    最高: {max_cpu:.2f}%\n")
                    f.write(f"    最低: {min_cpu:.2f}%\n")
                    cpu_high_count = sum(1 for v in cpu_values if v > 80)
                    if cpu_high_count > 0:
                        f.write(f"    高負載 (>80%) 次數: {cpu_high_count} ({cpu_high_count/len(cpu_values)*100:.1f}%)\n")
                
                if memory_values:
                    avg_mem = sum(memory_values) / len(memory_values)
                    max_mem = max(memory_values)
                    min_mem = min(memory_values)
                    f.write(f"\n  記憶體使用率:\n")
                    f.write(f"    平均: {avg_mem:.2f}%\n")
                    f.write(f"    最高: {max_mem:.2f}%\n")
                    f.write(f"    最低: {min_mem:.2f}%\n")
                    mem_high_count = sum(1 for v in memory_values if v > 85)
                    if mem_high_count > 0:
                        f.write(f"    高負載 (>85%) 次數: {mem_high_count} ({mem_high_count/len(memory_values)*100:.1f}%)\n")
                
                if network_sent_values and network_recv_values:
                    avg_sent = sum(network_sent_values) / len(network_sent_values)
                    max_sent = max(network_sent_values)
                    avg_recv = sum(network_recv_values) / len(network_recv_values)
                    max_recv = max(network_recv_values)
                    f.write(f"\n  網路流量:\n")
                    f.write(f"    平均發送速率: {format_bytes(avg_sent)}/s\n")
                    f.write(f"    最高發送速率: {format_bytes(max_sent)}/s\n")
                    f.write(f"    平均接收速率: {format_bytes(avg_recv)}/s\n")
                    f.write(f"    最高接收速率: {format_bytes(max_recv)}/s\n")
                    f.write(f"    總發送流量: {format_bytes(sum(network_sent_values))}\n")
                    f.write(f"    總接收流量: {format_bytes(sum(network_recv_values))}\n")
                
                # 資源競爭評估
                f.write(f"\n  資源競爭評估:\n")
                if cpu_values and memory_values:
                    high_load_count = sum(1 for i in range(len(cpu_values)) 
                                         if cpu_values[i] > 70 and memory_values[i] > 70)
                    if high_load_count > 0:
                        f.write(f"    CPU+記憶體同時高負載: {high_load_count} 次 ({high_load_count/len(cpu_values)*100:.1f}%)\n")
                        f.write(f"    ⚠️ 偵測到明顯資源競爭\n")
                    else:
                        f.write(f"    ✅ 未偵測到嚴重資源競爭\n")
                else:
                    f.write(f"    資料不足，無法評估\n")
            else:
                f.write(f"  無效能監控數據\n")
            
            f.write(f"\n")
            
            # 封包類型統計 (總體)
            f.write(f"[封包類型統計 - 總體]\n")
            with packet_stats_lock:
                total_method = sum(packet_stats_method.values())
                total_path = sum(packet_stats_path.values())
                
                f.write(f"  總請求數: {request_count}\n\n")
                
                # 按請求方法統計
                f.write(f"  按請求方法分類:\n")
                f.write(f"    {'方法':<15} {'數量':<12} {'比例':<10}\n")
                f.write(f"    {'-'*40}\n")
                for method, count in sorted(packet_stats_method.items(), key=lambda x: x[1], reverse=True):
                    if count > 0:
                        percentage = (count / total_method * 100) if total_method > 0 else 0
                        f.write(f"    {method:<15} {count:<12} {percentage:>6.2f}%\n")
                
                f.write(f"\n  按路徑類型分類:\n")
                f.write(f"    {'路徑類型':<15} {'數量':<12} {'比例':<10}\n")
                f.write(f"    {'-'*40}\n")
                for path_type, count in sorted(packet_stats_path.items(), key=lambda x: x[1], reverse=True):
                    if count > 0:
                        percentage = (count / total_path * 100) if total_path > 0 else 0
                        f.write(f"    {path_type:<15} {count:<12} {percentage:>6.2f}%\n")
                
                f.write(f"\n  封包組合 (方法+路徑):\n")
                f.write(f"    {'組合':<25} {'數量':<12} {'比例':<10}\n")
                f.write(f"    {'-'*50}\n")
                for combo, count in sorted(packet_combinations.items(), key=lambda x: x[1], reverse=True):
                    if count > 0:
                        percentage = (count / request_count * 100) if request_count > 0 else 0
                        f.write(f"    {combo:<25} {count:<12} {percentage:>6.2f}%\n")
            f.write("\n")
            
            # 攔截統計 (如果有防禦系統)
            if blocked_count > 0 or (block_reasons and len(block_reasons) > 0):
                f.write(f"[攔截統計 - 防禦系統]\n")
                f.write(f"  總攔截數: {blocked_count}\n")
                if total_all_requests > 0:
                    block_rate = (blocked_count / total_all_requests * 100)
                    f.write(f"  攔截率: {block_rate:.1f}%\n")
                    f.write(f"  通過率: {100 - block_rate:.1f}%\n")
                f.write("\n")
                
                if block_reasons and len(block_reasons) > 0:
                    f.write(f"  攔截原因分類:\n")
                    f.write(f"    {'原因':<30} {'數量':<15} {'比例':<10}\n")
                    f.write(f"    {'-'*60}\n")
                    
                    sorted_reasons = sorted(block_reasons.items(), key=lambda x: x[1], reverse=True)
                    for reason, count in sorted_reasons:
                        percentage = (count / blocked_count * 100) if blocked_count > 0 else 0
                        f.write(f"    {reason:<30} {count:<15} {percentage:>6.1f}%\n")
                
                # 顯示被攔截的 IP 統計
                if blocked_ips and len(blocked_ips) > 0:
                    f.write(f"\n  被攔截的 IP 地址:\n")
                    f.write(f"    共 {len(blocked_ips)} 個不同的 IP 被攔截\n\n")
                    f.write(f"    {'IP 地址':<20} {'攔截次數':<15} {'比例':<10}\n")
                    f.write(f"    {'-'*50}\n")
                    
                    sorted_ips = sorted(blocked_ips.items(), key=lambda x: x[1], reverse=True)
                    for ip, count in sorted_ips[:20]:  # 只顯示前 20 個
                        percentage = (count / blocked_count * 100) if blocked_count > 0 else 0
                        f.write(f"    {ip:<20} {count:<15} {percentage:>6.1f}%\n")
                    
                    if len(sorted_ips) > 20:
                        remaining = len(sorted_ips) - 20
                        remaining_count = sum(count for ip, count in sorted_ips[20:])
                        percentage = (remaining_count / blocked_count * 100) if blocked_count > 0 else 0
                        f.write(f"    ... 其他 {remaining} 個 IP  {remaining_count:<15} {percentage:>6.1f}%\n")
                
                f.write("\n")
            
            # 獨特標頭組合
            f.write(f"[獨特的封包標頭組合]\n")
            with header_combination_lock:
                f.write(f"  共發現 {len(unique_header_combinations)} 種不同的標頭組合\n\n")
                for idx, (signature, info) in enumerate(sorted(unique_header_combinations.items(), 
                                                              key=lambda x: x[1]['count'], reverse=True)[:10], 1):
                    f.write(f"  組合 #{idx} (出現 {info['count']} 次,首次於 {info['first_seen']})\n")
                    f.write(f"  標頭欄位: {', '.join(signature)}\n")
                    f.write(f"  {'-'*100}\n")
            f.write("\n")
            
            # 網路使用說明
            f.write(f"[網路流量說明]\n")
            f.write(f"  • 網路接收 (Recv): 從客戶端收到的數據量 (客戶端→伺服器)\n")
            f.write(f"    - 包含: HTTP 請求行、請求標頭、請求主體 (POST/PUT 等)\n")
            f.write(f"    - DDoS 攻擊特徵: 大量小請求會導致接收量激增\n\n")
            f.write(f"  • 網路發送 (Sent): 伺服器送出的數據量 (伺服器→客戶端)\n")
            f.write(f"    - 包含: HTTP 狀態行、響應標頭、響應主體 (HTML/JSON 等)\n")
            f.write(f"    - 無防禦伺服器: 每個請求都會返回完整 HTML (約 4-6 KB)\n")
            f.write(f"    - 有防禦伺服器: 被攔截的請求只返回簡短錯誤訊息 (約 100-200 B)\n\n")
            f.write(f"  • 為何發送/接收比例不如預期?\n")
            f.write(f"    1. 本機測試: 網路統計包含系統所有流量,不只是伺服器\n")
            f.write(f"    2. TCP 開銷: 三次握手、ACK 確認、連接管理等協議開銷\n")
            f.write(f"    3. 持久連接: HTTP Keep-Alive 會減少連接建立開銷\n")
            f.write(f"    4. 緩衝機制: 作業系統的緩衝會影響即時統計\n\n")
            
            # 每5秒性能記錄
            f.write(f"[每 5 秒性能記錄 - 詳細分析]\n")
            f.write(f"  共 {len(performance_records)} 筆記錄\n\n")
            
            if performance_records:
                # 表頭
                f.write(f"  {'時間':<20} {'運行':<10} {'總請求':<10} {'5秒內':<10} {'CPU%':<8} "
                       f"{'記憶體%':<8} {'發送':<12} {'接收':<12} {'比例':<8}\n")
                f.write(f"  {'-'*120}\n")
                
                with performance_lock:
                    for record in performance_records:
                        ratio = (record['network_recv_rate'] / record['network_sent_rate'] 
                                if record['network_sent_rate'] > 0 else 0)
                        f.write(f"  {record['timestamp']:<20} "
                               f"{record['uptime']:>6.0f}s    "
                               f"{record['total_requests']:>8}   "
                               f"{record['requests_in_period']:>8}   "
                               f"{record['cpu_percent']:>6.1f}%  "
                               f"{record['memory_percent']:>6.1f}%  "
                               f"{format_bytes(record['network_sent_rate']):<12} "
                               f"{format_bytes(record['network_recv_rate']):<12} "
                               f"{ratio:>6.2f}:1\n")
                        
                        # 顯示這5秒內的封包組合分布
                        period_combos = record['combo_stats_period']
                        total_in_period = record['requests_in_period']
                        
                        if total_in_period > 0:
                            f.write(f"      ├─ 方法: ")
                            method_parts = [f"{k}:{v}({v/total_in_period*100:.1f}%)" 
                                          for k, v in record['method_stats_period'].items() if v > 0]
                            f.write(", ".join(method_parts) + "\n")
                            
                            f.write(f"      ├─ 路徑: ")
                            path_parts = [f"{k}:{v}({v/total_in_period*100:.1f}%)" 
                                        for k, v in record['path_stats_period'].items() if v > 0]
                            f.write(", ".join(path_parts) + "\n")
                            
                            f.write(f"      └─ 組合: ")
                            combo_parts = [f"{k}:{v}({v/total_in_period*100:.1f}%)" 
                                         for k, v in sorted(period_combos.items(), key=lambda x: x[1], reverse=True)[:5] if v > 0]
                            f.write(", ".join(combo_parts) + "\n")
                
                # 統計分析
                f.write("\n[統計分析]\n")
                with performance_lock:
                    if performance_records:
                        avg_cpu = sum(r['cpu_percent'] for r in performance_records) / len(performance_records)
                        max_cpu = max(r['cpu_percent'] for r in performance_records)
                        avg_memory = sum(r['memory_percent'] for r in performance_records) / len(performance_records)
                        max_memory = max(r['memory_percent'] for r in performance_records)
                        avg_sent = sum(r['network_sent_rate'] for r in performance_records) / len(performance_records)
                        avg_recv = sum(r['network_recv_rate'] for r in performance_records) / len(performance_records)
                        max_sent = max(r['network_sent_rate'] for r in performance_records)
                        max_recv = max(r['network_recv_rate'] for r in performance_records)
                        
                        f.write(f"  平均 CPU 使用率: {avg_cpu:.2f}% (最高: {max_cpu:.2f}%)\n")
                        f.write(f"  平均記憶體使用率: {avg_memory:.2f}% (最高: {max_memory:.2f}%)\n")
                        f.write(f"  平均發送速率: {format_bytes(avg_sent)}/s (最高: {format_bytes(max_sent)}/s)\n")
                        f.write(f"  平均接收速率: {format_bytes(avg_recv)}/s (最高: {format_bytes(max_recv)}/s)\n")
                        f.write(f"  平均接收/發送比例: {(avg_recv/avg_sent if avg_sent > 0 else 0):.2f}:1\n")
                        
                        # 找出高負載時段
                        high_load_periods = [r for r in performance_records if r['cpu_percent'] > 30]
                        if high_load_periods:
                            f.write(f"\n  高負載時段 (CPU > 30%): {len(high_load_periods)} 個時段\n")
                            for period in high_load_periods[:5]:
                                f.write(f"    - {period['timestamp']}: CPU {period['cpu_percent']:.1f}%, "
                                       f"{period['requests_in_period']} 請求/5秒\n")
            
            f.write("\n" + "="*150 + "\n")
            f.write("報告生成時間: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")
            f.write("="*150 + "\n")
        
        print(f"\n[報告] 性能分析報告已生成: {report_path}")
        return report_path
    
    except Exception as e:
        print(f"[報告生成錯誤] {e}")
        import traceback
        traceback.print_exc()
        return None

def get_system_stats():
    """獲取當前系統狀態"""
    with stats_lock:
        return system_stats.copy()

def start_monitoring(request_count_func, start_time):
    """啟動所有監控線程"""
    # 啟動系統監控線程
    monitor_thread = threading.Thread(target=system_monitor_thread, daemon=True)
    monitor_thread.start()
    print("[監控模組] 已啟動資源監控線程")
    
    # 啟動性能記錄線程
    perf_thread = threading.Thread(target=performance_record_thread, 
                                   args=(request_count_func, start_time), 
                                   daemon=True)
    perf_thread.start()
    print("[監控模組] 已啟動性能記錄線程 (每5秒記錄一次)")
    
    return monitor_thread, perf_thread
