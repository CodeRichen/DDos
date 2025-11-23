"""
漸進式攻擊測試 - 自動增加線程直到伺服器卡頓
測試不同防禦機制的效果
"""
import requests
import threading
import time
import sys
import socket
from collections import defaultdict

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
    def __init__(self, target_url, attack_method='GET'):
        self.target_url = target_url
        self.attack_method = attack_method
        self.success_count = 0
        self.error_count = 0
        self.lock = threading.Lock()
        self.running = True
        self.response_times = []
        
    def reset_stats(self):
        with self.lock:
            self.success_count = 0
            self.error_count = 0
            self.response_times = []
    
    def http_get_attack(self):
        """標準 GET 請求"""
        while self.running:
            try:
                start = time.time()
                response = requests.get(self.target_url, timeout=5)
                elapsed = time.time() - start
                
                with self.lock:
                    self.success_count += 1
                    self.response_times.append(elapsed)
            except Exception as e:
                with self.lock:
                    self.error_count += 1
    
    def http_post_attack(self):
        """POST 請求帶數據"""
        while self.running:
            try:
                start = time.time()
                data = {'data': 'x' * 1000}
                response = requests.post(self.target_url, data=data, timeout=5)
                elapsed = time.time() - start
                
                with self.lock:
                    self.success_count += 1
                    self.response_times.append(elapsed)
            except Exception as e:
                with self.lock:
                    self.error_count += 1
    
    def http_no_headers_attack(self):
        """無 User-Agent 的請求 (測試請求驗證)"""
        while self.running:
            try:
                start = time.time()
                response = requests.get(self.target_url, headers={'User-Agent': ''}, timeout=5)
                elapsed = time.time() - start
                
                with self.lock:
                    self.success_count += 1
                    self.response_times.append(elapsed)
            except Exception as e:
                with self.lock:
                    self.error_count += 1
    
    def get_attack_function(self):
        """根據攻擊方法返回對應函數"""
        methods = {
            'GET': self.http_get_attack,
            'POST': self.http_post_attack,
            'NO_HEADERS': self.http_no_headers_attack
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
            total_requests = self.success_count + self.error_count
            success_rate = (self.success_count / total_requests * 100) if total_requests > 0 else 0
            avg_response = sum(self.response_times) / len(self.response_times) if self.response_times else 0
            request_rate = self.success_count / duration
        
        return {
            'threads': num_threads,
            'success': self.success_count,
            'failed': self.error_count,
            'success_rate': success_rate,
            'avg_response_time': avg_response,
            'request_rate': request_rate
        }

def print_result(result, is_severe=False):
    """打印測試結果"""
    threads = result['threads']
    success = result['success']
    failed = result['failed']
    success_rate = result['success_rate']
    avg_time = result['avg_response_time']
    rate = result['request_rate']
    
    # 判定狀態
    if avg_time > 2.0 or success_rate < 50:
        status = "🔴 嚴重卡頓"
        severe = True
    elif avg_time > 1.0 or success_rate < 80:
        status = "🟠 明顯延遲"
        severe = False
    elif avg_time > 0.5:
        status = "🟡 輕微影響"
        severe = False
    else:
        status = "🟢 運作正常"
        severe = False
    
    print(f"  線程: {threads:3d} | 成功: {success:4d} | 失敗: {failed:4d} | "
          f"成功率: {success_rate:5.1f}% | 延遲: {avg_time*1000:6.1f}ms | "
          f"速率: {rate:6.1f} req/s | {status}")
    
    return severe

def progressive_test(target_url, attack_method, defense_enabled):
    """漸進式測試 - 逐步增加線程"""
    print(f"\n{'='*100}")
    defense_text = "🛡️  有防禦" if defense_enabled else "❌ 無防禦"
    print(f"測試目標: {target_url} | 防禦狀態: {defense_text} | 攻擊方法: {attack_method}")
    print(f"{'='*100}")
    print(f"  {'線程':<6} {'成功':>6} {'失敗':>6} {'成功率':>8} {'延遲':>10} {'速率':>12} {'狀態'}")
    print(f"{'='*100}")
    
    attacker = ProgressiveAttack(target_url, attack_method)
    
    # 漸進式增加線程: 10, 20, 30, 50, 75, 100, 150, 200, 300
    thread_steps = [10, 20, 30, 50, 75, 100, 150, 200, 300]
    results = []
    
    for num_threads in thread_steps:
        result = attacker.test_with_threads(num_threads, duration=8)
        results.append(result)
        is_severe = print_result(result)
        
        # 如果已經嚴重卡頓,停止增加
        if is_severe and result['success_rate'] < 30:
            print(f"\n⚠️  伺服器已嚴重卡頓,停止增加線程")
            break
        
        time.sleep(2)  # 每次測試間隔
    
    print(f"{'='*100}\n")
    return results

def compare_defense_effectiveness():
    """比較有無防禦的效果"""
    print("""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║           DDoS 防禦效果對比測試 - 漸進式攻擊分析                   ║
    ║                                                                      ║
    ║  測試方式: 逐步增加攻擊線程,直到伺服器嚴重卡頓                     ║
    ║  比較指標: 響應時間、成功率、最大承受能力                           ║
    ╚══════════════════════════════════════════════════════════════════════╝
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
    print("  3. 測試不同攻擊方法")
    
    choice = input("\n選擇測試模式:\n  [1] 完整對比測試 (需要同時啟動2個伺服器)\n  [2] 僅測試單一伺服器\n請選擇: ")
    
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
        no_defense_results = progressive_test(no_defense_url, "GET", False)
        
        input("\n按 Enter 繼續測試有防禦伺服器 (8001)...")
        
        # 測試2: 有防禦伺服器 - GET
        defense_url = f"http://{local_ip}:8001"
        print("\n" + "🛡️ " * 30)
        print(f"第二階段: 測試有防禦伺服器 ({defense_url})")
        print("🛡️ " * 30)
        defense_get_results = progressive_test(defense_url, "GET", True)
        
        # 測試3: 有防禦伺服器 - POST
        print("\n" + "🛡️ " * 30)
        print("第三階段: 測試有防禦伺服器 (POST 攻擊)")
        print("🛡️ " * 30)
        defense_post_results = progressive_test(defense_url, "POST", True)
        
        # 測試4: 有防禦伺服器 - 無 Headers
        print("\n" + "🛡️ " * 30)
        print("第四階段: 測試有防禦伺服器 (無 User-Agent 攻擊)")
        print("🛡️ " * 30)
        defense_noheader_results = progressive_test(defense_url, "NO_HEADERS", True)
        
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
        print("  [1] GET 請求")
        print("  [2] POST 請求")
        print("  [3] 無 User-Agent")
        method_choice = input("請選擇 (1/2/3): ")
        
        method_map = {'1': 'GET', '2': 'POST', '3': 'NO_HEADERS'}
        attack_method = method_map.get(method_choice, 'GET')
        
        results = progressive_test(url, attack_method, has_defense)

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
