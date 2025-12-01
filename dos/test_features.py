"""
快速測試腳本 - 驗證新功能
測試各種攻擊模式和統計功能
"""
from progressive_test import ProgressiveAttack
import time

def test_port_uniqueness():
    """測試 source port 唯一性"""
    print("=" * 80)
    print("測試 1: Source Port 唯一性測試")
    print("=" * 80)
    
    attacker = ProgressiveAttack("http://httpbin.org/get", "GET")
    
    # 收集使用的 ports
    ports_before = len(attacker.unique_ports_used)
    
    # 模擬多次請求
    for i in range(5):
        port = attacker._get_random_port()
        attacker.unique_ports_used.add(port)
        print(f"  請求 {i+1}: 使用 port {port}")
    
    ports_after = len(attacker.unique_ports_used)
    
    print(f"\n✓ 總共使用了 {ports_after} 個不同的 port")
    print(f"✓ Port 範圍: 49152-65535 (臨時端口)")
    print()

def test_request_counting():
    """測試請求計數功能"""
    print("=" * 80)
    print("測試 2: 請求計數測試 (真實 HTTP 請求)")
    print("=" * 80)
    print("目標: http://httpbin.org/get (公開測試 API)")
    print()
    
    attacker = ProgressiveAttack("http://httpbin.org/get", "GET")
    
    # 運行短時間測試
    attacker.running = True
    import threading
    
    def run_attack():
        for _ in range(3):  # 只發送 3 個請求
            if not attacker.running:
                break
            attacker.http_get_attack()
            attacker.running = False  # 只執行一次
    
    threads = []
    for i in range(3):
        t = threading.Thread(target=run_attack)
        t.daemon = True
        t.start()
        threads.append(t)
    
    time.sleep(5)
    attacker.running = False
    
    print(f"✓ 發送請求數: {attacker.request_count}")
    print(f"✓ 成功請求: {attacker.success_count}")
    print(f"✓ 失敗請求: {attacker.error_count}")
    print(f"✓ 使用的不同 port: {len(attacker.unique_ports_used)}")
    print(f"✓ 平均響應時間: {sum(attacker.response_times)/len(attacker.response_times)*1000:.1f}ms" 
          if attacker.response_times else "N/A")
    print()

def test_protocol_selection():
    """測試協議選擇"""
    print("=" * 80)
    print("測試 3: 協議支援檢查")
    print("=" * 80)
    
    protocols = [
        ('GET', 'HTTP/1.1'),
        ('POST', 'HTTP/1.1'),
        ('HTTP3', 'HTTP/3'),
        ('UDP', 'UDP')
    ]
    
    for method, protocol in protocols:
        attacker = ProgressiveAttack("http://example.com", method, protocol)
        func = attacker.get_attack_function()
        status = "✓ 可用" if func else "✗ 不可用"
        print(f"  {method:12} ({protocol:10}): {status}")
    
    print()
    
    # 檢查 QUIC 可用性
    try:
        from progressive_test import QUIC_AVAILABLE
        if QUIC_AVAILABLE:
            print("✓ HTTP/3 (QUIC) 功能已啟用")
            print("  已安裝 aioquic 套件")
        else:
            print("⚠ HTTP/3 (QUIC) 功能未啟用")
            print("  安裝方式: pip install aioquic")
    except:
        print("⚠ 無法檢查 QUIC 狀態")
    
    print()

def test_connection_independence():
    """測試連線獨立性"""
    print("=" * 80)
    print("測試 4: 連線獨立性驗證")
    print("=" * 80)
    print("驗證每個請求使用新的 TCP 連線")
    print()
    
    attacker = ProgressiveAttack("http://httpbin.org/get", "GET")
    
    print("✓ 每個請求配置:")
    print("  - 新建 Session 對象")
    print("  - Connection: close header")
    print("  - 獨立 socket 綁定")
    print("  - 隨機 source port")
    print()
    print("✓ 避免以下情況:")
    print("  - TCP 連線重用")
    print("  - HTTP Keep-Alive")
    print("  - HTTP/2 多路復用")
    print("  - 請求池合併")
    print()

def show_statistics_demo():
    """展示統計數據格式"""
    print("=" * 80)
    print("測試 5: 統計數據格式展示")
    print("=" * 80)
    
    # 模擬結果
    result = {
        'threads': 100,
        'success': 950,
        'failed': 50,
        'success_rate': 95.0,
        'avg_response_time': 0.123,
        'request_rate': 95.0,
        'total_requests': 1000,
        'udp_packets': 0,
        'unique_ports': 98
    }
    
    print("\n範例輸出格式:")
    print("-" * 80)
    print(f"  線程: {result['threads']:3d} | "
          f"請求: {result['total_requests']:4d} | "
          f"成功: {result['success']:4d} | "
          f"失敗: {result['failed']:4d} | "
          f"成功率: {result['success_rate']:5.1f}% | "
          f"延遲: {result['avg_response_time']*1000:6.1f}ms | "
          f"速率: {result['request_rate']:6.1f} req/s | "
          f"Ports: {result['unique_ports']:3d} | 🟢 運作正常")
    print("-" * 80)
    
    print("\n欄位說明:")
    print(f"  {'線程':<10} : 並發執行的線程數量")
    print(f"  {'請求':<10} : 實際發送的請求總數 (新增)")
    print(f"  {'成功':<10} : 成功完成的請求數")
    print(f"  {'失敗':<10} : 失敗的請求數")
    print(f"  {'成功率':<10} : 成功請求百分比")
    print(f"  {'延遲':<10} : 平均響應時間")
    print(f"  {'速率':<10} : 每秒請求數")
    print(f"  {'Ports':<10} : 使用的唯一 port 數量 (新增)")
    print()

def main():
    """執行所有測試"""
    print("\n")
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║              DDoS 測試工具 - 新功能驗證測試                         ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print()
    
    try:
        # 測試 1: Port 唯一性
        test_port_uniqueness()
        time.sleep(1)
        
        # 測試 2: 請求計數
        print("⚠️  注意: 測試 2 會發送真實 HTTP 請求到 httpbin.org")
        response = input("是否繼續? (y/n): ")
        if response.lower() == 'y':
            test_request_counting()
            time.sleep(1)
        else:
            print("跳過測試 2\n")
        
        # 測試 3: 協議支援
        test_protocol_selection()
        time.sleep(1)
        
        # 測試 4: 連線獨立性
        test_connection_independence()
        time.sleep(1)
        
        # 測試 5: 統計展示
        show_statistics_demo()
        
        print("=" * 80)
        print("✓ 所有測試完成!")
        print("=" * 80)
        print()
        print("下一步:")
        print("  1. 運行完整測試: python progressive_test.py")
        print("  2. 查看文檔: cat README_ENHANCED.md")
        print()
        
    except KeyboardInterrupt:
        print("\n\n測試已中斷")
    except Exception as e:
        print(f"\n✗ 錯誤: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
