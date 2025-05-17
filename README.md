+---------------------------------------------------+
| 智能版灯塔(ARL)弱口令检测脚本 v3.1 |
| 更新说明:  					  					  |
| • 全平台兼容支持                                  |
| • 智能资源管理                                      |
| • 动态线程池调整                                   |
| • 自动故障转移机制                               |
+---------------------------------------------------+

```shell
# 扫描单个目标
python3 arl_auth_scan.py -u http://target --user admin --pass password

# 批量扫描文件中的目标
python3 arl_auth_scan.py -f targets.txt -o results.txt

# 使用代理调试
python3 arl_auth_scan.py -u https://target --proxy http://127.0.0.1:8080
```

1. **跨平台支持**

   - Windows/Linux/macOS 全兼容
   - 自动检测系统资源（需psutil库）
   - 无依赖基础模式自动降级

2. **智能资源管理**

   ```
   # 自动模式（推荐）
   python scan.py -f targets.txt
   
   # 手动指定线程数
   python scan.py -f targets.txt --threads 32
   ```

3. **性能优化**

   - 动态线程池管理
   - 连接复用机制
   - 智能超时处理（默认10秒）

4. **诊断模式**

   python

   ```
   # 查看内存检测结果
   if mem_gb < 2:
       print("低内存模式")
   ```

**部署说明：**

bash

```
# 基础依赖
pip install requests colorama tqdm

# 完整功能（推荐）
pip install psutil
```

**系统资源监控：**

python

```
try:
    # 实时内存监控
    from psutil import virtual_memory
    print(f"可用内存: {virtual_memory().available/1024**3:.1f}GB")
except ImportError:
    print("安装psutil可获得更精确监控")
```

该版本在保证功能完整性的同时，提供了更好的平台兼容性和更智能的资源管理策略，适合在各种环境下部署使用。
