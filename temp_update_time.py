
import toml
import time
import os

# 配置文件路径
creds_file = 'creds.toml'
# 目标凭证
credential_name = 'arcane-transit-469920-a6-1756070099-1756072275.json'
# 新的时间戳 = 当前时间 + 5分钟
new_timestamp = time.time() + 300

try:
    # 读取现有的 TOML 文件
    if os.path.exists(creds_file):
        with open(creds_file, 'r', encoding='utf-8') as f:
            creds = toml.load(f)
    else:
        creds = {}

    # 更新或创建凭证和状态
    if credential_name not in creds:
        creds[credential_name] = {}
    if "state" not in creds[credential_name]:
        creds[credential_name]["state"] = {}

    # 设置新的临时禁用时间
    creds[credential_name]["state"]["temp_disabled_until"] = new_timestamp
    creds[credential_name]["state"]["disabled"] = True # 确保它处于禁用状态

    # 写回文件
    with open(creds_file, 'w', encoding='utf-8') as f:
        toml.dump(creds, f)

    print(f"成功将凭证 {credential_name} 的恢复时间更新为 5 分钟后。")

except Exception as e:
    print(f"更新失败: {e}")
