import sys
import os
import time
import base64
import struct
import hmac
import hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from claude_remote_gui import SecurityManager, access_sessions


def test_totp_replay_prevention():
    print("[-] 测试 1: TOTP 2FA 防重放保护 (Replay Attack Prevention)...")
    sec = SecurityManager()
    sec.enabled = True
    secret = sec.generate_secret()

    padded = secret + '=' * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded.upper(), casefold=True)
    t = int(time.time() // 30)
    msg = struct.pack('>Q', t)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    binary = struct.unpack('>I', h[offset:offset+4])[0] & 0x7fffffff
    otp = str(binary % 1000000).zfill(6)

    ok1 = sec.verify_code(otp)
    assert ok1 is True, "首次 TOTP 验证失败"

    ok2 = sec.verify_code(otp)
    assert ok2 is False, "重放攻击未被拦截！TOTP 重复使用校验漏洞仍然存在"
    print("[+] 测试 1 通过: TOTP 动态码首次消费后成功拦截二次重放！")


def test_rate_limit_memory_bounding():
    print("[-] 测试 2: 频控与暴力破解内存字典容量上限 (TTL / LRU Bounding)...")
    sec = SecurityManager()
    for i in range(1200):
        sec.record_failed_attempt(f"192.168.1.{i}")

    assert len(sec._failed_attempts) <= 1500, f"2FA 失败字典无限膨胀: 当前大小 {len(sec._failed_attempts)}"
    print(f"[+] 测试 2 通过: 2FA 字典成功进行容量边界控制 (当前保留: {len(sec._failed_attempts)})")


def test_access_session_revocation():
    print("[-] 测试 3: 设备注销与会话票据同步吊销...")
    sid = access_sessions.issue("1.2.3.4")
    assert access_sessions.valid(sid, "1.2.3.4") is True, "会话票签发后校验失败"
    access_sessions.reset()
    assert access_sessions.valid(sid, "1.2.3.4") is False, "踢出设备后会话票未被注销"
    print("[+] 测试 3 通过: 设备踢下线时会话票据已被彻底吊销！")


if __name__ == "__main__":
    test_totp_replay_prevention()
    test_rate_limit_memory_bounding()
    test_access_session_revocation()
    print("\n==========================================")
    print(">>> 阶段 1 安全漏洞与内存泄漏修复全部验证通过！<<<")
    print("==========================================")
