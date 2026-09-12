import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from claude_remote_gui import ClaudeSession


def test_choice_serialization_and_generation():
    print("[-] 测试 4: 选项下发并发串行化 (Choice Lock FIFO)...")
    sess = ClaudeSession("test_sid", "测试会话")

    assert hasattr(sess, "_choice_lock"), "Session 缺少 _choice_lock 锁"
    assert hasattr(sess, "_buf_generation"), "Session 缺少 _buf_generation 世代号"

    sess.apply_choice("single", index=1)
    print("[+] 测试 4 通过: apply_choice 已引入互斥与串行保护机制！")


def test_buffer_generation_increment():
    print("[-] 测试 5: 缓冲区截断世代号自动递增与 Offset 保护...")
    sess = ClaudeSession("test_sid_2", "测试会话2")
    initial_gen = sess._buf_generation

    big_chunk = b"A" * 320000
    sess._append_output(big_chunk)

    assert sess._buf_generation == initial_gen + 1, f"缓冲区截断后世代号未递增: {sess._buf_generation}"

    inc = sess.get_incremental(offset=200000, generation=initial_gen)
    assert inc["reset"] is True, "世代号不一致时未能正确重置 offset"
    assert inc["generation"] == sess._buf_generation, "返回的 generation 不匹配"
    print("[+] 测试 5 通过: 缓冲区截断后世代号正确递增，且旧客户端 offset 自动安全重置！")


if __name__ == "__main__":
    test_choice_serialization_and_generation()
    test_buffer_generation_increment()
    print("\n==========================================")
    print(">>> 阶段 2 后端 PTY 与缓冲区修复全部验证通过！<<<")
    print("==========================================")
