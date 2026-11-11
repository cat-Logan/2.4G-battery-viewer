# -*- coding: utf-8 -*-
"""MCHOSE（迈从）G87 键盘 · 2.4G 接收器私有 HID 协议。

协议来源：kmizmal/mchose-battery（C# 实现）与 M HUB 网页驱动 WebHID 代码，
两者逐字节一致，本机实测通过。

    发送 13 4A 01 00 00 00 00 00 ... 00 5E      （20 字节，末字节=前 19 字节之和）
    回包 13 4A 01 00 02 3C 01 00 ... 00 9D      （第 6 字节 = 电量 0x3C = 60%）
                                                 （第 7 字节高 4 位=充电中，低 4 位=满电）

要点（踩过的坑）：必须用**同一个** OVERLAPPED 句柄做 WriteFile + ReadFile；
用 HidD_SetOutputReport 发、另开读句柄收，写会「成功」但永远收不到回包。
"""
from __future__ import annotations

import ctypes
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import Optional

import hid_win as hw

VID = 0x41E4
USAGE_PAGE = 0xFF02
REPORT_ID = 0x13
CMD_BATTERY = 0x4A
FRAME_LEN = 20

OFF_CMD = 1
OFF_BATTERY = 5
OFF_STATUS = 6

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x01
FILE_SHARE_WRITE = 0x02
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
ERROR_IO_PENDING = 997
WAIT_OBJECT_0 = 0x00000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


@dataclass
class G87Battery:
    ok: bool
    level: Optional[int] = None
    charging: bool = False
    full: bool = False
    raw: bytes = b""
    detail: str = ""


def find_interface():
    """接收器的 20 字节厂商通道（UsagePage 0xFF02，In=Out=20）。"""
    for d in hw.enumerate_hid():
        if d.vid == VID and d.usage_page == USAGE_PAGE \
                and d.input_len >= FRAME_LEN and d.output_len >= FRAME_LEN:
            return d
    return None


def build_frame() -> bytes:
    frame = bytearray(FRAME_LEN)
    frame[0] = REPORT_ID
    frame[1] = CMD_BATTERY
    frame[2] = 0x01          # 总分片数
    frame[3] = 0x00          # 当前分片
    frame[FRAME_LEN - 1] = sum(frame[:FRAME_LEN - 1]) & 0xFF
    return bytes(frame)


def _open(path: str):
    handle = hw.kernel32.CreateFileW(
        path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, None,
        OPEN_EXISTING, FILE_FLAG_OVERLAPPED, None,
    )
    if handle == INVALID_HANDLE_VALUE or not handle:
        raise OSError(f"打开设备失败 (err={ctypes.get_last_error()})")
    event = hw.kernel32.CreateEventW(None, True, False, None)
    return handle, event


def _write(handle, event, data: bytes) -> bool:
    ov = _OVERLAPPED()
    ov.hEvent = event
    buf = ctypes.create_string_buffer(data, len(data))
    done = wintypes.DWORD(0)
    hw.kernel32.ResetEvent(event)
    ok = hw.kernel32.WriteFile(handle, buf, len(data),
                               ctypes.byref(done), ctypes.byref(ov))
    if not ok:
        if ctypes.get_last_error() != ERROR_IO_PENDING:
            return False
        if hw.kernel32.WaitForSingleObject(event, 300) != WAIT_OBJECT_0:
            return False
        if not hw.kernel32.GetOverlappedResult(handle, ctypes.byref(ov),
                                               ctypes.byref(done), False):
            return False
    return True


def _read(handle, event, timeout_ms: int, length: int = FRAME_LEN) -> Optional[bytes]:
    ov = _OVERLAPPED()
    ov.hEvent = event
    buf = ctypes.create_string_buffer(length)
    done = wintypes.DWORD(0)
    hw.kernel32.ResetEvent(event)
    ok = hw.kernel32.ReadFile(handle, buf, length,
                              ctypes.byref(done), ctypes.byref(ov))
    if not ok:
        if ctypes.get_last_error() != ERROR_IO_PENDING:
            return None
    if hw.kernel32.WaitForSingleObject(event, max(1, timeout_ms)) != WAIT_OBJECT_0:
        hw.kernel32.CancelIoEx(handle, ctypes.byref(ov))
        return None
    if not hw.kernel32.GetOverlappedResult(handle, ctypes.byref(ov),
                                           ctypes.byref(done), False):
        return None
    if done.value <= 0:
        return None
    return buf.raw[: done.value]


def parse(raw: bytes) -> G87Battery:
    if not raw or len(raw) <= OFF_STATUS:
        return G87Battery(ok=False, raw=raw, detail=f"回包太短（{len(raw)} 字节）")
    if raw[0] != REPORT_ID or raw[OFF_CMD] != CMD_BATTERY:
        return G87Battery(ok=False, raw=raw,
                          detail=f"不是电量回包（{raw[:3].hex(' ')}）")
    percent = raw[OFF_BATTERY]
    status = raw[OFF_STATUS]
    if percent > 100:
        return G87Battery(ok=False, raw=raw,
                          detail=f"电量字节 0x{percent:02X} 超出 0..100")
    return G87Battery(
        ok=True, level=percent,
        charging=bool(status & 0xF0),   # 高 4 位 = chargeStatus
        full=bool(status & 0x0F),       # 低 4 位 = fullStatus
        raw=raw,
        detail=f"0x{REPORT_ID:02X}/0x{CMD_BATTERY:02X} 电量@{OFF_BATTERY}={percent}% "
               f"状态@{OFF_STATUS}=0x{status:02X}",
    )


def read_battery(timeout_ms: int = 1600, retries: int = 3) -> G87Battery:
    """查询电量。键盘休眠时前几次可能没回包，所以默认重试 3 次。"""
    iface = find_interface()
    if iface is None:
        return G87Battery(ok=False, detail="没找到 41E4:FF02 接收器通道")
    frame = build_frame()
    try:
        handle, event = _open(iface.path)
    except OSError as e:
        return G87Battery(ok=False, detail=str(e))
    last = G87Battery(ok=False, detail="设备没有回复（动一下键盘唤醒后重试）")
    try:
        for _ in range(max(1, retries)):
            if not _write(handle, event, frame):
                last = G87Battery(ok=False, detail="输出报告写入失败")
                continue
            deadline = time.monotonic() + timeout_ms / 1000.0
            while time.monotonic() < deadline:
                remain = int(max(20, (deadline - time.monotonic()) * 1000))
                raw = _read(handle, event, remain)
                if raw is None:
                    break
                res = parse(raw)
                if res.ok:
                    return res
                last = res
            time.sleep(0.05)
    finally:
        hw.kernel32.CloseHandle(event)
        hw.kernel32.CloseHandle(handle)
    return last


def read_battery_only(timeout_ms: int = 1600) -> tuple[Optional[int], str]:
    res = read_battery(timeout_ms=timeout_ms)
    if res.ok:
        return res.level, ""
    return None, res.detail


if __name__ == "__main__":
    r = read_battery()
    print("ok=%s level=%s charging=%s raw=%s\n%s"
          % (r.ok, r.level, r.charging, r.raw.hex(" "), r.detail))
