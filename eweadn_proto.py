# -*- coding: utf-8 -*-
"""EWEADN（前行者）S9 无线鼠标 · 2.4G 接收器私有 HID 协议。

协议来源：官方网页驱动 hub.eweadn.cn/pq/web（WebHID 版）中的鼠标协议类，
本机实测通过。

    发送 00 30 00 00 00 00 ... 00 00       （33 字节；[1]=命令字 0x30 取设备信息，
                                            [32]=sum(buf[5..31]) & 0xFF，全零时也是 0）
    回包 00 30 00 01 0b | 4d 31 35 36 | 01 19 | 95 | aa | 00 | 45 | 01 ... 88
                         "M156"         fw      ic   rate  chg  69%  conn

字节位（以含 report id 的 33 字节回包为准）：
    [1]  命令字回显 0x30
    [5..8]  设备标识 ASCII（官方 MS.ini 里 Identify=4d,31,35,36 → "M156"）
    [9]  固件版本低字节   [10] 固件版本高字节
    [11] sensor/IC 类型   [12] 回报率上限
    [13] 充电标志（0=未充电，非 0=充电中；设备主动推送时见过 0x01/0x04）
    [14] **电量百分比 0..100**
    [15] 连接状态（1=2.4G）

要点（踩过的坑）：
  * 用 ms_pix（00 xx 50 00 .. 4f 81）那套帧，设备只回 ack 不给数据；
    本协议 [1] 才是命令字，[3]=0x01 只用于写命令。
  * 必须用**同一个** OVERLAPPED 句柄 WriteFile + ReadFile，且写满 33 字节
    （含 report id 字节 0x00）；另一个读句柄收不到任何东西。
"""
from __future__ import annotations

import ctypes
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import Optional

import hid_win as hw

VID = 0x089D
PID = 0x062F
USAGE_PAGE = 0xFF01
REPORT_ID = 0x00
CMD_INFO = 0x30
FRAME_LEN = 33

OFF_MODEL = 5
OFF_FW_LO = 9
OFF_FW_HI = 10
OFF_IC = 11
OFF_RATE = 12
OFF_CHARGE = 13
OFF_BATTERY = 14
OFF_CONNECT = 15

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
class S9Battery:
    ok: bool
    level: Optional[int] = None
    charging: bool = False
    model: str = ""
    firmware: str = ""
    connect: str = ""
    raw: bytes = b""
    detail: str = ""


def find_interface():
    """接收器的 33 字节厂商通道（UsagePage 0xFF01 / Usage 0x10）。"""
    for d in hw.enumerate_hid():
        if d.vid == VID and d.pid == PID and d.usage_page == USAGE_PAGE \
                and d.input_len >= FRAME_LEN and d.output_len >= FRAME_LEN:
            return d
    return None


def build_frame(cmd: int = CMD_INFO) -> bytes:
    frame = bytearray(FRAME_LEN)
    frame[0] = REPORT_ID          # report id
    frame[1] = cmd                # 命令字
    frame[FRAME_LEN - 1] = sum(frame[5:FRAME_LEN - 1]) & 0xFF
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
        if hw.kernel32.WaitForSingleObject(event, 500) != WAIT_OBJECT_0:
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


def _decode_model(raw: bytes) -> str:
    txt = "".join(chr(b) for b in raw[OFF_MODEL:OFF_MODEL + 4] if 32 <= b < 127)
    return txt


def parse(raw: bytes) -> S9Battery:
    if not raw or len(raw) <= OFF_BATTERY:
        return S9Battery(ok=False, raw=raw, detail=f"回包太短（{len(raw)} 字节）")
    if raw[0] != REPORT_ID or raw[1] != CMD_INFO:
        return S9Battery(ok=False, raw=raw,
                         detail=f"不是设备信息回包（{raw[:4].hex(' ')}）")
    if raw[2] != 0x00:
        return S9Battery(ok=False, raw=raw,
                         detail=f"设备未就绪（状态 0x{raw[2]:02X}，动一下鼠标唤醒再读）")
    if not _decode_model(raw):
        return S9Battery(ok=False, raw=raw,
                         detail="设备未就绪（回包无型号，动一下鼠标唤醒再读）")
    level = raw[OFF_BATTERY]
    if level > 100:
        return S9Battery(ok=False, raw=raw,
                         detail=f"电量字节 0x{level:02X} 超出 0..100")
    fw = "v%X.%02X" % (raw[OFF_FW_HI], raw[OFF_FW_LO])
    conn = "2.4G" if raw[OFF_CONNECT] & 0x0F else "USB"
    return S9Battery(
        ok=True, level=level,
        charging=bool(raw[OFF_CHARGE]),
        model=_decode_model(raw),
        firmware=fw,
        connect=conn,
        raw=raw,
        detail=f"0x{CMD_INFO:02X} 电量@{OFF_BATTERY}={level}% "
               f"充电@{OFF_CHARGE}=0x{raw[OFF_CHARGE]:02X} 型号={_decode_model(raw)} {fw}",
    )


def read_battery(timeout_ms: int = 2500, retries: int = 3) -> S9Battery:
    """查询电量。鼠标休眠时会超时，动一下鼠标即可。"""
    iface = find_interface()
    if iface is None:
        return S9Battery(ok=False, detail="没找到 089D:062F 的 FF01 通道")
    frame = build_frame()
    try:
        handle, event = _open(iface.path)
    except OSError as e:
        return S9Battery(ok=False, detail=str(e))
    last = S9Battery(ok=False, detail="设备没有回复（动一下鼠标唤醒后重试）")
    try:
        for _ in range(max(1, retries)):
            if not _write(handle, event, frame):
                last = S9Battery(ok=False, detail="输出报告写入失败")
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


def read_battery_only(timeout_ms: int = 2500) -> tuple[Optional[int], str]:
    res = read_battery(timeout_ms=timeout_ms)
    if res.ok:
        return res.level, ""
    return None, res.detail


if __name__ == "__main__":
    r = read_battery()
    print("ok=%s level=%s charging=%s model=%s fw=%s raw=%s\n%s"
          % (r.ok, r.level, r.charging, r.model, r.firmware, r.raw.hex(" "), r.detail))
