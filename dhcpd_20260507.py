"""
DHCPD - Python DHCP Server
RFC 2131 / RFC 2132 준수
- Tkinter GUI 설정
- In-Memory Lease 관리
- TXT 로그 파일
- DISCOVER / OFFER / REQUEST / ACK / NAK / DECLINE / RELEASE / INFORM 처리
- ARP Conflict Detection (DECLINE 처리 포함)
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import struct
import threading
import time
import datetime
import ipaddress
import logging
import os
import sys
import subprocess
import random
import platform
import copy
from collections import OrderedDict

# PDF (reportlab) - 없으면 경고만 출력
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable)
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

# ──────────────────────────────────────────────
# DHCP 상수 (RFC 2131 / 2132)
# ──────────────────────────────────────────────
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'
BROADCAST_ADDR = '255.255.255.255'
INADDR_ANY = '0.0.0.0'

# DHCP Message Types (Option 53)
DHCPDISCOVER = 1
DHCPOFFER    = 2
DHCPREQUEST  = 3
DHCPDECLINE  = 4
DHCPACK      = 5
DHCPNAK      = 6
DHCPRELEASE  = 7
DHCPINFORM   = 8

MSG_NAME = {
    DHCPDISCOVER: 'DHCPDISCOVER',
    DHCPOFFER:    'DHCPOFFER',
    DHCPREQUEST:  'DHCPREQUEST',
    DHCPDECLINE:  'DHCPDECLINE',
    DHCPACK:      'DHCPACK',
    DHCPNAK:      'DHCPNAK',
    DHCPRELEASE:  'DHCPRELEASE',
    DHCPINFORM:   'DHCPINFORM',
}

# DHCP Options
OPT_SUBNET_MASK      = 1
OPT_ROUTER           = 3
OPT_DNS              = 6
OPT_DOMAIN_NAME      = 15
OPT_BROADCAST        = 28
OPT_LEASE_TIME       = 51
OPT_MSG_TYPE         = 53
OPT_SERVER_ID        = 54
OPT_PARAM_LIST       = 55
OPT_MESSAGE          = 56
OPT_RENEWAL_TIME     = 58
OPT_REBINDING_TIME   = 59
OPT_CLIENT_ID        = 61
OPT_END              = 255

# ──────────────────────────────────────────────
# 유틸리티
# ──────────────────────────────────────────────
def ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)

def bytes_to_ip(b: bytes) -> str:
    return socket.inet_ntoa(b)

def mac_to_str(b: bytes) -> str:
    return ':'.join(f'{x:02x}' for x in b[:6])

def ip_int(ip: str) -> int:
    return struct.unpack('!I', socket.inet_aton(ip))[0]

def int_ip(n: int) -> str:
    return socket.inet_ntoa(struct.pack('!I', n))

def get_interfaces():
    """OS별 네트워크 인터페이스 목록 반환"""
    ifaces = []
    if platform.system() == 'Windows':
        try:
            import subprocess
            out = subprocess.check_output(['ipconfig'], encoding='utf-8', errors='ignore')
            for line in out.splitlines():
                if 'adapter' in line.lower() and ':' in line:
                    name = line.split(':')[0].strip()
                    ifaces.append(name)
        except Exception:
            pass
        try:
            import ctypes
            import ctypes.wintypes
            # socket 기반 대체
            hostname = socket.gethostname()
            ips = socket.getaddrinfo(hostname, None)
            for info in ips:
                if info[0] == socket.AF_INET:
                    ifaces.append(info[4][0])
        except Exception:
            pass
    else:
        try:
            import fcntl
            import struct as st
            SIOCGIFCONF = 0x8912
            MAXBYTES = 8096
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            names = bytearray(MAXBYTES)
            bytelen = st.pack('iL', MAXBYTES, id(names))
            try:
                fcntl.ioctl(s.fileno(), SIOCGIFCONF, bytelen)
                maxlen = st.unpack('iL', bytelen)[0]
                for i in range(0, maxlen, 40):
                    name = names[i:i+16].split(b'\0', 1)[0].decode()
                    if name:
                        ifaces.append(name)
            except Exception:
                pass
            s.close()
        except Exception:
            pass
        # /proc/net/dev fallback
        if not ifaces:
            try:
                with open('/proc/net/dev') as f:
                    for line in f:
                        if ':' in line:
                            name = line.split(':')[0].strip()
                            if name:
                                ifaces.append(name)
            except Exception:
                pass
    # lo 제거, 중복 제거
    seen = set()
    result = []
    for i in ifaces:
        if i not in seen and i not in ('lo', 'localhost'):
            seen.add(i)
            result.append(i)
    return result if result else ['0.0.0.0']

def get_iface_ip(iface: str) -> str:
    """인터페이스의 IP 주소 조회"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        import fcntl, struct as st
        SIOCGIFADDR = 0x8915
        ip = st.unpack('!4s', fcntl.ioctl(
            s.fileno(), SIOCGIFADDR,
            st.pack('256s', iface[:15].encode())
        )[20:24])[0]
        return socket.inet_ntoa(ip)
    except Exception:
        return '0.0.0.0'

# ──────────────────────────────────────────────
# DHCP 패킷 파싱 / 빌드
# ──────────────────────────────────────────────
class DHCPPacket:
    """RFC 2131 DHCP 패킷 파싱 및 생성"""

    # op, htype, hlen, hops, xid, secs, flags,
    # ciaddr, yiaddr, siaddr, giaddr, chaddr(16), sname(64), file(128), magic(4)
    FIXED_FMT = '!BBBBIHHIIII16s64s128s4s'
    FIXED_LEN = struct.calcsize(FIXED_FMT)  # 236 + 4 = 240

    def __init__(self):
        self.op = 1
        self.htype = 1
        self.hlen = 6
        self.hops = 0
        self.xid = 0
        self.secs = 0
        self.flags = 0x8000  # Broadcast flag
        self.ciaddr = '0.0.0.0'
        self.yiaddr = '0.0.0.0'
        self.siaddr = '0.0.0.0'
        self.giaddr = '0.0.0.0'
        self.chaddr = b'\x00' * 16
        self.sname = b'\x00' * 64
        self.file = b'\x00' * 128
        self.options: dict = {}

    @classmethod
    def parse(cls, data: bytes) -> 'DHCPPacket':
        pkt = cls()
        if len(data) < cls.FIXED_LEN:
            raise ValueError('Packet too short')
        fields = struct.unpack(cls.FIXED_FMT, data[:cls.FIXED_LEN])
        pkt.op, pkt.htype, pkt.hlen, pkt.hops = fields[0], fields[1], fields[2], fields[3]
        pkt.xid = fields[4]
        pkt.secs, pkt.flags = fields[5], fields[6]
        pkt.ciaddr = bytes_to_ip(struct.pack('!I', fields[7]))
        pkt.yiaddr = bytes_to_ip(struct.pack('!I', fields[8]))
        pkt.siaddr = bytes_to_ip(struct.pack('!I', fields[9]))
        pkt.giaddr = bytes_to_ip(struct.pack('!I', fields[10]))
        pkt.chaddr = fields[11]
        pkt.sname = fields[12]
        pkt.file = fields[13]
        magic = fields[14]
        if magic != DHCP_MAGIC_COOKIE:
            raise ValueError('Invalid magic cookie')
        # 옵션 파싱
        pkt.options = cls._parse_options(data[cls.FIXED_LEN:])
        return pkt

    @staticmethod
    def _parse_options(data: bytes) -> dict:
        opts = {}
        i = 0
        while i < len(data):
            code = data[i]
            if code == 0:   # Pad
                i += 1
                continue
            if code == 255: # End
                break
            if i + 1 >= len(data):
                break
            length = data[i + 1]
            val = data[i + 2: i + 2 + length]
            opts[code] = val
            i += 2 + length
        return opts

    def build(self) -> bytes:
        ciaddr = ip_to_bytes(self.ciaddr)
        yiaddr = ip_to_bytes(self.yiaddr)
        siaddr = ip_to_bytes(self.siaddr)
        giaddr = ip_to_bytes(self.giaddr)
        header = struct.pack(
            self.FIXED_FMT,
            self.op, self.htype, self.hlen, self.hops,
            self.xid, self.secs, self.flags,
            struct.unpack('!I', ciaddr)[0],
            struct.unpack('!I', yiaddr)[0],
            struct.unpack('!I', siaddr)[0],
            struct.unpack('!I', giaddr)[0],
            self.chaddr, self.sname, self.file,
            DHCP_MAGIC_COOKIE
        )
        opt_bytes = b''
        for code, val in self.options.items():
            opt_bytes += bytes([code, len(val)]) + val
        opt_bytes += bytes([OPT_END])
        # 패딩 (최소 300바이트)
        total = len(header) + len(opt_bytes)
        if total < 300:
            opt_bytes += b'\x00' * (300 - total)
        return header + opt_bytes

    @property
    def mac(self) -> str:
        return mac_to_str(self.chaddr[:self.hlen])

    @property
    def msg_type(self) -> int:
        return self.options.get(OPT_MSG_TYPE, b'\x00')[0]


# ──────────────────────────────────────────────
# Lease 관리 (In-Memory)
# ──────────────────────────────────────────────
class LeaseState:
    FREE = 'FREE'
    OFFERED = 'OFFERED'
    LEASED = 'LEASED'
    DECLINED = 'DECLINED'
    EXPIRED = 'EXPIRED'

class Lease:
    def __init__(self, ip: str, mac: str, state: str, expire_ts: float, hostname: str = ''):
        self.ip = ip
        self.mac = mac
        self.state = state
        self.expire_ts = expire_ts
        self.hostname = hostname
        self.offered_at = time.time()

    def is_expired(self) -> bool:
        if self.state in (LeaseState.FREE, LeaseState.DECLINED):
            return False
        return time.time() > self.expire_ts

    def remaining(self) -> int:
        if self.state in (LeaseState.FREE, LeaseState.DECLINED):
            return 0
        return max(0, int(self.expire_ts - time.time()))

    def expire_str(self) -> str:
        if self.state in (LeaseState.FREE, LeaseState.DECLINED):
            return '-'
        return datetime.datetime.fromtimestamp(self.expire_ts).strftime('%H:%M:%S')


class LeaseDB:
    """In-Memory Lease 데이터베이스"""

    def __init__(self):
        self._lock = threading.Lock()
        # ip -> Lease
        self._leases: dict[str, Lease] = {}
        # mac -> ip (빠른 조회)
        self._mac_to_ip: dict[str, str] = {}

    def allocate(self, pool_start: str, pool_end: str,
                 static_map: dict, mac: str,
                 lease_sec: int, offer_sec: int = 30) -> str | None:
        """MAC에 IP 할당. 이미 임대된 경우 동일 IP 반환."""
        with self._lock:
            # 1. 정적 매핑 확인
            if mac in static_map:
                ip = static_map[mac]
                self._set_lease(ip, mac, LeaseState.OFFERED, time.time() + offer_sec)
                return ip
            # 2. 기존 임대 확인
            if mac in self._mac_to_ip:
                ip = self._mac_to_ip[mac]
                lease = self._leases.get(ip)
                if lease and lease.state in (LeaseState.LEASED, LeaseState.OFFERED):
                    lease.expire_ts = time.time() + offer_sec
                    lease.state = LeaseState.OFFERED
                    return ip
            # 3. 새 IP 할당
            start_int = ip_int(pool_start)
            end_int = ip_int(pool_end)
            for i in range(start_int, end_int + 1):
                ip = int_ip(i)
                lease = self._leases.get(ip)
                if lease is None or lease.state == LeaseState.FREE:
                    self._set_lease(ip, mac, LeaseState.OFFERED, time.time() + offer_sec)
                    return ip
                if lease.state == LeaseState.EXPIRED or lease.is_expired():
                    # 만료된 임대 재사용
                    old_mac = lease.mac
                    if old_mac in self._mac_to_ip:
                        del self._mac_to_ip[old_mac]
                    self._set_lease(ip, mac, LeaseState.OFFERED, time.time() + offer_sec)
                    return ip
            return None

    def confirm(self, ip: str, mac: str, lease_sec: int):
        with self._lock:
            self._set_lease(ip, mac, LeaseState.LEASED, time.time() + lease_sec)

    def release(self, ip: str, mac: str):
        with self._lock:
            lease = self._leases.get(ip)
            if lease and lease.mac == mac:
                lease.state = LeaseState.FREE
                if mac in self._mac_to_ip:
                    del self._mac_to_ip[mac]

    def decline(self, ip: str, mac: str):
        """DECLINE: IP 격리 (RFC 2131 §3.4)"""
        with self._lock:
            self._leases[ip] = Lease(ip, mac, LeaseState.DECLINED, 0)
            if mac in self._mac_to_ip:
                del self._mac_to_ip[mac]

    def get_by_mac(self, mac: str) -> Lease | None:
        with self._lock:
            ip = self._mac_to_ip.get(mac)
            return self._leases.get(ip) if ip else None

    def get_by_ip(self, ip: str) -> Lease | None:
        with self._lock:
            return self._leases.get(ip)

    def _set_lease(self, ip: str, mac: str, state: str, expire_ts: float):
        self._leases[ip] = Lease(ip, mac, state, expire_ts)
        if state != LeaseState.FREE:
            self._mac_to_ip[mac] = ip

    def cleanup_expired(self):
        with self._lock:
            for ip, lease in list(self._leases.items()):
                if lease.is_expired():
                    lease.state = LeaseState.EXPIRED
                    if lease.mac in self._mac_to_ip:
                        del self._mac_to_ip[lease.mac]

    def snapshot(self) -> list[Lease]:
        with self._lock:
            return list(self._leases.values())


# ──────────────────────────────────────────────
# Logger
# ──────────────────────────────────────────────
class DHCPLogger:
    def __init__(self, log_path: str):
        self.log_path = log_path
        self._lock = threading.Lock()
        self._gui_callbacks = []
        # 파이썬 logger
        self._logger = logging.getLogger('DHCPD')
        self._logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(log_path, encoding='utf-8')
        fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        self._logger.addHandler(fh)

    def add_gui_callback(self, cb):
        self._gui_callbacks.append(cb)

    def _emit(self, level: str, msg: str):
        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        line = f'[{ts}] [{level}] {msg}'
        getattr(self._logger, level.lower(), self._logger.info)(msg)
        for cb in self._gui_callbacks:
            try:
                cb(level, line)
            except Exception:
                pass

    def info(self, msg): self._emit('INFO', msg)
    def warn(self, msg): self._emit('WARNING', msg)
    def error(self, msg): self._emit('ERROR', msg)
    def debug(self, msg): self._emit('DEBUG', msg)

    def log_rx(self, msg_type: int, mac: str, src_ip: str):
        name = MSG_NAME.get(msg_type, f'UNKNOWN({msg_type})')
        self.info(f'RX  {name:<16} from {mac}  src={src_ip}')

    def log_tx(self, msg_type: int, mac: str, offered_ip: str):
        name = MSG_NAME.get(msg_type, f'UNKNOWN({msg_type})')
        self.info(f'TX  {name:<16} to   {mac}  ip={offered_ip}')

    def log_lease(self, action: str, ip: str, mac: str, duration: int = 0):
        if duration:
            self.info(f'LEASE {action:<10} ip={ip}  mac={mac}  duration={duration}s')
        else:
            self.info(f'LEASE {action:<10} ip={ip}  mac={mac}')


# ──────────────────────────────────────────────
# Conflict Detection
# ──────────────────────────────────────────────
class ConflictDetector:
    """
    RFC 2131 §2.1 - DHCPD는 OFFER 전 ARP로 IP 사용 여부 확인 가능
    (선택적 기능; 구현 환경에 따라 작동 여부 다름)
    """

    @staticmethod
    def probe(ip: str, timeout: float = 0.3) -> bool:
        """ARP 또는 ICMP ping으로 IP 사용 여부 확인. True=충돌"""
        system = platform.system()
        if system == 'Windows':
            cmd = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip]
        else:
            cmd = ['ping', '-c', '1', '-W', str(max(1, int(timeout))), ip]
        try:
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=timeout + 1)
            return result.returncode == 0
        except Exception:
            return False


# ──────────────────────────────────────────────
# DHCP Server Core
# ──────────────────────────────────────────────
class DHCPServer:
    """RFC 2131 DHCP Server"""

    def __init__(self, config: dict, logger: DHCPLogger, lease_db: LeaseDB,
                 on_lease_change=None):
        self.config = config
        self.logger = logger
        self.db = lease_db
        self.on_lease_change = on_lease_change
        self._sock = None
        self._running = False
        self._thread = None
        self._gc_thread = None
        self._detector = ConflictDetector()

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._gc_thread = threading.Thread(target=self._gc_loop, daemon=True)
        self._gc_thread.start()
        self.logger.info(f'DHCPD 시작: 인터페이스={self.config["iface"]}  '
                         f'풀={self.config["pool_start"]}~{self.config["pool_end"]}')

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        self.logger.info('DHCPD 중지')

    def _bind(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                         self.config['iface'].encode())
        except (AttributeError, OSError):
            pass
        s.bind((INADDR_ANY, DHCP_SERVER_PORT))
        s.settimeout(2.0)
        return s

    def _run(self):
        try:
            self._sock = self._bind()
        except Exception as e:
            self.logger.error(f'소켓 바인드 실패: {e}')
            self._running = False
            return
        self.logger.info(f'UDP {DHCP_SERVER_PORT} 포트 바인드 완료')
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
                threading.Thread(target=self._handle, args=(data, addr),
                                 daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                self.logger.error(f'수신 오류: {e}')

    def _gc_loop(self):
        """만료 임대 정리"""
        while self._running:
            time.sleep(30)
            self.db.cleanup_expired()
            if self.on_lease_change:
                self.on_lease_change()

    def _handle(self, data: bytes, addr):
        try:
            pkt = DHCPPacket.parse(data)
        except Exception as e:
            self.logger.warn(f'패킷 파싱 실패: {e}')
            return

        src_ip = addr[0]
        mac = pkt.mac
        msg_type = pkt.msg_type
        self.logger.log_rx(msg_type, mac, src_ip)

        if msg_type == DHCPDISCOVER:
            self._handle_discover(pkt)
        elif msg_type == DHCPREQUEST:
            self._handle_request(pkt)
        elif msg_type == DHCPDECLINE:
            self._handle_decline(pkt)
        elif msg_type == DHCPRELEASE:
            self._handle_release(pkt)
        elif msg_type == DHCPINFORM:
            self._handle_inform(pkt)
        else:
            self.logger.warn(f'처리되지 않은 메시지 타입: {msg_type} from {mac}')

    # ── DISCOVER → OFFER ──────────────────────
    def _handle_discover(self, pkt: DHCPPacket):
        """RFC 2131 §3.1 Step 2"""
        mac = pkt.mac
        cfg = self.config

        ip = self.db.allocate(
            cfg['pool_start'], cfg['pool_end'],
            cfg.get('static_map', {}), mac,
            cfg['lease_time'], offer_sec=30
        )
        if ip is None:
            self.logger.warn(f'IP 풀 소진: DISCOVER 무시 mac={mac}')
            return

        # 선택적 충돌 감지 (OFFER 전 ARP)
        if cfg.get('conflict_detect', False):
            if self._detector.probe(ip):
                self.logger.warn(f'ARP 충돌 감지: {ip} 격리 (DISCOVER from {mac})')
                self.db.decline(ip, 'arp-probe')
                # 재시도
                ip = self.db.allocate(
                    cfg['pool_start'], cfg['pool_end'],
                    cfg.get('static_map', {}), mac,
                    cfg['lease_time'], offer_sec=30
                )
                if ip is None:
                    return

        resp = self._make_base_reply(pkt)
        resp.op = 2  # BOOTREPLY
        resp.yiaddr = ip
        resp.siaddr = cfg['server_ip']
        resp.options = self._build_options(DHCPOFFER, cfg)
        self._send(resp, pkt)
        self.logger.log_tx(DHCPOFFER, mac, ip)
        if self.on_lease_change:
            self.on_lease_change()

    # ── REQUEST → ACK / NAK ──────────────────
    def _handle_request(self, pkt: DHCPPacket):
        """RFC 2131 §3.1 Step 3–5 및 §3.2, §3.3"""
        mac = pkt.mac
        cfg = self.config

        # 요청 IP 결정 (Option 50 또는 ciaddr)
        req_ip_bytes = pkt.options.get(50)  # Requested IP Address
        server_id_bytes = pkt.options.get(OPT_SERVER_ID)

        if req_ip_bytes:
            requested_ip = bytes_to_ip(req_ip_bytes)
        elif pkt.ciaddr != '0.0.0.0':
            requested_ip = pkt.ciaddr
        else:
            requested_ip = None

        # ── Server Identifier 확인 (다른 서버 선택 시 무시) ──
        if server_id_bytes:
            server_id = bytes_to_ip(server_id_bytes)
            if server_id != cfg['server_ip']:
                # RFC 2131 §3.1: 다른 DHCP 서버를 선택한 경우 임대 취소
                self.logger.info(f'다른 서버 선택됨({server_id}): 임대 취소 mac={mac}')
                lease = self.db.get_by_mac(mac)
                if lease:
                    self.db.release(lease.ip, mac)
                    if self.on_lease_change:
                        self.on_lease_change()
                return

        # ── 유효성 검사 ──────────────────────
        nak_reason = None

        if requested_ip is None:
            nak_reason = 'No requested IP'
        else:
            # 풀 범위 내 확인
            try:
                pool_s = ip_int(cfg['pool_start'])
                pool_e = ip_int(cfg['pool_end'])
                req_int = ip_int(requested_ip)
                if not (pool_s <= req_int <= pool_e):
                    # 정적 맵 확인
                    static_map = cfg.get('static_map', {})
                    if static_map.get(mac) != requested_ip:
                        nak_reason = f'IP {requested_ip} not in pool range'
            except Exception:
                nak_reason = 'Invalid IP'

            if nak_reason is None:
                lease = self.db.get_by_ip(requested_ip)
                if lease:
                    if lease.state == LeaseState.DECLINED:
                        nak_reason = f'IP {requested_ip} is in DECLINED state'
                    elif lease.mac != mac and lease.state == LeaseState.LEASED:
                        nak_reason = f'IP {requested_ip} already leased to {lease.mac}'

        if nak_reason:
            self._send_nak(pkt, nak_reason)
            self.logger.warn(f'NAK 전송: {nak_reason}  mac={mac}')
            return

        # ── ACK ─────────────────────────────
        self.db.confirm(requested_ip, mac, cfg['lease_time'])
        self.logger.log_lease('ASSIGN', requested_ip, mac, cfg['lease_time'])

        resp = self._make_base_reply(pkt)
        resp.op = 2
        resp.yiaddr = requested_ip
        resp.siaddr = cfg['server_ip']
        resp.options = self._build_options(DHCPACK, cfg)
        self._send(resp, pkt)
        self.logger.log_tx(DHCPACK, mac, requested_ip)
        if self.on_lease_change:
            self.on_lease_change()

    # ── DECLINE ──────────────────────────────
    def _handle_decline(self, pkt: DHCPPacket):
        """RFC 2131 §3.4 - 클라이언트가 충돌을 감지해 IP 반환"""
        mac = pkt.mac
        req_ip_bytes = pkt.options.get(50)
        if req_ip_bytes:
            ip = bytes_to_ip(req_ip_bytes)
            self.db.decline(ip, mac)
            self.logger.warn(f'DECLINE 수신: IP={ip} mac={mac} → 격리 처리')
            self.logger.log_lease('DECLINED', ip, mac)
        else:
            self.logger.warn(f'DECLINE 수신 (IP 없음): mac={mac}')
        if self.on_lease_change:
            self.on_lease_change()

    # ── RELEASE ──────────────────────────────
    def _handle_release(self, pkt: DHCPPacket):
        """RFC 2131 §3.3"""
        mac = pkt.mac
        ip = pkt.ciaddr
        if ip and ip != '0.0.0.0':
            self.db.release(ip, mac)
            self.logger.info(f'RELEASE 수신: IP={ip} mac={mac} → 풀 반환')
            self.logger.log_lease('RELEASE', ip, mac)
        if self.on_lease_change:
            self.on_lease_change()

    # ── INFORM → ACK (옵션만) ─────────────────
    def _handle_inform(self, pkt: DHCPPacket):
        """RFC 2131 §3.5 - 이미 IP 있는 클라이언트가 옵션만 요청"""
        mac = pkt.mac
        client_ip = pkt.ciaddr
        cfg = self.config

        resp = self._make_base_reply(pkt)
        resp.op = 2
        resp.yiaddr = '0.0.0.0'  # INFORM에 대한 ACK는 yiaddr=0
        resp.ciaddr = client_ip
        resp.siaddr = cfg['server_ip']
        opts = self._build_options(DHCPACK, cfg)
        # lease time 옵션 제거 (INFORM ACK에는 포함 안 함 - RFC 2131 §3.5)
        opts.pop(OPT_LEASE_TIME, None)
        opts.pop(OPT_RENEWAL_TIME, None)
        opts.pop(OPT_REBINDING_TIME, None)
        resp.options = opts
        # INFORM ACK는 유니캐스트로 직접 전송
        self._send_unicast(resp, client_ip)
        self.logger.log_tx(DHCPACK, mac, client_ip)

    # ── NAK 전송 ─────────────────────────────
    def _send_nak(self, pkt: DHCPPacket, reason: str = ''):
        cfg = self.config
        resp = self._make_base_reply(pkt)
        resp.op = 2
        resp.yiaddr = '0.0.0.0'
        resp.ciaddr = '0.0.0.0'
        resp.siaddr = cfg['server_ip']
        resp.options = {
            OPT_MSG_TYPE: bytes([DHCPNAK]),
            OPT_SERVER_ID: ip_to_bytes(cfg['server_ip']),
        }
        if reason:
            encoded = reason.encode('ascii', 'ignore')[:254]
            resp.options[OPT_MESSAGE] = encoded
        resp.flags = 0x8000  # Broadcast NAK (RFC 2131 §4.3.2)
        self._send(resp, pkt, force_broadcast=True)
        self.logger.log_tx(DHCPNAK, pkt.mac, '0.0.0.0')

    # ── 응답 전송 ─────────────────────────────
    def _send(self, resp: DHCPPacket, req: DHCPPacket, force_broadcast: bool = False):
        """RFC 2131 §4.1 응답 방식 결정"""
        data = resp.build()
        # giaddr이 있으면 relay agent로 전송
        if req.giaddr and req.giaddr != '0.0.0.0':
            self._sock.sendto(data, (req.giaddr, DHCP_SERVER_PORT))
            return
        # Broadcast flag 또는 ciaddr=0이면 브로드캐스트
        if force_broadcast or (req.flags & 0x8000) or req.ciaddr == '0.0.0.0':
            self._sock.sendto(data, (BROADCAST_ADDR, DHCP_CLIENT_PORT))
        else:
            self._sock.sendto(data, (req.ciaddr, DHCP_CLIENT_PORT))

    def _send_unicast(self, resp: DHCPPacket, dst_ip: str):
        data = resp.build()
        self._sock.sendto(data, (dst_ip, DHCP_CLIENT_PORT))

    # ── 헬퍼 ─────────────────────────────────
    def _make_base_reply(self, req: DHCPPacket) -> DHCPPacket:
        resp = DHCPPacket()
        resp.xid = req.xid
        resp.flags = req.flags
        resp.chaddr = req.chaddr
        resp.htype = req.htype
        resp.hlen = req.hlen
        resp.hops = req.hops
        resp.giaddr = req.giaddr
        return resp

    def _build_options(self, msg_type: int, cfg: dict) -> dict:
        lease = cfg['lease_time']
        t1 = lease // 2
        t2 = int(lease * 0.875)
        opts = {
            OPT_MSG_TYPE: bytes([msg_type]),
            OPT_SERVER_ID: ip_to_bytes(cfg['server_ip']),
            OPT_SUBNET_MASK: ip_to_bytes(cfg['subnet_mask']),
            OPT_LEASE_TIME: struct.pack('!I', lease),
            OPT_RENEWAL_TIME: struct.pack('!I', t1),
            OPT_REBINDING_TIME: struct.pack('!I', t2),
        }
        if cfg.get('gateway') and cfg['gateway'] != '0.0.0.0':
            opts[OPT_ROUTER] = ip_to_bytes(cfg['gateway'])
        dns_list = cfg.get('dns', [])
        if dns_list:
            opts[OPT_DNS] = b''.join(ip_to_bytes(d) for d in dns_list if d)
        bcast = cfg.get('broadcast')
        if bcast:
            opts[OPT_BROADCAST] = ip_to_bytes(bcast)
        domain = cfg.get('domain_name', '')
        if domain:
            opts[OPT_DOMAIN_NAME] = domain.encode()
        return opts


# ──────────────────────────────────────────────
# GUI
# ──────────────────────────────────────────────
# 자동화 탭 GUI (DHCPDApp에 믹스인)
# ──────────────────────────────────────────────

class AutoTabMixin:
    """DHCPDApp에 자동화 탭 기능 추가"""

    def _init_automation(self):
        self._engine = AutomationEngine(self)
        self._scenario_events: list[ScenarioEvent] = []
        self._auto_plan: dict = {}

    def _build_automation_tab(self):
        f = self.tab_auto
        pad = {'padx': 8, 'pady': 3}

        # ── 공통 설정 ──────────────────────────
        gcommon = ttk.LabelFrame(f, text=' 공통 설정 ')
        gcommon.pack(fill='x', padx=10, pady=(8, 4))

        tk.Label(gcommon, text='실행 모드:').grid(row=0, column=0, sticky='e', **pad)
        self.auto_mode_var = tk.StringVar(value='both')
        for col, (val, lbl) in enumerate([('sc1','시나리오1만'), ('sc2','시나리오2만'), ('both','1→2 순차')]):
            ttk.Radiobutton(gcommon, text=lbl, variable=self.auto_mode_var,
                            value=val).grid(row=0, column=col+1, sticky='w', padx=4, pady=3)

        tk.Label(gcommon, text='시나리오 간 대기(초):').grid(row=0, column=4, sticky='e', **pad)
        self.between_sec_var = tk.StringVar(value='5')
        tk.Entry(gcommon, textvariable=self.between_sec_var, width=6).grid(
            row=0, column=5, sticky='w', **pad)

        tk.Label(gcommon, text='감시 MAC (IP 재할당 확인):').grid(row=1, column=0, sticky='e', **pad)
        self.watch_mac_var = tk.StringVar(value='')
        tk.Entry(gcommon, textvariable=self.watch_mac_var, width=20).grid(
            row=1, column=1, columnspan=3, sticky='w', **pad)
        tk.Label(gcommon, text='예: aa:bb:cc:dd:ee:ff', fg='gray50').grid(
            row=1, column=4, columnspan=2, sticky='w', **pad)

        # ── 시나리오 1 ─────────────────────────
        g1 = ttk.LabelFrame(f, text=' 시나리오 1 : DHCP 정보 변경 ')
        g1.pack(fill='x', padx=10, pady=4)

        # 변경할 DHCP 설정
        tk.Label(g1, text='변경 Pool 시작:').grid(row=0, column=0, sticky='e', **pad)
        self.sc1_pool_start = tk.StringVar(value='192.168.0.150')
        tk.Entry(g1, textvariable=self.sc1_pool_start, width=16).grid(row=0, column=1, sticky='w', **pad)

        tk.Label(g1, text='변경 Pool 종료:').grid(row=0, column=2, sticky='e', **pad)
        self.sc1_pool_end = tk.StringVar(value='192.168.0.200')
        tk.Entry(g1, textvariable=self.sc1_pool_end, width=16).grid(row=0, column=3, sticky='w', **pad)

        tk.Label(g1, text='변경 GW:').grid(row=1, column=0, sticky='e', **pad)
        self.sc1_gw = tk.StringVar(value='192.168.0.1')
        tk.Entry(g1, textvariable=self.sc1_gw, width=16).grid(row=1, column=1, sticky='w', **pad)

        tk.Label(g1, text='변경 Lease(초):').grid(row=1, column=2, sticky='e', **pad)
        self.sc1_lease = tk.StringVar(value='3600')
        tk.Entry(g1, textvariable=self.sc1_lease, width=10).grid(row=1, column=3, sticky='w', **pad)

        tk.Label(g1, text='변경 DNS:').grid(row=2, column=0, sticky='e', **pad)
        self.sc1_dns = tk.StringVar(value='1.1.1.1')
        tk.Entry(g1, textvariable=self.sc1_dns, width=16).grid(row=2, column=1, sticky='w', **pad)

        tk.Label(g1, text='변경 서브넷:').grid(row=2, column=2, sticky='e', **pad)
        self.sc1_subnet = tk.StringVar(value='255.255.255.0')
        tk.Entry(g1, textvariable=self.sc1_subnet, width=16).grid(row=2, column=3, sticky='w', **pad)

        # 타이밍
        tk.Label(g1, text='변경 시점까지 대기(초):').grid(row=3, column=0, sticky='e', **pad)
        self.sc1_change_sec = tk.StringVar(value='10')
        tk.Entry(g1, textvariable=self.sc1_change_sec, width=8).grid(row=3, column=1, sticky='w', **pad)

        tk.Label(g1, text='원복까지 대기(초):').grid(row=3, column=2, sticky='e', **pad)
        self.sc1_restore_sec = tk.StringVar(value='30')
        tk.Entry(g1, textvariable=self.sc1_restore_sec, width=8).grid(row=3, column=3, sticky='w', **pad)

        tk.Label(g1, text='반복 횟수:').grid(row=4, column=0, sticky='e', **pad)
        self.sc1_cycles = tk.StringVar(value='1')
        ttk.Spinbox(g1, textvariable=self.sc1_cycles, from_=1, to=99, width=6).grid(
            row=4, column=1, sticky='w', **pad)

        # ── 시나리오 2 ─────────────────────────
        g2 = ttk.LabelFrame(f, text=' 시나리오 2 : DHCP 정지 / 재시작 ')
        g2.pack(fill='x', padx=10, pady=4)

        tk.Label(g2, text='정지 후 재시작까지 대기(초):').grid(row=0, column=0, sticky='e', **pad)
        self.sc2_stop_sec = tk.StringVar(value='30')
        tk.Entry(g2, textvariable=self.sc2_stop_sec, width=8).grid(row=0, column=1, sticky='w', **pad)

        tk.Label(g2, text='전체 지속 시간:').grid(row=0, column=2, sticky='e', **pad)
        self.sc2_duration_var = tk.StringVar(value='10')
        sc2_dur_frame = ttk.Frame(g2)
        sc2_dur_frame.grid(row=0, column=3, sticky='w', **pad)
        ttk.Spinbox(sc2_dur_frame, textvariable=self.sc2_duration_var,
                    from_=10, to=1440, increment=10, width=6).pack(side='left')
        tk.Label(sc2_dur_frame, text='분').pack(side='left', padx=2)

        tk.Label(g2, text='※ 정지/재시작을 지속 시간 내에서 반복합니다.',
                 fg='gray50').grid(row=1, column=0, columnspan=4, sticky='w', padx=8, pady=2)

        # ── 실행 버튼 & 이벤트 뷰 ──────────────
        btn_frame = ttk.Frame(f)
        btn_frame.pack(fill='x', padx=10, pady=6)

        self.auto_start_btn = ttk.Button(btn_frame, text='▶  자동화 시작',
                                         command=self._auto_start, width=16)
        self.auto_start_btn.pack(side='left', padx=4)
        self.auto_stop_btn = ttk.Button(btn_frame, text='■  중지',
                                        command=self._auto_stop, width=10, state='disabled')
        self.auto_stop_btn.pack(side='left', padx=4)
        self.auto_pdf_btn = ttk.Button(btn_frame, text='PDF 리포트 저장',
                                       command=self._save_pdf, width=16, state='disabled')
        self.auto_pdf_btn.pack(side='left', padx=4)

        self.auto_status_var = tk.StringVar(value='대기 중')
        tk.Label(btn_frame, textvariable=self.auto_status_var,
                 fg='gray40').pack(side='right', padx=8)

        # 이벤트 테이블
        ev_frame = ttk.Frame(f)
        ev_frame.pack(fill='both', expand=True, padx=10, pady=(0, 8))

        cols = ('ts', 'scenario', 'action', 'detail', 'result')
        self.auto_tree = ttk.Treeview(ev_frame, columns=cols, show='headings', height=10)
        hdrs = {'ts': ('시각', 140), 'scenario': ('시나리오', 80),
                'action': ('액션', 120), 'detail': ('상세', 320), 'result': ('결과', 60)}
        for col, (hdr, w) in hdrs.items():
            self.auto_tree.heading(col, text=hdr)
            self.auto_tree.column(col, width=w, anchor='w')

        sb2 = ttk.Scrollbar(ev_frame, orient='vertical', command=self.auto_tree.yview)
        self.auto_tree.configure(yscrollcommand=sb2.set)
        self.auto_tree.pack(side='left', fill='both', expand=True)
        sb2.pack(side='right', fill='y')

        self.auto_tree.tag_configure('OK',   foreground='#1a7a1a')
        self.auto_tree.tag_configure('FAIL', foreground='#cc0000')
        self.auto_tree.tag_configure('INFO', foreground='gray50')

    # ── 자동화 제어 ────────────────────────────
    def _auto_start(self):
        if not self.server or not self.server._running:
            messagebox.showwarning('알림', 'DHCP 서버가 실행 중이어야 합니다.\n설정 탭에서 서버를 먼저 시작하세요.')
            return
        plan = self._build_plan()
        if plan is None:
            return
        self._auto_plan = plan
        self._scenario_events.clear()
        for row in self.auto_tree.get_children():
            self.auto_tree.delete(row)

        self._engine.start(plan)
        self.auto_start_btn.config(state='disabled')
        self.auto_stop_btn.config(state='normal')
        self.auto_pdf_btn.config(state='disabled')
        self.auto_status_var.set('실행 중...')

    def _auto_stop(self):
        self._engine.stop()
        self.auto_status_var.set('중지 요청됨...')

    def _save_pdf(self):
        if not REPORTLAB_OK:
            messagebox.showerror('오류', 'reportlab 라이브러리가 필요합니다.\npip install reportlab')
            return
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        path = f'dhcpd_scenario_report_{ts}.pdf'
        ok = generate_pdf_report(self._scenario_events, self._auto_plan, path)
        if ok:
            messagebox.showinfo('완료', f'PDF 저장 완료:\n{os.path.abspath(path)}')
            try:
                if platform.system() == 'Windows':
                    os.startfile(path)
                elif platform.system() == 'Darwin':
                    subprocess.run(['open', path])
                else:
                    subprocess.run(['xdg-open', path])
            except Exception:
                pass
        else:
            messagebox.showerror('오류', 'PDF 생성 실패. reportlab을 확인하세요.')

    def _on_scenario_event(self, evt: ScenarioEvent):
        self._scenario_events.append(evt)
        self.auto_tree.insert('', 'end', values=(
            evt.ts, evt.scenario, evt.action, evt.detail, evt.result
        ), tags=(evt.result,))
        self.auto_tree.yview_moveto(1.0)

    def _on_automation_done(self):
        self.auto_start_btn.config(state='normal')
        self.auto_stop_btn.config(state='disabled')
        self.auto_pdf_btn.config(state='normal')
        ok   = sum(1 for e in self._scenario_events if e.result == 'OK')
        fail = sum(1 for e in self._scenario_events if e.result == 'FAIL')
        self.auto_status_var.set(f'완료  OK={ok}  FAIL={fail}')
        # 서버가 중지됐을 수 있으면 버튼 상태 동기화
        if self.server and not self.server._running:
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
            self.status_var.set('■ 중지됨')

    def _stop_server_silent(self):
        """자동화 엔진에서 호출: 조용히 서버 정지"""
        if self.server:
            self.server.stop()
        self.status_var.set('■ 중지됨 (자동화)')

    def _start_server_silent(self):
        """자동화 엔진에서 호출: 조용히 서버 재시작"""
        cfg = self._get_config()
        if cfg is None:
            return
        if self.server:
            try:
                self.server.stop()
            except Exception:
                pass
        self.server = DHCPServer(cfg, self.logger, self.db,
                                 on_lease_change=self._schedule_lease_refresh_now)
        self.server.start()
        self.status_var.set('▶ 실행 중 (자동화 재시작)')

    def _build_plan(self) -> dict | None:
        """GUI 입력값 → plan 딕셔너리"""
        try:
            plan = {
                'mode': self.auto_mode_var.get(),
                'between_sec': int(self.between_sec_var.get()),
                'watch_mac': self.watch_mac_var.get().strip().lower(),
                'sc1_change_sec': int(self.sc1_change_sec.get()),
                'sc1_restore_sec': int(self.sc1_restore_sec.get()),
                'sc1_cycles': int(self.sc1_cycles.get()),
                'sc2_stop_sec': int(self.sc2_stop_sec.get()),
                'sc2_duration_sec': int(self.sc2_duration_var.get()) * 60,
            }
        except ValueError as e:
            messagebox.showerror('입력 오류', f'숫자를 확인하세요: {e}')
            return None

        # 시나리오1 변경 설정 구성
        base = self._get_config()
        if base is None:
            return None
        sc1_cfg = copy.deepcopy(base)
        sc1_cfg['pool_start'] = self.sc1_pool_start.get().strip()
        sc1_cfg['pool_end']   = self.sc1_pool_end.get().strip()
        sc1_cfg['gateway']    = self.sc1_gw.get().strip()
        sc1_cfg['lease_time'] = int(self.sc1_lease.get())
        dns_raw = self.sc1_dns.get().strip()
        sc1_cfg['dns'] = [d.strip() for d in dns_raw.split(',') if d.strip()]
        sc1_cfg['subnet_mask'] = self.sc1_subnet.get().strip()
        plan['sc1_cfg'] = sc1_cfg

        return plan


# ──────────────────────────────────────────────
# DHCPDApp
# ──────────────────────────────────────────────
class DHCPDApp(AutoTabMixin):
    """Tkinter 기반 DHCPD GUI"""

    LOG_PATH = 'dhcpd.log'

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title('DHCPD - Python DHCP Server')
        self.root.geometry('940x680')
        self.root.resizable(True, True)

        self.server: DHCPServer | None = None
        self.logger = DHCPLogger(self.LOG_PATH)
        self.logger.add_gui_callback(self._on_log)
        self.db = LeaseDB()
        self._scenario_events: list = []
        self._auto_plan: dict = {}

        self._build_ui()
        self._load_iface_list()
        self._init_automation()

    # ─── UI 구성 ───────────────────────────────
    def _build_ui(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill='both', expand=True, padx=6, pady=6)

        self.tab_config = ttk.Frame(nb)
        self.tab_leases = ttk.Frame(nb)
        self.tab_log = ttk.Frame(nb)
        self.tab_auto = ttk.Frame(nb)
        nb.add(self.tab_config, text='  설정 / 제어  ')
        nb.add(self.tab_leases, text='  임대 현황  ')
        nb.add(self.tab_log,    text='  로그  ')
        nb.add(self.tab_auto,   text='  자동화 시나리오  ')

        self._build_config_tab()
        self._build_lease_tab()
        self._build_log_tab()
        self._build_automation_tab()

        # 하단 상태바
        self.status_var = tk.StringVar(value='■ 중지됨')
        status_bar = tk.Label(self.root, textvariable=self.status_var,
                              bd=1, relief='sunken', anchor='w', padx=8,
                              fg='gray40')
        status_bar.pack(fill='x', side='bottom')

    def _build_config_tab(self):
        f = self.tab_config
        pad = {'padx': 8, 'pady': 4}

        # ── 인터페이스 ──
        g1 = ttk.LabelFrame(f, text=' 인터페이스 선택 ')
        g1.pack(fill='x', padx=10, pady=(10, 4))

        tk.Label(g1, text='인터페이스:').grid(row=0, column=0, sticky='e', **pad)
        self.iface_var = tk.StringVar()
        self.iface_cb = ttk.Combobox(g1, textvariable=self.iface_var, width=22,
                                     state='readonly')
        self.iface_cb.grid(row=0, column=1, sticky='w', **pad)
        ttk.Button(g1, text='새로고침', command=self._load_iface_list,
                   width=10).grid(row=0, column=2, **pad)

        tk.Label(g1, text='서버 IP:').grid(row=0, column=3, sticky='e', **pad)
        self.server_ip_var = tk.StringVar(value='192.168.0.1')
        tk.Entry(g1, textvariable=self.server_ip_var, width=16).grid(
            row=0, column=4, sticky='w', **pad)

        # ── IP 풀 ──
        g2 = ttk.LabelFrame(f, text=' IP Pool 설정 ')
        g2.pack(fill='x', padx=10, pady=4)

        fields_row0 = [
            ('시작 IP:', 'pool_start_var', '192.168.0.100'),
            ('종료 IP:', 'pool_end_var', '192.168.0.200'),
        ]
        for col, (label, varname, default) in enumerate(fields_row0):
            tk.Label(g2, text=label).grid(row=0, column=col*2, sticky='e', **pad)
            var = tk.StringVar(value=default)
            setattr(self, varname, var)
            tk.Entry(g2, textvariable=var, width=16).grid(
                row=0, column=col*2+1, sticky='w', **pad)

        tk.Label(g2, text='서브넷 마스크:').grid(row=1, column=0, sticky='e', **pad)
        self.subnet_var = tk.StringVar(value='255.255.255.0')
        tk.Entry(g2, textvariable=self.subnet_var, width=16).grid(
            row=1, column=1, sticky='w', **pad)

        tk.Label(g2, text='브로드캐스트:').grid(row=1, column=2, sticky='e', **pad)
        self.broadcast_var = tk.StringVar(value='192.168.0.255')
        tk.Entry(g2, textvariable=self.broadcast_var, width=16).grid(
            row=1, column=3, sticky='w', **pad)

        # ── DHCP 옵션 ──
        g3 = ttk.LabelFrame(f, text=' DHCP 옵션 ')
        g3.pack(fill='x', padx=10, pady=4)

        tk.Label(g3, text='게이트웨이:').grid(row=0, column=0, sticky='e', **pad)
        self.gw_var = tk.StringVar(value='192.168.0.1')
        tk.Entry(g3, textvariable=self.gw_var, width=16).grid(
            row=0, column=1, sticky='w', **pad)

        tk.Label(g3, text='DNS 1:').grid(row=0, column=2, sticky='e', **pad)
        self.dns1_var = tk.StringVar(value='8.8.8.8')
        tk.Entry(g3, textvariable=self.dns1_var, width=16).grid(
            row=0, column=3, sticky='w', **pad)

        tk.Label(g3, text='DNS 2:').grid(row=0, column=4, sticky='e', **pad)
        self.dns2_var = tk.StringVar(value='8.8.4.4')
        tk.Entry(g3, textvariable=self.dns2_var, width=14).grid(
            row=0, column=5, sticky='w', **pad)

        tk.Label(g3, text='임대 시간(초):').grid(row=1, column=0, sticky='e', **pad)
        self.lease_var = tk.StringVar(value='86400')
        tk.Entry(g3, textvariable=self.lease_var, width=10).grid(
            row=1, column=1, sticky='w', **pad)

        tk.Label(g3, text='도메인:').grid(row=1, column=2, sticky='e', **pad)
        self.domain_var = tk.StringVar(value='')
        tk.Entry(g3, textvariable=self.domain_var, width=20).grid(
            row=1, column=3, columnspan=3, sticky='w', **pad)

        # ── 추가 옵션 ──
        g4 = ttk.LabelFrame(f, text=' 충돌 감지 / 정적 매핑 ')
        g4.pack(fill='x', padx=10, pady=4)

        self.conflict_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(g4, text='OFFER 전 ARP Probe (충돌 감지)',
                        variable=self.conflict_var).grid(
            row=0, column=0, columnspan=4, sticky='w', padx=8, pady=4)

        tk.Label(g4, text='정적 매핑 (MAC=IP, 줄 구분):').grid(
            row=1, column=0, sticky='nw', padx=8, pady=4)
        self.static_text = tk.Text(g4, width=50, height=3, font=('Courier', 9))
        self.static_text.grid(row=1, column=1, columnspan=5, padx=8, pady=4, sticky='w')
        self.static_text.insert('1.0', '# 예: aa:bb:cc:dd:ee:ff=192.168.0.50')

        # ── 제어 버튼 ──
        g5 = ttk.Frame(f)
        g5.pack(fill='x', padx=10, pady=8)

        self.start_btn = ttk.Button(g5, text='▶  서버 시작', command=self._start_server,
                                    width=16)
        self.start_btn.pack(side='left', padx=4)
        self.stop_btn = ttk.Button(g5, text='■  서버 중지', command=self._stop_server,
                                   width=16, state='disabled')
        self.stop_btn.pack(side='left', padx=4)

        tk.Label(g5, text=f'로그 파일: {self.LOG_PATH}', fg='gray50').pack(
            side='right', padx=12)

    def _build_lease_tab(self):
        f = self.tab_leases

        ctrl = ttk.Frame(f)
        ctrl.pack(fill='x', padx=8, pady=6)
        ttk.Button(ctrl, text='새로고침', command=self._refresh_leases).pack(side='left', padx=4)
        self.auto_refresh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctrl, text='자동 새로고침(5초)',
                        variable=self.auto_refresh_var).pack(side='left')

        cols = ('ip', 'mac', 'state', 'expires', 'remaining')
        self.lease_tree = ttk.Treeview(f, columns=cols, show='headings', height=20)
        headers = {
            'ip': ('IP 주소', 140),
            'mac': ('MAC 주소', 160),
            'state': ('상태', 100),
            'expires': ('만료 시각', 100),
            'remaining': ('남은 시간(초)', 110),
        }
        for col, (hdr, width) in headers.items():
            self.lease_tree.heading(col, text=hdr)
            self.lease_tree.column(col, width=width, anchor='center')

        sb = ttk.Scrollbar(f, orient='vertical', command=self.lease_tree.yview)
        self.lease_tree.configure(yscrollcommand=sb.set)
        self.lease_tree.pack(side='left', fill='both', expand=True, padx=(8, 0), pady=4)
        sb.pack(side='right', fill='y', pady=4, padx=(0, 8))

        # 색상 태그
        self.lease_tree.tag_configure('LEASED', foreground='#1a7a1a')
        self.lease_tree.tag_configure('OFFERED', foreground='#b07000')
        self.lease_tree.tag_configure('DECLINED', foreground='#cc0000')
        self.lease_tree.tag_configure('EXPIRED', foreground='gray60')

        self._schedule_lease_refresh()

    def _build_log_tab(self):
        f = self.tab_log

        ctrl = ttk.Frame(f)
        ctrl.pack(fill='x', padx=8, pady=4)
        ttk.Button(ctrl, text='로그 지우기', command=self._clear_log).pack(side='left', padx=4)
        ttk.Button(ctrl, text='파일 열기', command=self._open_log_file).pack(side='left', padx=4)

        self.log_area = scrolledtext.ScrolledText(
            f, font=('Courier', 9), state='disabled',
            wrap='word', height=28
        )
        self.log_area.pack(fill='both', expand=True, padx=8, pady=4)
        self.log_area.tag_config('WARNING', foreground='#cc7700')
        self.log_area.tag_config('ERROR', foreground='#cc0000')
        self.log_area.tag_config('INFO', foreground='#1a5c1a')
        self.log_area.tag_config('DEBUG', foreground='gray60')

    # ─── 서버 제어 ─────────────────────────────
    def _get_config(self) -> dict | None:
        try:
            lease_time = int(self.lease_var.get())
        except ValueError:
            messagebox.showerror('오류', '임대 시간은 숫자여야 합니다.')
            return None

        # 정적 매핑 파싱
        static_map = {}
        for line in self.static_text.get('1.0', 'end').splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                parts = line.split('=', 1)
                mac_s = parts[0].strip().lower()
                ip_s = parts[1].strip()
                static_map[mac_s] = ip_s

        dns_list = []
        for v in (self.dns1_var, self.dns2_var):
            d = v.get().strip()
            if d:
                dns_list.append(d)

        iface = self.iface_var.get() or '0.0.0.0'

        return {
            'iface': iface,
            'server_ip': self.server_ip_var.get().strip(),
            'pool_start': self.pool_start_var.get().strip(),
            'pool_end': self.pool_end_var.get().strip(),
            'subnet_mask': self.subnet_var.get().strip(),
            'broadcast': self.broadcast_var.get().strip(),
            'gateway': self.gw_var.get().strip(),
            'dns': dns_list,
            'lease_time': lease_time,
            'domain_name': self.domain_var.get().strip(),
            'static_map': static_map,
            'conflict_detect': self.conflict_var.get(),
        }

    def _start_server(self):
        cfg = self._get_config()
        if cfg is None:
            return
        if self.server and self.server._running:
            messagebox.showwarning('알림', '이미 서버가 실행 중입니다.')
            return
        self.db = LeaseDB()
        self.server = DHCPServer(cfg, self.logger, self.db,
                                 on_lease_change=self._schedule_lease_refresh_now)
        self.server.start()
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_var.set(
            f'▶ 실행 중  |  인터페이스: {cfg["iface"]}  |  '
            f'풀: {cfg["pool_start"]} ~ {cfg["pool_end"]}  |  '
            f'서버 IP: {cfg["server_ip"]}'
        )

    def _stop_server(self):
        if self.server:
            self.server.stop()
            self.server = None
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_var.set('■ 중지됨')

    def _load_iface_list(self):
        ifaces = get_interfaces()
        self.iface_cb['values'] = ifaces
        if ifaces:
            self.iface_cb.set(ifaces[0])
            # 인터페이스 IP 자동 채우기
            ip = get_iface_ip(ifaces[0])
            if ip and ip != '0.0.0.0':
                self.server_ip_var.set(ip)

    # ─── 임대 현황 ─────────────────────────────
    def _refresh_leases(self):
        leases = self.db.snapshot()
        for row in self.lease_tree.get_children():
            self.lease_tree.delete(row)
        for lease in sorted(leases, key=lambda l: ip_int(l.ip)):
            tag = lease.state
            self.lease_tree.insert('', 'end', values=(
                lease.ip,
                lease.mac,
                lease.state,
                lease.expire_str(),
                lease.remaining() if lease.state == LeaseState.LEASED else '-',
            ), tags=(tag,))

    def _schedule_lease_refresh(self):
        if self.auto_refresh_var.get():
            self._refresh_leases()
        self.root.after(5000, self._schedule_lease_refresh)

    def _schedule_lease_refresh_now(self):
        self.root.after(0, self._refresh_leases)

    # ─── 로그 ──────────────────────────────────
    def _on_log(self, level: str, line: str):
        def _append():
            self.log_area.config(state='normal')
            self.log_area.insert('end', line + '\n', level)
            self.log_area.see('end')
            self.log_area.config(state='disabled')
        self.root.after(0, _append)

    def _clear_log(self):
        self.log_area.config(state='normal')
        self.log_area.delete('1.0', 'end')
        self.log_area.config(state='disabled')

    def _open_log_file(self):
        try:
            if platform.system() == 'Windows':
                os.startfile(self.LOG_PATH)
            elif platform.system() == 'Darwin':
                subprocess.run(['open', self.LOG_PATH])
            else:
                subprocess.run(['xdg-open', self.LOG_PATH])
        except Exception as e:
            messagebox.showerror('오류', f'로그 파일을 열 수 없습니다: {e}')


# ──────────────────────────────────────────────
# 자동화 시나리오 엔진
# ──────────────────────────────────────────────

class ScenarioEvent:
    """시나리오 실행 중 발생한 이벤트 기록"""
    def __init__(self, ts: str, scenario: str, action: str, detail: str, result: str):
        self.ts = ts
        self.scenario = scenario
        self.action = action
        self.detail = detail
        self.result = result  # 'OK' / 'FAIL' / 'INFO'


class AutomationEngine:
    """
    시나리오 1: DHCP 정보 변경 (변경 → 주기 후 원복)
    시나리오 2: DHCP 정지/재시작 (Stop → 대기 → Start 반복)
    공통: 감시 MAC IP 재할당 확인, 결과 이벤트 기록
    """

    def __init__(self, app: 'DHCPDApp'):
        self.app = app
        self._thread: threading.Thread | None = None
        self._stop_evt = threading.Event()
        self.events: list[ScenarioEvent] = []
        self._lock = threading.Lock()

    # ── 공개 API ──────────────────────────────
    def start(self, plan: dict):
        """plan 딕셔너리에 따라 시나리오 실행 스레드 시작"""
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self.events.clear()
        self._thread = threading.Thread(target=self._run, args=(plan,), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_evt.set()

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # ── 내부 실행 ─────────────────────────────
    def _run(self, plan: dict):
        self._log('INFO', 'SYSTEM', '자동화 시작', f'모드={plan["mode"]}', 'INFO')
        try:
            mode = plan['mode']
            if mode == 'sc1':
                self._run_sc1(plan)
            elif mode == 'sc2':
                self._run_sc2(plan)
            elif mode == 'both':
                self._run_sc1(plan)
                if not self._stop_evt.is_set():
                    self._sleep(plan.get('between_sec', 5))
                if not self._stop_evt.is_set():
                    self._run_sc2(plan)
        except Exception as e:
            self._log('ERROR', 'SYSTEM', '예외 발생', str(e), 'FAIL')
        finally:
            self._log('INFO', 'SYSTEM', '자동화 종료', '', 'INFO')
            self.app.root.after(0, self.app._on_automation_done)

    # ── 시나리오 1: 정보 변경 ─────────────────
    def _run_sc1(self, plan: dict):
        """변경 설정 적용 → wait → 원복 → (반복 주기만큼 대기)"""
        original_cfg = copy.deepcopy(self.app.server.config) if self.app.server else None
        changed_cfg  = plan['sc1_cfg']
        change_sec   = plan['sc1_change_sec']    # 변경 시점까지 대기
        restore_sec  = plan['sc1_restore_sec']   # 원복까지 대기
        cycles       = plan.get('sc1_cycles', 1)
        watch_mac    = plan.get('watch_mac', '').strip().lower()

        for cycle in range(1, cycles + 1):
            if self._stop_evt.is_set():
                break
            self._log('INFO', 'SC1', f'사이클 {cycle}/{cycles}', '변경 대기 시작', 'INFO')

            # 변경 시점까지 대기
            self._sleep(change_sec)
            if self._stop_evt.is_set():
                break

            # 설정 변경 적용
            self._apply_config(changed_cfg, 'SC1', f'사이클{cycle} 설정 변경')

            # 감시 MAC IP 재할당 확인
            if watch_mac:
                self._sleep(3)
                self._check_mac_lease(watch_mac, 'SC1', f'사이클{cycle} 변경 후')

            # 원복 대기
            self._sleep(restore_sec)
            if self._stop_evt.is_set():
                break

            # 원복
            if original_cfg:
                self._apply_config(original_cfg, 'SC1', f'사이클{cycle} 원복')
                if watch_mac:
                    self._sleep(3)
                    self._check_mac_lease(watch_mac, 'SC1', f'사이클{cycle} 원복 후')

    # ── 시나리오 2: 정지/재시작 ───────────────
    def _run_sc2(self, plan: dict):
        """Stop → wait → Start 반복, 지속 시간 내"""
        stop_wait_sec  = plan['sc2_stop_sec']    # 정지 후 재시작까지 대기
        duration_sec   = plan['sc2_duration_sec'] # 전체 지속 시간
        watch_mac      = plan.get('watch_mac', '').strip().lower()

        deadline = time.time() + duration_sec
        cycle = 0

        while not self._stop_evt.is_set() and time.time() < deadline:
            cycle += 1
            remain = int(deadline - time.time())
            self._log('INFO', 'SC2', f'사이클 {cycle}',
                      f'서버 정지  (남은 시간 {remain}s)', 'INFO')

            # 서버 정지
            self.app.root.after(0, self.app._stop_server_silent)
            self._sleep(1)

            # 정지 중 감시 MAC 확인 (할당 불가 상태)
            if watch_mac:
                self._check_mac_lease(watch_mac, 'SC2', f'사이클{cycle} 정지 중', expect_fail=True)

            # 재시작까지 대기
            self._sleep(stop_wait_sec)
            if self._stop_evt.is_set() or time.time() >= deadline:
                break

            # 서버 재시작
            self._log('INFO', 'SC2', f'사이클 {cycle}', '서버 재시작', 'INFO')
            self.app.root.after(0, self.app._start_server_silent)
            self._sleep(3)  # 소켓 바인딩 안정화

            # 재시작 후 감시 MAC 확인
            if watch_mac:
                self._sleep(2)
                self._check_mac_lease(watch_mac, 'SC2', f'사이클{cycle} 재시작 후')

            # 다음 사이클까지 남은 시간 대기 (최소 5초)
            next_wait = max(5, min(30, int(deadline - time.time()) // 2))
            self._sleep(next_wait)

    # ── 헬퍼 ─────────────────────────────────
    def _apply_config(self, cfg: dict, scenario: str, label: str):
        """서버에 새 설정 적용 (재시작)"""
        def _do():
            try:
                if self.app.server and self.app.server._running:
                    self.app.server.stop()
                    time.sleep(0.5)
                self.app.server = DHCPServer(
                    cfg, self.app.logger, self.app.db,
                    on_lease_change=self.app._schedule_lease_refresh_now
                )
                self.app.server.start()
            except Exception as e:
                self._log('ERROR', scenario, label, str(e), 'FAIL')
                return
            self._log('INFO', scenario, label,
                      f'Pool={cfg.get("pool_start")}~{cfg.get("pool_end")}  '
                      f'GW={cfg.get("gateway")}  Lease={cfg.get("lease_time")}s', 'OK')
        self.app.root.after(0, _do)
        time.sleep(0.8)

    def _check_mac_lease(self, mac: str, scenario: str, label: str, expect_fail: bool = False):
        """감시 MAC의 IP 할당 여부 확인"""
        lease = self.app.db.get_by_mac(mac)
        if lease and lease.state == LeaseState.LEASED:
            result = 'FAIL' if expect_fail else 'OK'
            self._log('INFO', scenario, label,
                      f'MAC {mac} → IP {lease.ip} ({lease.state})', result)
        else:
            result = 'OK' if expect_fail else 'FAIL'
            self._log('INFO', scenario, label,
                      f'MAC {mac} → 미할당', result)

    def _sleep(self, sec: float):
        """stop 이벤트 감시하며 sleep"""
        step = 0.5
        elapsed = 0.0
        while elapsed < sec and not self._stop_evt.is_set():
            time.sleep(min(step, sec - elapsed))
            elapsed += step

    def _log(self, level: str, scenario: str, action: str, detail: str, result: str):
        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        evt = ScenarioEvent(ts, scenario, action, detail, result)
        with self._lock:
            self.events.append(evt)
        self.app.logger.info(f'[AUTO][{scenario}] {action} | {detail} | {result}')
        self.app.root.after(0, lambda e=evt: self.app._on_scenario_event(e))


# ──────────────────────────────────────────────
# PDF 리포트 생성
# ──────────────────────────────────────────────

def generate_pdf_report(events: list[ScenarioEvent], plan: dict, path: str) -> bool:
    """reportlab으로 시나리오 결과 PDF 생성"""
    if not REPORTLAB_OK:
        return False

    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('title', fontSize=18, spaceAfter=6,
                                  textColor=colors.HexColor('#1a1a2e'), fontName='Helvetica-Bold')
    head2_style = ParagraphStyle('h2', fontSize=13, spaceBefore=10, spaceAfter=4,
                                  textColor=colors.HexColor('#185FA5'), fontName='Helvetica-Bold')
    body_style  = ParagraphStyle('body', fontSize=9, leading=14, fontName='Helvetica')
    small_style = ParagraphStyle('small', fontSize=8, leading=12,
                                  textColor=colors.HexColor('#555555'), fontName='Helvetica')

    story = []

    # ── 제목 ──
    now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    story.append(Paragraph('DHCPD 자동화 시나리오 결과 리포트', title_style))
    story.append(Paragraph(f'생성 일시: {now_str}', small_style))
    story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#185FA5')))
    story.append(Spacer(1, 6*mm))

    # ── 시나리오 설정 요약 ──
    story.append(Paragraph('1. 시나리오 설정 요약', head2_style))
    mode_label = {'sc1': '시나리오 1 (정보 변경)', 'sc2': '시나리오 2 (정지/재시작)',
                  'both': '시나리오 1 → 2 순차 실행'}.get(plan.get('mode', ''), '-')
    summary_data = [
        ['항목', '값'],
        ['실행 모드', mode_label],
        ['감시 MAC', plan.get('watch_mac', '-') or '-'],
    ]
    if plan.get('mode') in ('sc1', 'both'):
        summary_data += [
            ['[SC1] 변경 대기 시간', f'{plan.get("sc1_change_sec", 0)}초'],
            ['[SC1] 원복 대기 시간', f'{plan.get("sc1_restore_sec", 0)}초'],
            ['[SC1] 반복 횟수', f'{plan.get("sc1_cycles", 1)}회'],
        ]
    if plan.get('mode') in ('sc2', 'both'):
        summary_data += [
            ['[SC2] 정지→재시작 대기', f'{plan.get("sc2_stop_sec", 0)}초'],
            ['[SC2] 전체 지속 시간', f'{plan.get("sc2_duration_sec", 0)}초'],
        ]

    tbl = Table(summary_data, colWidths=[60*mm, 110*mm])
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#185FA5')),
        ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#F5F5F5'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.4, colors.HexColor('#CCCCCC')),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 6*mm))

    # ── 이벤트 통계 ──
    story.append(Paragraph('2. 결과 통계', head2_style))
    total  = len(events)
    ok     = sum(1 for e in events if e.result == 'OK')
    fail   = sum(1 for e in events if e.result == 'FAIL')
    info   = sum(1 for e in events if e.result == 'INFO')
    rate   = f'{ok/total*100:.1f}%' if total else '-'

    stat_data = [
        ['전체 이벤트', 'OK', 'FAIL', 'INFO', '성공률'],
        [str(total), str(ok), str(fail), str(info), rate],
    ]
    stbl = Table(stat_data, colWidths=[34*mm]*5)
    stbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1D9E75')),
        ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 9),
        ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.4, colors.HexColor('#CCCCCC')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('BACKGROUND', (2,1), (2,1), colors.HexColor('#FFF0F0') if fail else colors.white),
    ]))
    story.append(stbl)
    story.append(Spacer(1, 6*mm))

    # ── 이벤트 상세 ──
    story.append(Paragraph('3. 이벤트 상세 로그', head2_style))
    ev_data = [['시각', '시나리오', '액션', '상세', '결과']]
    for e in events:
        color_map = {'OK': colors.HexColor('#1D9E75'),
                     'FAIL': colors.HexColor('#CC0000'),
                     'INFO': colors.HexColor('#888888')}
        ev_data.append([e.ts, e.scenario, e.action,
                        Paragraph(e.detail, small_style), e.result])

    etbl = Table(ev_data, colWidths=[32*mm, 16*mm, 28*mm, 72*mm, 14*mm])
    ev_style = [
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#444441')),
        ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#FAFAFA'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#DDDDDD')),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]
    # 결과 셀 색상
    for i, e in enumerate(events, start=1):
        if e.result == 'OK':
            ev_style.append(('TEXTCOLOR', (4,i), (4,i), colors.HexColor('#1D9E75')))
        elif e.result == 'FAIL':
            ev_style.append(('TEXTCOLOR', (4,i), (4,i), colors.HexColor('#CC0000')))

    etbl.setStyle(TableStyle(ev_style))
    story.append(etbl)

    doc.build(story)
    return True


# ──────────────────────────────────────────────
# 진입점
# ──────────────────────────────────────────────
def main():
    root = tk.Tk()
    try:
        root.tk.call('tk', 'scaling', 1.2)
    except Exception:
        pass
    app = DHCPDApp(root)

    def on_close():
        if app.server:
            app.server.stop()
        root.destroy()

    root.protocol('WM_DELETE_WINDOW', on_close)
    root.mainloop()


if __name__ == '__main__':
    if platform.system() == 'Windows':
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False
        if not is_admin:
            # UAC 관리자 권한 요청
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit()
    main()
