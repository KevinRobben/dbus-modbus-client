# vm3p75ct_emulator.py
import os, struct, socket, argparse, time
import dbus, dbus.mainloop.glib
from gi.repository import GLib

PRODUCT_ID = 0xA1B1
UDP_PORT = int(os.getenv('VM_UDP_PORT', '502'))  # change via env if needed

def pack_ver(maj=1, minv=8, beta=0xFF):
    # VEReg_ver encoding (4 bytes over 2 regs)
    return list(struct.unpack('>2H', struct.pack('4B', 0, maj, minv, beta)))

class VM3P75CT:
    def __init__(self, bus):
        self.bus = bus
        self.grid = os.getenv('VM_GRID_SVC', 'com.victronenergy.grid')
        # Optional: override data source by serial/VRM ID of an existing meter
        self.src_service = self._resolve_source_service()
        self._log_reads = os.getenv('VM_LOG_MB', '0') == '1'
        self._make_ctx()
        self._init_id_regs()
        self._init_mdns()
        self._start_udp()
        if os.getenv('VM_AUTOSAVE', '1') == '1':
            try:
                self._ensure_modbusclient_saved_device()
            except Exception as e:
                print('Warning: failed to save device in Modbus client settings:', e)

    def _make_ctx(self):
        # 0..0x4FFF addressable region is enough for our register set
        self.holding = [0] * 0x5000
        self.inputr = [0] * 0x5000
        # Local per-phase energy accumulators (kWh) as fallback when D-Bus lacks per-phase energy)
        self._kwh_fwd = {1: 0.0, 2: 0.0, 3: 0.0}
        self._kwh_rev = {1: 0.0, 2: 0.0, 3: 0.0}
        self._last_update = time.time()

    def _w16(self, addr, val):
        v = val & 0xFFFF
        self.holding[addr] = v
        if 0 <= addr < len(self.inputr):
            self.inputr[addr] = v
    def _w32b(self, addr, val):  # big-endian two regs
        val &= 0xFFFFFFFF
        self._w16(addr, (val >> 16) & 0xFFFF)
        self._w16(addr + 1, val & 0xFFFF)
    def _wtext(self, addr, text, words):
        b = text.encode('utf-8')[:2 * words]
        b = b + b'\0' * (2 * words - len(b))
        vals = list(struct.unpack('>%dH' % words, b))
        for i, v in enumerate(vals):
            self._w16(addr + i, v)

    def _rtext(self, addr, words):
        vals = self.holding[addr:addr + words]
        try:
            b = struct.pack('>%dH' % words, *vals)
            return b.rstrip(b'\0').decode('utf-8', errors='ignore')
        except Exception:
            return ''

    def _init_id_regs(self):
        self._w16(0x1000, PRODUCT_ID)
        ser = os.getenv('VM_SERIAL','HQ25043WWRJ')
        self._wtext(0x1001, ser, 8)
        v1, v2 = pack_ver(1, 10, 0xFF)
        self._w16(0x1009, v1)
        self._w16(0x1009 + 1, v2)
        self._w16(0x100B, 1)
        self._w16(0x2000, 3)  # 3-phase
        self._w16(0x2001, 0)  # role grid
        self._wtext(0x2002, os.getenv('VM_NAME','VM-3P75CT HQ25043WWRJ'), 32)
        self._w16(0x2022, 0)  # position
        self._w16(0x2023, 0)  # n2k instance
        # Capabilities: set HasUdpSnapshots bit (0x0400)
        self._w32b(0x2024, 0x0400)

    def _get(self, path):
        try:
            svc = self.src_service or self.grid
            obj = self.bus.get_object(svc, path)
            iface = dbus.Interface(obj, 'com.victronenergy.BusItem')
            val = iface.GetValue()
            try:
                return float(val)
            except Exception:
                return None
        except Exception:
            return None

    # ------------------- Source service resolution -------------------
    def _resolve_source_service(self):
        wanted_serial = os.getenv('VM_SRC_SERIAL') or os.getenv('RED_SERIAL')
        if not wanted_serial:
            return None

        try:
            names = self.bus.list_names()
        except Exception:
            return None

        pref = 'com.victronenergy.grid'
        candidates = [n for n in names if n.startswith(pref)]

        for name in sorted(candidates):
            try:
                obj = self.bus.get_object(name, '/Serial')
                iface = dbus.Interface(obj, 'com.victronenergy.BusItem')
                serial = iface.GetValue()
                serial = str(serial)
            except Exception:
                continue

            if serial == wanted_serial:
                print('Using source service', name, 'for serial', wanted_serial)
                return name

        print('Warning: source serial', wanted_serial, 'not found; using', self.grid)
        return None

    def _update_phase(self, n, dt_s):
        base = 0x3040 + 8*(n-1)
        pwr = 0x3082 + 4*(n-1)
        voltage = self._get(f'/Ac/L{n}/Voltage') or 0.0
        current = self._get(f'/Ac/L{n}/Current') or 0.0
        power = self._get(f'/Ac/L{n}/Power') or 0.0
        self._w16(base + 0, int(round(voltage * 100)))
        self._w16(base + 1, int(round(current * 100)))
        self._w32b(pwr, int(round(power)))
        # Per-phase power factor (s16, scale 1000)
        try:
            apparent = abs(voltage) * abs(current)
            pf = power / apparent if apparent > 1e-3 else 1.0
        except Exception:
            pf = 1.0
        # Clamp to [-1, 1]
        if pf > 1.0:
            pf = 1.0
        if pf < -1.0:
            pf = -1.0
        self._w16(base + 7, int(round(pf * 1000)))
        # Per-phase energy forward/reverse
        e_fwd = self._get(f'/Ac/L{n}/Energy/Forward')
        e_rev = self._get(f'/Ac/L{n}/Energy/Reverse')
        if e_fwd is None and e_rev is None and dt_s is not None and dt_s > 0:
            # Integrate from power; assume positive = import (forward), negative = export (reverse)
            if power >= 0:
                self._kwh_fwd[n] += (power * dt_s) / 3600000.0
            else:
                self._kwh_rev[n] += ((-power) * dt_s) / 3600000.0
        else:
            if e_fwd is not None:
                self._kwh_fwd[n] = e_fwd
            if e_rev is not None:
                self._kwh_rev[n] = e_rev

        self._w32b(base + 2, int(round(self._kwh_fwd[n] * 100)))
        self._w32b(base + 4, int(round(self._kwh_rev[n] * 100)))
        # Optional L-L voltage if 3-phase
        if (self.holding[0x2000] == 3) and voltage:
            ll = int(round(voltage * 1.732 * 100))
            self._w16(base + 6, ll)

    def _update_totals(self):
        f = self._get('/Ac/Frequency') or 50.0
        p = self._get('/Ac/Power') or 0.0
        self._w16(0x3032, int(round(f*100)))
        self._w32b(0x3080, int(round(p)))
        # energy counters: optional if available
        fwd = self._get('/Ac/Energy/Forward')
        rev = self._get('/Ac/Energy/Reverse')
        if fwd is not None:
            self._w32b(0x3034, int(round(fwd * 100)))
        else:
            # Sum per-phase as fallback
            total_fwd = self._kwh_fwd[1] + self._kwh_fwd[2] + self._kwh_fwd[3]
            self._w32b(0x3034, int(round(total_fwd * 100)))
        if rev is not None:
            self._w32b(0x3036, int(round(rev * 100)))
        else:
            total_rev = self._kwh_rev[1] + self._kwh_rev[2] + self._kwh_rev[3]
            self._w32b(0x3036, int(round(total_rev * 100)))
        self._w16(0x3038, 0)
        # optional extra fields for newer FW behavior
        self._w16(0x3039, 0)                 # /Ac/N/Current
        # Total power factor: P_total / sum(|V_i|*|I_i|)
        try:
            v1 = self.holding[0x3040] / 100.0
            i1 = self.holding[0x3041] / 100.0
            v2 = self.holding[0x3048] / 100.0
            i2 = self.holding[0x3049] / 100.0
            v3 = self.holding[0x3050] / 100.0
            i3 = self.holding[0x3051] / 100.0
            s_sum = abs(v1*i1) + abs(v2*i2) + abs(v3*i3)
            pf_tot = p / s_sum if s_sum > 1e-3 else 1.0
        except Exception:
            pf_tot = 1.0
        if pf_tot > 1.0:
            pf_tot = 1.0
        if pf_tot < -1.0:
            pf_tot = -1.0
        self._w16(0x303a, int(round(pf_tot * 1000)))
        self._w16(0x303b, 0)                 # /PhaseSequence -> 'L1-L2-L3'
        self._w32b(0x303C, 0)                # alarms bitfield

    def loop_update(self):
        now = time.time()
        dt_s = now - self._last_update if self._last_update else None
        self._last_update = now
        self._update_totals()
        for n in (1, 2, 3):
            self._update_phase(n, dt_s)

    def _init_mdns(self):
        # Advertise service via Avahi over D-Bus (preinstalled on Venus OS)
        try:
            bus = dbus.SystemBus()
            server = dbus.Interface(bus.get_object('org.freedesktop.Avahi', '/'),
                                    'org.freedesktop.Avahi.Server')
            group_path = server.EntryGroupNew()
            group = dbus.Interface(bus.get_object('org.freedesktop.Avahi', group_path),
                                   'org.freedesktop.Avahi.EntryGroup')

            AVAHI_IF_UNSPEC = dbus.Int32(-1)
            AVAHI_PROTO_UNSPEC = dbus.Int32(-1)
            flags = dbus.UInt32(0)
            name = f"VM-3P75CT@{socket.gethostname()}"
            stype = '_victron-energy-meter._udp'
            domain = ''
            host = ''
            port = dbus.UInt16(UDP_PORT)
            txt = []

            group.AddService(AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, flags,
                              name, stype, domain, host, port, txt)
            group.Commit()
            self._avahi_group = group
        except Exception as e:
            print('Avahi mDNS registration failed:', e)

    def _get_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return ip

    # ------------------- Minimal Modbus-UDP server -------------------
    def _start_udp(self):
        import threading
        self._running = True
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._udp.bind(("0.0.0.0", UDP_PORT))
        except Exception as e:
            print('Failed to bind UDP port', UDP_PORT, e)
            raise
        t = threading.Thread(target=self._udp_loop, daemon=True)
        t.start()

    def _udp_loop(self):
        while self._running:
            try:
                data, addr = self._udp.recvfrom(2048)
                resp = self._handle_mbap(data)
                if resp:
                    self._udp.sendto(resp, addr)
            except Exception:
                if not self._running:
                    break
                continue

    def _handle_mbap(self, pkt):
        if len(pkt) < 8:
            return None
        # MBAP: 0-1 TID, 2-3 PID, 4-5 LEN, 6 UID, then PDU
        tid = pkt[0:2]
        pid = pkt[2:4]
        # length = pkt[4:6]  # not used
        uid = pkt[6:7]
        pdu = pkt[7:]
        if pid != b"\x00\x00" or len(pdu) < 5:
            return None
        func = pdu[0]
        if func in (3, 4):
            start = (pdu[1] << 8) | pdu[2]
            qty = (pdu[3] << 8) | pdu[4]
            if self._log_reads and start != 0x3080:
                print('Modbus-UDP read func=%d start=%#04x qty=%d' % (func, start, qty))
            # Serve same values for holding (3) and input (4) reads
            regs = self.holding
            if start + qty > len(regs):
                # exception: illegal data address (0x02)
                epdu = bytes([func | 0x80, 0x02])
                elen = (1 + len(epdu)).to_bytes(2, 'big')
                return tid + pid + elen + uid + epdu
            values = regs[start:start+qty]
            bytecount = len(values) * 2
            rpdu = bytes([func, bytecount]) + b"".join(v.to_bytes(2, 'big') for v in values)
            rlen = (1 + len(rpdu)).to_bytes(2, 'big')
            return tid + pid + rlen + uid + rpdu
        elif func == 0x17:  # Read/Write Multiple Registers (VregLink)
            if len(pdu) < 11:
                epdu = bytes([func | 0x80, 0x03])
                elen = (1 + len(epdu)).to_bytes(2, 'big')
                return tid + pid + elen + uid + epdu
            raddr = (pdu[1] << 8) | pdu[2]
            rqty  = (pdu[3] << 8) | pdu[4]
            waddr = (pdu[5] << 8) | pdu[6]
            wqty  = (pdu[7] << 8) | pdu[8]
            wbc   = pdu[9]
            wdata = pdu[10:10 + wbc]

            if self._log_reads:
                print('Modbus-UDP fc=23 raddr=%#04x rqty=%d waddr=%#04x wqty=%d wbc=%d' % (raddr, rqty, waddr, wqty, wbc))

            if raddr != 0x4000 or waddr != 0x4000:
                epdu = bytes([func | 0x80, 0x02])
                elen = (1 + len(epdu)).to_bytes(2, 'big')
                return tid + pid + elen + uid + epdu

            # Parse write payload into 16-bit words
            wwords = []
            for i in range(0, len(wdata), 2):
                if i + 1 >= len(wdata):
                    word = wdata[i] << 8
                else:
                    word = (wdata[i] << 8) | wdata[i + 1]
                wwords.append(word)

            if self._log_reads:
                if wwords:
                    op = 'SET' if len(wwords) >= 2 else 'GET'
                    print('  VregLink %s reg=0x%04x' % (op, wwords[0]))

            # Handle VregLink logic
            out_words = self._vreglink_handle(wwords, rqty)

            # Build response: func, bytecount, data
            bytecount = 2 * len(out_words)
            rpdu = bytes([func, bytecount]) + b"".join(w.to_bytes(2, 'big') for w in out_words)
            rlen = (1 + len(rpdu)).to_bytes(2, 'big')
            return tid + pid + rlen + uid + rpdu
        elif func == 6 and len(pdu) >= 5:
            # Write single register
            addr = (pdu[1] << 8) | pdu[2]
            val = (pdu[3] << 8) | pdu[4]
            if addr < len(self.holding):
                self._w16(addr, val)
                # echo request as response per Modbus spec
                rlen = (1 + len(pdu)).to_bytes(2, 'big')
                return tid + pid + rlen + uid + pdu
            epdu = bytes([func | 0x80, 0x02])
            elen = (1 + len(epdu)).to_bytes(2, 'big')
            return tid + pid + elen + uid + epdu
        elif func == 16 and len(pdu) >= 6:
            # Write multiple registers
            addr = (pdu[1] << 8) | pdu[2]
            qty = (pdu[3] << 8) | pdu[4]
            bytecount = pdu[5]
            if bytecount != qty * 2 or len(pdu) < 6 + bytecount:
                epdu = bytes([func | 0x80, 0x03])  # illegal data value
                elen = (1 + len(epdu)).to_bytes(2, 'big')
                return tid + pid + elen + uid + epdu
            if addr + qty > len(self.holding):
                epdu = bytes([func | 0x80, 0x02])  # illegal address
                elen = (1 + len(epdu)).to_bytes(2, 'big')
                return tid + pid + elen + uid + epdu
            data = pdu[6:6+bytecount]
            for i in range(qty):
                word = (data[2*i] << 8) | data[2*i + 1]
                self._w16(addr + i, word)
            # normal response: echo start and qty
            rpdu = bytes([func, pdu[1], pdu[2], pdu[3], pdu[4]])
            rlen = (1 + len(rpdu)).to_bytes(2, 'big')
            return tid + pid + rlen + uid + rpdu
        # unsupported function: respond with ILLEGAL FUNCTION (0x01)
        epdu = bytes([func | 0x80, 0x01])
        elen = (1 + len(epdu)).to_bytes(2, 'big')
        return tid + pid + elen + uid + epdu

    # ------------------- Modbus client persistence via D-Bus settings -------------------
    def _ensure_modbusclient_saved_device(self):
        svc = 'com.victronenergy.settings'
        path = '/Settings/ModbusClient/tcp/Devices'
        try:
            obj = self.bus.get_object(svc, path)
        except Exception as e:
            print('Settings service not available:', e)
            return

        iface = dbus.Interface(obj, 'com.victronenergy.BusItem')
        try:
            cur = str(iface.GetValue())
        except Exception:
            cur = ''

        entry = 'udp:%s:%d:1' % (self._get_ip(), UDP_PORT)
        items = [s for s in (cur.split(',') if cur else []) if s]
        if entry not in items:
            items.append(entry)
            newval = ','.join(sorted(set(items)))
            try:
                iface.SetValue(dbus.String(newval))
                print('Added to Modbus client device list:', entry)
            except Exception as e:
                print('Failed to update Modbus client device list:', e)

    def stop(self):
        # Stop UDP server
        try:
            self._running = False
        except Exception:
            pass

    # ------------------- VregLink emulation -------------------
    def _vreglink_handle(self, wwords, rqty):
        # Expected formats:
        # GET:  wwords = [regid]
        # SET:  wwords = [regid, dlen_bytes, data_words...]
        def pack_bytes_to_words(b):
            if len(b) & 1:
                b = b + b'\0'
            words = list(struct.unpack('>%dH' % (len(b) // 2), b))
            return words

        def trim_to(out, n):
            if len(out) < n:
                out += [0] * (n - len(out))
            elif len(out) > n:
                out = out[:n]
            return out

        # Defaults for unknown regids
        regid = wwords[0] if wwords else 0
        is_set = len(wwords) >= 2
        status = 0x8001
        data_bytes = b''

        if regid == 0x10C:  # CustomName (text)
            if is_set:
                dlen = wwords[1] & 0xFFFF
                # Convert remaining words to bytes
                payload = struct.pack('>%dH' % max(0, len(wwords) - 2), *wwords[2:]) if len(wwords) > 2 else b''
                payload = payload[:dlen]
                try:
                    name = payload.decode('utf-8', errors='ignore')
                except Exception:
                    name = ''
                self._wtext(0x2002, name, 32)
                data_bytes = b''
                status = 0x0000
            else:
                name = self._rtext(0x2002, 32)
                data_bytes = name.encode('utf-8')
                status = 0x0000
        elif regid == 0x010A:  # Serial (text)
            # Return serial as ASCII bytes
            ser = self._rtext(0x1001, 8)
            data_bytes = ser.encode('utf-8')
            status = 0x0000
        elif regid == 0x0101:  # Role via Vreg (bridge to 0x2001) [byte]
            if is_set:
                dlen = wwords[1] & 0xFF
                if dlen >= 1 and len(wwords) >= 3:
                    payload = struct.pack('>%dH' % (len(wwords) - 2), *wwords[2:])
                    val = payload[0]
                    self._w16(0x2001, val)
                data_bytes = b''
                status = 0x0000
            else:
                val = self.holding[0x2001] & 0xFF
                data_bytes = bytes([val])
                status = 0x0000
        elif regid == 0x3001:  # Role code (byte); SET also observed
            if is_set:
                dlen = wwords[1] & 0xFF
                if dlen >= 1 and len(wwords) >= 3:
                    payload = struct.pack('>%dH' % (len(wwords) - 2), *wwords[2:])
                    val = payload[0]
                    self._w16(0x2001, val)
                data_bytes = b''
                status = 0x0000
            else:
                val = self.holding[0x2001] & 0xFF
                data_bytes = bytes([val])
                status = 0x0000
        elif regid == 0x112:  # N2kSystemInstance (byte)
            if is_set:
                dlen = wwords[1] & 0xFF
                if dlen >= 1 and len(wwords) >= 3:
                    payload = struct.pack('>%dH' % (len(wwords) - 2), *wwords[2:])
                    val = payload[0]
                    self._w16(0x2023, val)
                data_bytes = b''
                status = 0x0000
            else:
                val = self.holding[0x2023] & 0xFF
                data_bytes = bytes([val])
                status = 0x0000
        elif regid == 0x3000:  # Small code (observed size 1)
            data_bytes = b"\x03"
            status = 0x0000
        elif regid == 0x3004:  # Small code (observed size 1 -> 0x00)
            data_bytes = b"\x00"
            status = 0x0000
        elif regid == 0x3005:  # Small code (observed size 1 -> 0x01)
            data_bytes = b"\x01"
            status = 0x0000
        elif regid == 0x3006 or regid == 0x300a or regid == 0x300b or regid == 0x3007 or regid == 0x3009:
            status = 0x8001
            data_bytes = b''
        elif regid == 0x0181:  # 4-byte marker
            data_bytes = b"\xff\x04\x01\xfe"
            status = 0x0000
        elif regid == 0x0102:  # 4-byte descriptor
            data_bytes = b"\x00\xff\x06\x01"
            status = 0x0000
        elif regid == 0x0110:  # 4-byte marker
            data_bytes = b"\xff\x04\x01\xfe"
            status = 0x0000
        elif regid == 0x010D:  # returns OK with size 0
            data_bytes = b''
            status = 0x0000
        # -------- Vreg 0x11xx block (observed on real meter) --------
        elif regid == 0x1100:
            data_bytes = b"\x01"
            status = 0x0000
        elif regid == 0x1101:
            data_bytes = bytes.fromhex('36 b2 a8 c0')
            status = 0x0000
        elif regid == 0x1102:
            data_bytes = bytes.fromhex('00 ff ff ff')
            status = 0x0000
        elif regid == 0x1103:
            data_bytes = bytes.fromhex('01 b2 a8 c0')
            status = 0x0000
        elif regid == 0x1105:
            data_bytes = b"\x00"
            status = 0x0000
        elif regid == 0x1106:
            data_bytes = b"\x02"
            status = 0x0000
        elif regid == 0x1104:
            data_bytes = bytes.fromhex('c0 61 9a b9 01 54')
            status = 0x0000
        # -------- Vreg 0x22xx/0x21xx small integers (subset) --------
        elif regid == 0x2234:
            data_bytes = bytes.fromhex('41 00 00 00')
            status = 0x0000
        elif regid == 0x225c:
            data_bytes = bytes.fromhex('20 00 00 00')
            status = 0x0000
        elif regid == 0x225a:
            data_bytes = bytes.fromhex('35 5b')
            status = 0x0000
        elif regid == 0x225b:
            data_bytes = bytes.fromhex('24 00')
            status = 0x0000
        elif regid == 0x2278 or regid == 0x227e or regid == 0x2277 or regid == 0x227d or regid == 0x2276 or regid == 0x227c:
            status = 0x8001
            data_bytes = b''
        elif regid == 0x2196:
            data_bytes = bytes.fromhex('00 00 00 00')
            status = 0x0000
        elif regid == 0x2197:
            data_bytes = bytes.fromhex('fb 16 00 00')
            status = 0x0000
        elif regid == 0x2194:
            data_bytes = bytes.fromhex('00 00 00 00')
            status = 0x0000
        elif regid == 0x2195:
            data_bytes = bytes.fromhex('6c 28 00 00')
            status = 0x0000
        elif regid == 0x2192:
            data_bytes = bytes.fromhex('3f 29 00 00')
            status = 0x0000
        elif regid == 0x2193:
            data_bytes = bytes.fromhex('b0 02 00 00')
            status = 0x0000
        elif regid == 0x2238:
            data_bytes = bytes.fromhex('8d 13')
            status = 0x0000
        elif regid == 0x2209:
            data_bytes = bytes.fromhex('0b 00')
            status = 0x0000
        elif regid == 0x2190:
            data_bytes = bytes.fromhex('8f 06 00 00')
            status = 0x0000
        elif regid == 0x2191:
            data_bytes = bytes.fromhex('69 1f 00 00')
            status = 0x0000
        elif regid == 0x2250:
            data_bytes = bytes.fromhex('35 5b')
            status = 0x0000
        elif regid == 0x2251:
            data_bytes = bytes.fromhex('d8 ff')
            status = 0x0000
        # -------- Misc observed --------
        elif regid == 0xedda:
            data_bytes = b"\x00"
            status = 0x0000
        elif regid in (0xec7f, 0xec11, 0xec0f, 0xec0e, 0xec7d, 0xec10, 0xec3f, 0xec12):
            status = 0x8001
            data_bytes = b''
        else:
            # Unknown regid: respond unsupported
            status = 0x8001
            data_bytes = b''

        # Build response words: [regid, status, size_bytes, data_words...]
        data_words = pack_bytes_to_words(data_bytes)
        size = len(data_bytes) & 0xFFFF
        out = [regid & 0xFFFF, status & 0xFFFF, size] + data_words
        return trim_to(out, rqty)
        try:
            if hasattr(self, '_udp'):
                self._udp.close()
        except Exception:
            pass
        # Unregister Avahi service
        try:
            if hasattr(self, '_avahi_group'):
                try:
                    self._avahi_group.Reset()
                except Exception:
                    pass
                try:
                    self._avahi_group.Free()
                except Exception:
                    pass
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description='VM-3P75CT emulator bridging from an existing grid meter')
    parser.add_argument('-s', '--serial', help='Source meter serial/VRM ID to mirror (e.g. HQ25043WWRJ)')
    args, unknown = parser.parse_known_args()

    if args.serial:
        os.environ['VM_SRC_SERIAL'] = args.serial

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus() if os.getenv('DBUS_SESSION') else dbus.SystemBus()
    vm = VM3P75CT(bus)

    def updater():
        vm.loop_update()
        return True

    GLib.timeout_add(500, updater)  # 2 Hz

    loop = GLib.MainLoop()

    # Graceful exit on SIGINT/SIGTERM and on keypress (Enter)
    import signal, threading, sys

    def shutdown(*_):
        try:
            vm.stop()
        finally:
            try:
                loop.quit()
            except Exception:
                pass

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    def key_listener():
        try:
            sys.stdin.read(1)
        except Exception:
            pass
        shutdown()

    try:
        t = threading.Thread(target=key_listener, daemon=True)
        t.start()
    except Exception:
        pass

    loop.run()

if __name__ == '__main__':
    main()