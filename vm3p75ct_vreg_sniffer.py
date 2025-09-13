#!/usr/bin/env python3

import argparse
import ipaddress
import socket
import struct
import sys
import time


ETH_P_ALL = 0x0003
ETH_HDR_LEN = 14


def process_modbus_payload(payload, logfc3=False, is_response=False):
    # Returns a printable string or None
    if len(payload) < 8:
        return None
    func = payload[7]
    if func == 0x17:
        ts = time.strftime('%H:%M:%S')
        if not is_response:
            if len(payload) < 17:
                return None
            raddr = struct.unpack('!H', payload[8:10])[0]
            rqty = struct.unpack('!H', payload[10:12])[0]
            waddr = struct.unpack('!H', payload[12:14])[0]
            wqty = struct.unpack('!H', payload[14:16])[0]
            wbc = payload[16]
            if len(payload) < 17 + wbc:
                return None
            wdata = payload[17:17 + wbc]
            wwords = []
            for i in range(0, len(wdata), 2):
                word = (wdata[i] << 8) | (wdata[i + 1] if i + 1 < len(wdata) else 0)
                wwords.append(word)
            op = 'SET' if len(wwords) >= 2 else 'GET'
            regid = wwords[0] if wwords else None
            if regid is not None:
                return ('%s VREGLINK %s reg=0x%04x raddr=%#04x rqty=%d waddr=%#04x wqty=%d bc=%d' %
                        (ts, op, regid, raddr, rqty, waddr, wqty, wbc))
            return ('%s VREGLINK %s raddr=%#04x rqty=%d waddr=%#04x wqty=%d bc=%d' %
                    (ts, op, raddr, rqty, waddr, wqty, wbc))
        else:
            # Response: payload[8] = bytecount, then read data (words)
            if len(payload) < 9:
                return None
            bc = payload[8]
            if len(payload) < 9 + bc:
                return None
            rdata = payload[9:9 + bc]
            words = []
            for i in range(0, len(rdata), 2):
                word = (rdata[i] << 8) | (rdata[i + 1] if i + 1 < len(rdata) else 0)
                words.append(word)
            regid = words[0] if len(words) >= 1 else None
            status = words[1] if len(words) >= 2 else None
            size = words[2] if len(words) >= 3 else 0
            data_bytes = b''
            if len(words) > 3:
                # Rebuild bytes from remaining words
                body = b''.join(((w >> 8) & 0xFF).to_bytes(1, 'big') + (w & 0xFF).to_bytes(1, 'big') for w in words[3:])
                data_bytes = body[:size]
            # Render small payload preview
            preview = data_bytes[:32]
            try:
                ascii_preview = preview.decode('utf-8', errors='ignore')
            except Exception:
                ascii_preview = ''
            hex_preview = ' '.join(f'{b:02x}' for b in preview)
            return ('%s VREGLINK RESP reg=%s status=%s size=%d data_bytes=%d data[hex]=%s data[utf8]=%r' %
                    (ts,
                     ('0x%04x' % regid) if regid is not None else 'n/a',
                     ('0x%04x' % status) if status is not None else 'n/a',
                     size,
                     len(rdata),
                     hex_preview,
                     ascii_preview))
    elif logfc3 and func in (3, 4):
        if len(payload) >= 12:
            start = struct.unpack('!H', payload[8:10])[0]
            qty = struct.unpack('!H', payload[10:12])[0]
            if start != 0x3080:
                ts = time.strftime('%H:%M:%S')
                return ('%s READ fc=%d start=%#04x qty=%d' % (ts, func, start, qty))
    return None


def parse_ipv4_header(buf, offset):
    if len(buf) < offset + 20:
        return None
    vihl = buf[offset]
    version = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    if version != 4 or len(buf) < offset + ihl:
        return None
    proto = buf[offset + 9]
    src = socket.inet_ntoa(buf[offset + 12: offset + 16])
    dst = socket.inet_ntoa(buf[offset + 16: offset + 20])
    total_len = struct.unpack('!H', buf[offset + 2: offset + 4])[0]
    return {
        'ihl': ihl,
        'proto': proto,
        'src': src,
        'dst': dst,
        'total_len': total_len,
    }


def parse_udp_header(buf, offset):
    if len(buf) < offset + 8:
        return None
    sport, dport, length, checksum = struct.unpack('!HHHH', buf[offset:offset + 8])
    return {'sport': sport, 'dport': dport, 'length': length}


def hexdump(b):
    return ' '.join(f'{x:02x}' for x in b)


def main():
    parser = argparse.ArgumentParser(description='Passive Modbus-UDP VregLink sniffer (no proxy)')
    parser.add_argument('--iface', default='auto', help='Network interface (default: auto-detect route to meter)')
    parser.add_argument('--meter', required=True, help='Target meter IP to filter on')
    parser.add_argument('--logfc3', action='store_true', help='Also log function 3 reads')
    parser.add_argument('--pcap', help='Offline pcap file to read instead of live sniffing')
    args = parser.parse_args()

    try:
        meter_ip = str(ipaddress.ip_address(args.meter))
    except Exception:
        print('Invalid meter IP:', args.meter, file=sys.stderr)
        sys.exit(1)

    # Offline pcap path using scapy (if available)
    if args.pcap:
        try:
            from scapy.all import rdpcap, TCP, UDP, IP  # type: ignore
        except Exception:
            print('Scapy is required for --pcap mode. Install with: pip install scapy', file=sys.stderr)
            sys.exit(1)

        try:
            packets = rdpcap(args.pcap)
        except Exception as e:
            print('Failed to read pcap:', e, file=sys.stderr)
            sys.exit(1)

        for pkt in packets:
            if IP in pkt and (pkt[IP].src == meter_ip or pkt[IP].dst == meter_ip):
                payload = b''
                if UDP in pkt and (pkt[UDP].sport == 502 or pkt[UDP].dport == 502):
                    payload = bytes(pkt[UDP].payload)
                elif TCP in pkt and (pkt[TCP].sport == 502 or pkt[TCP].dport == 502):
                    payload = bytes(pkt[TCP].payload)
                if not payload:
                    continue
                is_resp = (iphdr['src'] == meter_ip)
                line = process_modbus_payload(payload, logfc3=args.logfc3, is_response=is_resp)
                if line:
                    print(line)
        return

    # Live sniff: try raw socket on Linux, else fallback to scapy if available
    iface = args.iface
    use_raw = hasattr(socket, 'AF_PACKET') and iface != 'pcap'
    if use_raw and iface == 'auto':
        try:
            import subprocess
            import re
            out = subprocess.check_output(['ip', 'route', 'get', meter_ip], text=True)
            m = re.search(r' dev\s+(\S+)', out)
            if m:
                iface = m.group(1)
            else:
                raise RuntimeError('could not parse route output')
        except Exception as e:
            print('Auto-detect interface failed:', e, file=sys.stderr)
            cmd = "ip -o link show | awk -F': ' '{print $2}'"
            print('List interfaces with:', cmd, file=sys.stderr)
            sys.exit(1)

    if use_raw:
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            s.bind((iface, 0))
        except PermissionError:
            print('Root privileges are required to sniff packets.', file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print('Failed to open raw socket on', iface, e, file=sys.stderr)
            sys.exit(1)

        print('Sniffing on %s for UDP/TCP port 502 to/from %s (Ctrl-C to stop)...' % (iface, meter_ip))
        try:
            while True:
                pkt = s.recv(65535)
                if len(pkt) < ETH_HDR_LEN + 20:
                    continue
                eth_type = struct.unpack('!H', pkt[12:14])[0]
                if eth_type != 0x0800:  # IPv4
                    continue
                iphdr = parse_ipv4_header(pkt, ETH_HDR_LEN)
                if not iphdr:
                    continue
                if iphdr['src'] != meter_ip and iphdr['dst'] != meter_ip:
                    continue

                l4off = ETH_HDR_LEN + iphdr['ihl']
                payload = b''
                if iphdr['proto'] == 17:  # UDP
                    udph = parse_udp_header(pkt, l4off)
                    if not udph:
                        continue
                    if udph['sport'] != 502 and udph['dport'] != 502:
                        continue
                    payload = pkt[l4off + 8:]
                elif iphdr['proto'] == 6:  # TCP
                    if len(pkt) < l4off + 20:
                        continue
                    sport, dport = struct.unpack('!HH', pkt[l4off:l4off + 4])
                    if sport != 502 and dport != 502:
                        continue
                    doff = (pkt[l4off + 12] >> 4) * 4
                    if len(pkt) < l4off + doff:
                        continue
                    payload = pkt[l4off + doff:]
                else:
                    continue

                is_resp = (iphdr['src'] == meter_ip)
                line = process_modbus_payload(payload, logfc3=args.logfc3, is_response=is_resp)
                if line:
                    print(line)
        except KeyboardInterrupt:
            pass
        return

    # Fallback to Scapy live sniff (cross-platform if Npcap/libpcap available)
    try:
        from scapy.all import sniff, TCP, UDP, IP  # type: ignore
    except Exception:
        print('Raw sniffing unavailable and scapy not installed. Install scapy or run on Linux as root.', file=sys.stderr)
        sys.exit(1)

    bpf = f'host {meter_ip} and port 502'
    iface_arg = None if args.iface == 'auto' else args.iface
    print('Sniffing (pcap) on %s with filter "%s" (Ctrl-C to stop)...' % (iface_arg or 'all interfaces', bpf))

    def on_pkt(pkt):
        try:
            if IP in pkt and (pkt[IP].src == meter_ip or pkt[IP].dst == meter_ip):
                payload = b''
                if UDP in pkt and (pkt[UDP].sport == 502 or pkt[UDP].dport == 502):
                    payload = bytes(pkt[UDP].payload)
                elif TCP in pkt and (pkt[TCP].sport == 502 or pkt[TCP].dport == 502):
                    payload = bytes(pkt[TCP].payload)
                if not payload:
                    return
                is_resp = (pkt[IP].src == meter_ip)
                line = process_modbus_payload(payload, logfc3=args.logfc3, is_response=is_resp)
                if line:
                    print(line)
        except Exception:
            pass

    try:
        sniff(filter=bpf, prn=on_pkt, iface=iface_arg, store=False)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()


