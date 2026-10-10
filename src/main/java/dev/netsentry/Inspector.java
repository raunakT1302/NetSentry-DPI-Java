package dev.netsentry;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Bounds-checked Ethernet/IPv4/TCP/UDP parser plus best-effort HTTP Host and TLS SNI inspection. */
final class Inspector {
    PacketInfo inspect(byte[] b) {
        PacketInfo p = new PacketInfo();
        if (b.length < 14) return p;
        int etherType = PcapFile.u16(b, 12);
        int off = 14;
        // Support one 802.1Q VLAN tag.
        if (etherType == 0x8100 && b.length >= 18) { etherType = PcapFile.u16(b, 16); off = 18; }
        if (etherType != 0x0800 || b.length < off + 20) return p; // IPv4 only
        int version = (b[off] >>> 4) & 15, ihl = (b[off] & 15) * 4;
        if (version != 4 || ihl < 20 || b.length < off + ihl) return p;
        p.ipv4 = true; p.ipOffset = off;
        p.srcIp = ip(b, off+12); p.dstIp = ip(b, off+16);
        int proto = b[off+9] & 255;
        int totalLength = PcapFile.u16(b, off+2);
        int end = Math.min(b.length, off + Math.max(ihl, totalLength));
        int t = off + ihl; p.transportOffset = t;
        if (proto == 6) {
            p.protocol = "TCP";
            if (t + 20 > end) return p;
            p.srcPort = PcapFile.u16(b,t); p.dstPort = PcapFile.u16(b,t+2);
            int dataOffset = ((b[t+12] >>> 4)&15)*4;
            if (dataOffset < 20 || t + dataOffset > end) return p;
            p.payloadOffset = t+dataOffset; p.payloadLength = end-p.payloadOffset;
        } else if (proto == 17) {
            p.protocol = "UDP";
            if (t + 8 > end) return p;
            p.srcPort = PcapFile.u16(b,t); p.dstPort = PcapFile.u16(b,t+2);
            p.payloadOffset = t+8; p.payloadLength = Math.max(0, Math.min(end, t+PcapFile.u16(b,t+4))-p.payloadOffset);
        } else { p.protocol = "IP-" + proto; return p; }

        if (p.payloadLength > 0 && p.payloadOffset >= 0) {
            int start=p.payloadOffset, len=p.payloadLength;
            if (p.protocol.equals("TCP")) {
                String host = extractHttpHost(b,start,len);
                if (host.isEmpty()) host = extractTlsSni(b,start,len);
                p.domain = host;
            }
        }
        p.app = classify(p);
        return p;
    }
    private static String ip(byte[] b, int o) {
        return (b[o]&255)+"."+(b[o+1]&255)+"."+(b[o+2]&255)+"."+(b[o+3]&255);
    }
    private static String classify(PacketInfo p) {
        if (!p.domain.isEmpty()) {
            String d=p.domain.toLowerCase(Locale.ROOT);
            if (d.contains("youtube")) return "YOUTUBE";
            if (d.contains("facebook")) return "FACEBOOK";
            if (d.contains("instagram")) return "INSTAGRAM";
            if (d.contains("tiktok")) return "TIKTOK";
            if (d.contains("netflix")) return "NETFLIX";
            if (d.contains("github")) return "GITHUB";
            if (d.contains("google")) return "GOOGLE";
            return "WEB_DOMAIN";
        }
        if (p.protocol.equals("UDP") && (p.srcPort==53 || p.dstPort==53)) return "DNS";
        if (p.protocol.equals("TCP") && (p.srcPort==80 || p.dstPort==80)) return "HTTP";
        if (p.protocol.equals("TCP") && (p.srcPort==443 || p.dstPort==443)) return "HTTPS";
        if (p.protocol.equals("UDP") && (p.srcPort==443 || p.dstPort==443)) return "QUIC_OR_UDP443";
        return "UNKNOWN";
    }
    private static String extractHttpHost(byte[] b, int off, int len) {
        int n=Math.min(len, 8192);
        String s=new String(b,off,n,StandardCharsets.ISO_8859_1);
        if (!(s.startsWith("GET ")||s.startsWith("POST ")||s.startsWith("HEAD ")||s.startsWith("PUT ")||s.startsWith("DELETE ")||s.startsWith("OPTIONS "))) return "";
        for (String line:s.split("\\r?\\n")) {
            if (line.regionMatches(true,0,"Host:",0,5)) return line.substring(5).trim().replaceFirst(":\\d+$","");
        }
        return "";
    }
    private static String extractTlsSni(byte[] b, int off, int len) {
        // Parse a TLS ClientHello in this packet only; no TCP stream reassembly.
        int end=off+len;
        if (len<9 || (b[off]&255)!=22 || (b[off+5]&255)!=1) return "";
        try {
            int pos=off+9;
            pos+=2+32; // legacy version and random
            int session=b[pos++]&255; pos+=session;
            int cipher=PcapFile.u16(b,pos); pos+=2+cipher;
            int comp=b[pos++]&255; pos+=comp;
            if (pos+2>end) return "";
            int extLen=PcapFile.u16(b,pos); pos+=2;
            int extEnd=Math.min(end,pos+extLen);
            while(pos+4<=extEnd) {
                int type=PcapFile.u16(b,pos), size=PcapFile.u16(b,pos+2); pos+=4;
                if(size<0 || pos+size>extEnd) return "";
                if(type==0 && size>=5) {
                    int listLen=PcapFile.u16(b,pos);
                    if(listLen+2>size) return "";
                    int q=pos+2, listEnd=pos+2+listLen;
                    while(q+3<=listEnd) {
                        int nameType=b[q++]&255, nameLen=PcapFile.u16(b,q); q+=2;
                        if(q+nameLen>listEnd) return "";
                        if(nameType==0) return new String(b,q,nameLen,StandardCharsets.US_ASCII).toLowerCase(Locale.ROOT);
                        q+=nameLen;
                    }
                    return "";
                }
                pos+=size;
            }
        } catch (IndexOutOfBoundsException | IllegalArgumentException ignored) { return ""; }
        return "";
    }
}
