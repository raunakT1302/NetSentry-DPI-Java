package dev.netsentry;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/** Minimal classic-PCAP reader/writer. Supports little- and big-endian PCAP headers. */
final class PcapFile implements AutoCloseable {
    private final DataInputStream in;
    private final OutputStream out;
    private final boolean little;
    private final byte[] globalHeader = new byte[24];

    PcapFile(Path input, Path output) throws IOException {
        in = new DataInputStream(new BufferedInputStream(Files.newInputStream(input)));
        readFully(in, globalHeader);
        int magic = ((globalHeader[0]&255)<<24)|((globalHeader[1]&255)<<16)|((globalHeader[2]&255)<<8)|(globalHeader[3]&255);
        if (magic == 0xa1b2c3d4) little = false;
        else if (magic == 0xd4c3b2a1) little = true;
        else if (magic == 0xa1b23c4d || magic == 0x4d3cb2a1)
            throw new IOException("Nanosecond PCAP is not supported by this minimal version; convert to microsecond PCAP first.");
        else throw new IOException("Invalid classic PCAP magic number.");
        long linkType = u32(globalHeader, 20, little);
        if (linkType != 1) throw new IOException("Unsupported PCAP link type " + linkType + "; Ethernet (1) is required.");
        out = new BufferedOutputStream(Files.newOutputStream(output));
        out.write(globalHeader);
    }
    byte[] nextPacket() throws IOException {
        byte[] h = new byte[16];
        int first = in.read();
        if (first < 0) return null;
        h[0] = (byte) first;
        try { readFully(in, h, 1, 15); } catch (EOFException e) { throw new IOException("Truncated packet header."); }
        long incl = u32(h, 8, little);
        if (incl > 16_777_216) throw new IOException("Unreasonable packet size: " + incl);
        byte[] data = new byte[(int)incl];
        try { readFully(in, data); } catch (EOFException e) { throw new IOException("Truncated packet body."); }
        currentHeader = h;
        return data;
    }
    private byte[] currentHeader;
    void writePacket(byte[] packet) throws IOException {
        if (currentHeader == null) throw new IllegalStateException("No packet header");
        out.write(currentHeader); out.write(packet);
    }
    static long u32(byte[] b, int o, boolean le) {
        if (le) return (b[o]&255L)|((b[o+1]&255L)<<8)|((b[o+2]&255L)<<16)|((b[o+3]&255L)<<24);
        return ((b[o]&255L)<<24)|((b[o+1]&255L)<<16)|((b[o+2]&255L)<<8)|(b[o+3]&255L);
    }
    static int u16(byte[] b, int o) { return ((b[o]&255)<<8)|(b[o+1]&255); }
    static void readFully(InputStream in, byte[] b) throws IOException { readFully(in,b,0,b.length); }
    static void readFully(InputStream in, byte[] b, int off, int len) throws IOException {
        int n=0; while(n<len){int r=in.read(b,off+n,len-n); if(r<0)throw new EOFException(); n+=r;}
    }
    @Override public void close() throws IOException { try { in.close(); } finally { out.close(); } }
}
