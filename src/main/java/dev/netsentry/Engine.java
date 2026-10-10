package dev.netsentry;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Offline packet inspection, rule evaluation, PCAP filtering and CSV flow reporting. */
final class Engine {
    private final Policy policy;
    private final Inspector inspector = new Inspector();
    Engine(Policy policy) { this.policy = policy; }

    static final class FlowStats {
        String key, src, dst, protocol, domain, app, action;
        long packets, bytes;
    }
    static final class Result {
        long total, forwarded, dropped, bytes;
        final Map<String,FlowStats> flows = new LinkedHashMap<>();
    }
    Result process(Path input, Path output, Path report) throws IOException {
        Result r = new Result();
        Set<String> blockedFlows = new HashSet<>();
        try (PcapFile pcap = new PcapFile(input, output)) {
            byte[] raw;
            while ((raw = pcap.nextPacket()) != null) {
                r.total++; r.bytes += raw.length;
                PacketInfo p = inspector.inspect(raw);
                String key = p.flowKey();
                boolean drop = blockedFlows.contains(key) || blockedFlows.contains(p.reverseFlowKey()) || policy.matches(p);
                if (drop) {
                    blockedFlows.add(key);
                    blockedFlows.add(p.reverseFlowKey());
                }
                FlowStats f = r.flows.computeIfAbsent(key, k -> {
                    FlowStats x = new FlowStats(); x.key=k; x.src=p.srcIp+":"+p.srcPort; x.dst=p.dstIp+":"+p.dstPort;
                    x.protocol=p.protocol; x.domain=p.domain; x.app=p.app; return x;
                });
                f.packets++; f.bytes += raw.length;
                if (!p.domain.isEmpty()) f.domain=p.domain;
                if (!p.app.equals("UNKNOWN")) f.app=p.app;
                if (drop) { r.dropped++; f.action="DROP"; }
                else { r.forwarded++; if (f.action == null) f.action="FORWARD"; pcap.writePacket(raw); }
            }
        }
        writeCsv(report, r);
        return r;
    }
    private static void writeCsv(Path path, Result r) throws IOException {
        try (BufferedWriter w=Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            w.write("flow,source,destination,protocol,domain,application,packets,bytes,action\n");
            for (FlowStats f:r.flows.values()) {
                w.write(csv(f.key)+","+csv(f.src)+","+csv(f.dst)+","+csv(f.protocol)+","+csv(f.domain)+","+csv(f.app)+","+f.packets+","+f.bytes+","+csv(f.action==null?"FORWARD":f.action)+"\n");
            }
        }
    }
    private static String csv(String s) { return "\""+(s==null?"":s).replace("\"","\"\"")+"\""; }
}
