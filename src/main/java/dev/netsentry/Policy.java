package dev.netsentry;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/** Policy rules are deliberately simple and auditable. */
final class Policy {
    final Set<String> blockedIps = new HashSet<>();
    final Set<String> blockedDomains = new HashSet<>();
    final Set<Integer> blockedPorts = new HashSet<>();
    final Set<String> blockedApps = new HashSet<>();

    void loadRules(Path path) throws IOException {
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(path)) { p.load(r); }
        addCsv(blockedIps, p.getProperty("blocked.ips", ""));
        addCsv(blockedDomains, p.getProperty("blocked.domains", "").toLowerCase(Locale.ROOT));
        addCsv(blockedApps, p.getProperty("blocked.apps", "").toUpperCase(Locale.ROOT));
        for (String s : split(p.getProperty("blocked.ports", ""))) blockedPorts.add(Integer.parseInt(s));
    }
    private static void addCsv(Set<String> target, String value) { target.addAll(split(value)); }
    private static List<String> split(String s) {
        if (s == null || s.isBlank()) return List.of();
        return Arrays.stream(s.split(",")).map(String::trim).filter(x -> !x.isEmpty()).toList();
    }
    boolean matches(PacketInfo p) {
        if (blockedIps.contains(p.srcIp) || blockedIps.contains(p.dstIp)) return true;
        if (blockedPorts.contains(p.srcPort) || blockedPorts.contains(p.dstPort)) return true;
        if (!p.domain.isBlank() && blockedDomains.stream().anyMatch(d -> domainMatches(p.domain, d))) return true;
        return blockedApps.contains(p.app.toUpperCase(Locale.ROOT));
    }
    private boolean domainMatches(String host, String rule) {
        String h = host.toLowerCase(Locale.ROOT), r = rule.toLowerCase(Locale.ROOT);
        if (r.startsWith("*.")) r = r.substring(2);
        return h.equals(r) || h.endsWith("." + r);
    }
}
