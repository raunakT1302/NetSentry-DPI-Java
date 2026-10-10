package dev.netsentry;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * NetSentry DPI: offline PCAP inspector and policy-based packet filter.
 * This tool processes capture files only; it does not intercept live traffic.
 */
public final class Main {
    private Main() {}

    public static void main(String[] args) {
        try {
            if (args.length == 0 || Arrays.asList(args).contains("--help")) {
                usage();
                return;
            }
            Map<String, List<String>> options = parseArgs(args);
            String input = one(options, "--input", null);
            if (input == null && !options.getOrDefault("_", List.of()).isEmpty()) input = options.get("_").get(0);
            if (input == null) throw new IllegalArgumentException("Missing input PCAP. Use --input capture.pcap");
            String output = one(options, "--output", "filtered.pcap");
            String report = one(options, "--report", "report.csv");
            Policy policy = new Policy();
            for (String ip : options.getOrDefault("--block-ip", List.of())) policy.blockedIps.add(ip.trim());
            for (String d : options.getOrDefault("--block-domain", List.of())) policy.blockedDomains.add(d.trim().toLowerCase(Locale.ROOT));
            for (String p : options.getOrDefault("--block-port", List.of())) {
                int port = Integer.parseInt(p);
                if (port < 0 || port > 65535) throw new IllegalArgumentException("Invalid port: " + p);
                policy.blockedPorts.add(port);
            }
            for (String app : options.getOrDefault("--block-app", List.of())) policy.blockedApps.add(app.toUpperCase(Locale.ROOT));
            for (String d : options.getOrDefault("--rules", List.of())) policy.loadRules(Path.of(d));

            Engine engine = new Engine(policy);
            Engine.Result result = engine.process(Path.of(input), Path.of(output), Path.of(report));
            System.out.println("\n=== NetSentry DPI report ===");
            System.out.printf("Packets read:       %d%n", result.total);
            System.out.printf("Packets forwarded:  %d%n", result.forwarded);
            System.out.printf("Packets dropped:    %d%n", result.dropped);
            System.out.printf("Bytes inspected:    %d%n", result.bytes);
            System.out.printf("Flows observed:     %d%n", result.flows.size());
            System.out.println("Filtered PCAP:      " + output);
            System.out.println("Flow CSV report:    " + report);
            System.out.println("\nNote: offline filtering creates a new capture file; it does not block traffic on your network.");
        } catch (Exception e) {
            System.err.println("NetSentry error: " + e.getMessage());
            System.err.println("Run with --help for usage.");
            System.exit(2);
        }
    }

    private static Map<String, List<String>> parseArgs(String[] args) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.startsWith("--")) {
                if (i + 1 >= args.length || args[i + 1].startsWith("--"))
                    throw new IllegalArgumentException("Expected a value after " + a);
                map.computeIfAbsent(a, k -> new ArrayList<>()).add(args[++i]);
            } else map.computeIfAbsent("_", k -> new ArrayList<>()).add(a);
        }
        return map;
    }
    private static String one(Map<String,List<String>> m, String key, String fallback) {
        List<String> v = m.get(key); return v == null || v.isEmpty() ? fallback : v.get(v.size()-1);
    }
    private static void usage() {
        System.out.println("""
            NetSentry DPI — offline Deep Packet Inspection in Java 17

            Usage:
              java -jar target/netsentry-dpi-1.0.0.jar --input capture.pcap --output filtered.pcap --report flows.csv
                [--block-ip 192.0.2.10] [--block-domain example.com]
                [--block-port 23] [--block-app YOUTUBE] [--rules rules.properties]

            Options can be repeated. Domains match the exact domain and its subdomains.
            Supported capture: classic PCAP, Ethernet link type, IPv4, TCP/UDP.
            This is a defensive educational analyzer, not a live firewall.
            """);
    }
}
