package dev.netsentry;

final class PacketInfo {
    String srcIp = "", dstIp = "", protocol = "OTHER", domain = "", app = "UNKNOWN";
    int srcPort = -1, dstPort = -1;
    int ipOffset = -1, transportOffset = -1, payloadOffset = -1, payloadLength = 0;
    boolean ipv4;
    String flowKey() {
        return srcIp + ":" + srcPort + " -> " + dstIp + ":" + dstPort + "/" + protocol;
    }
    String reverseFlowKey() {
        return dstIp + ":" + dstPort + " -> " + srcIp + ":" + srcPort + "/" + protocol;
    }
}
