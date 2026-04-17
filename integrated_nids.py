#!/usr/bin/env python3
"""
Integrated NIDS: eBPF Sniffer + XDP IPS Blocker + Autoencoder + Decision Tree
"""

import os
import sys
import ctypes
import time
import socket
import struct
import pickle
import numpy as np
import torch
import torch.nn as nn
from bcc import BPF

# ==============================================================================
# eBPF KERNEL C CODE
# ==============================================================================
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define FLOW_TIMEOUT_NS 5000000000ULL // 5 seconds

// Flow key (5-tuple)
struct flow_key_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  protocol;
};

// Extracted features
struct flow_stats_t {
    u64 flow_start_ns;
    u64 flow_last_ns;
    
    u32 fwd_packets;
    u32 bwd_packets;
    
    u64 fwd_bytes;
    u64 bwd_bytes;
    
    u32 fwd_pkt_len_min;
    u32 fwd_pkt_len_max;
    u32 bwd_pkt_len_min;
    u32 bwd_pkt_len_max;
    
    u64 fwd_iat_total;
    u64 fwd_iat_max;
    u64 fwd_iat_min;
    u64 fwd_last_ns;
    
    u64 bwd_iat_total;
    u64 bwd_iat_max;
    u64 bwd_iat_min;
    u64 bwd_last_ns;
    
    u32 fin_count;
    u32 syn_count;
    u32 rst_count;
    u32 psh_count;
    u32 ack_count;
    u32 urg_count;
    
    u16 fwd_win_init;
    u16 bwd_win_init;
};

// Maps
BPF_HASH(flow_map, struct flow_key_t, struct flow_stats_t, 10240);
BPF_HASH(blocked_ips, u32, u32, 10240); // XDP Blocklist Map

int xdp_packet_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // 1. IP BLOCKING LOGIC (XDP DROP)
    u32 src_ip = ip->saddr;
    u32 *is_blocked = blocked_ips.lookup(&src_ip);
    if (is_blocked && *is_blocked == 1) {
        return XDP_DROP; // Drop packet immediately without reaching OS
    }

    // 2. FLOW EXTRACTION LOGIC
    u8 protocol = ip->protocol;
    u16 src_port = 0, dst_port = 0;
    u32 payload_len = 0;
    u8 flags = 0;
    u16 window = 0;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        src_port = tcp->source;
        dst_port = tcp->dest;
        payload_len = bpf_ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);
        window = bpf_ntohs(tcp->window);
        u8 *tcp_header_byte = (u8 *)tcp;
        flags = tcp_header_byte[13];
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        src_port = udp->source;
        dst_port = udp->dest;
        payload_len = bpf_ntohs(udp->len) - 8;
    } else {
        return XDP_PASS; // Only care about TCP/UDP
    }

    struct flow_key_t key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = protocol
    };

    struct flow_key_t rev_key = {
        .src_ip = ip->daddr,
        .dst_ip = ip->saddr,
        .src_port = dst_port,
        .dst_port = src_port,
        .protocol = protocol
    };

    u64 now = bpf_ktime_get_ns();
    struct flow_stats_t *stats = flow_map.lookup(&key);
    int is_fwd = 1;

    if (!stats) {
        stats = flow_map.lookup(&rev_key);
        if (stats) is_fwd = 0;
    }

    if (!stats) {
        struct flow_stats_t new_stats = {0};
        new_stats.flow_start_ns = now;
        new_stats.flow_last_ns = now;
        new_stats.fwd_packets = 1;
        new_stats.fwd_bytes = payload_len;
        new_stats.fwd_pkt_len_min = payload_len;
        new_stats.fwd_pkt_len_max = payload_len;
        new_stats.fwd_last_ns = now;
        new_stats.fwd_win_init = window;
        
        if (protocol == IPPROTO_TCP) {
            if (flags & 0x01) new_stats.fin_count++;
            if (flags & 0x02) new_stats.syn_count++;
            if (flags & 0x04) new_stats.rst_count++;
            if (flags & 0x08) new_stats.psh_count++;
            if (flags & 0x10) new_stats.ack_count++;
            if (flags & 0x20) new_stats.urg_count++;
        }
        flow_map.update(&key, &new_stats);
    } else {
        stats->flow_last_ns = now;
        if (is_fwd) {
            stats->fwd_packets++;
            stats->fwd_bytes += payload_len;
            if (payload_len < stats->fwd_pkt_len_min) stats->fwd_pkt_len_min = payload_len;
            if (payload_len > stats->fwd_pkt_len_max) stats->fwd_pkt_len_max = payload_len;
            
            u64 iat = now - stats->fwd_last_ns;
            stats->fwd_iat_total += iat;
            if (iat > stats->fwd_iat_max) stats->fwd_iat_max = iat;
            if (stats->fwd_iat_min == 0 || iat < stats->fwd_iat_min) stats->fwd_iat_min = iat;
            stats->fwd_last_ns = now;
        } else {
            if (stats->bwd_packets == 0) stats->bwd_win_init = window;
            stats->bwd_packets++;
            stats->bwd_bytes += payload_len;
            if (stats->bwd_pkt_len_min == 0 || payload_len < stats->bwd_pkt_len_min) stats->bwd_pkt_len_min = payload_len;
            if (payload_len > stats->bwd_pkt_len_max) stats->bwd_pkt_len_max = payload_len;
            
            u64 iat = now - stats->bwd_last_ns;
            if (stats->bwd_last_ns != 0) {
                stats->bwd_iat_total += iat;
                if (iat > stats->bwd_iat_max) stats->bwd_iat_max = iat;
                if (stats->bwd_iat_min == 0 || iat < stats->bwd_iat_min) stats->bwd_iat_min = iat;
            }
            stats->bwd_last_ns = now;
        }
        
        if (protocol == IPPROTO_TCP) {
            if (flags & 0x01) stats->fin_count++;
            if (flags & 0x02) stats->syn_count++;
            if (flags & 0x04) stats->rst_count++;
            if (flags & 0x08) stats->psh_count++;
            if (flags & 0x10) stats->ack_count++;
            if (flags & 0x20) stats->urg_count++;
        }
    }
    return XDP_PASS;
}
"""

FEATURES = [
    'Destination Port',
    'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min',
    'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Min Packet Length', 'Max Packet Length', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Flow Duration', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Max', 'Bwd IAT Min',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'Subflow Fwd Packets', 'Subflow Bwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Bytes',
    'Down/Up Ratio', 'act_data_pkt_fwd', 'min_seg_size_forward'
]

# ==============================================================================
# ML ARCHITECTURE
# ==============================================================================
class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.enc1 = nn.Linear(input_dim, 64)
        self.enc2 = nn.Linear(64, 32)
        self.enc3 = nn.Linear(32, 16)
        self.dec1 = nn.Linear(16, 32)
        self.dec2 = nn.Linear(32, 64)
        self.dec3 = nn.Linear(64, input_dim)
        
        self.dec1.weight = nn.Parameter(self.enc3.weight.T.clone())
        self.dec2.weight = nn.Parameter(self.enc2.weight.T.clone())
        self.dec3.weight = nn.Parameter(self.enc1.weight.T.clone())
        
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.1)

    def encode(self, x):
        x = self.dropout(self.relu(self.enc1(x)))
        x = self.dropout(self.relu(self.enc2(x)))
        x = self.relu(self.enc3(x))
        return x

    def decode(self, z):
        z = self.dropout(self.relu(self.dec1(z)))
        z = self.dropout(self.relu(self.dec2(z)))
        return self.dec3(z)

    def forward(self, x):
        return self.decode(self.encode(x))

    def reconstruction_error(self, x):
        with torch.no_grad():
            return ((x - self.forward(x)) ** 2).sum(dim=1).cpu().numpy()

class UnifiedNIDS:
    def __init__(self, interface, model_path='ae_ids_model.pth', scaler_path='scaler.pkl', dt_path='decision_tree.pkl'):
        # 1. LOAD ML MODELS
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        print("[*] Loading ML Models...")
        ckpt = torch.load(model_path, map_location=self.device)
        
        self.threshold = 260
        self.margin = self.threshold * 0.5
        
        self.ae_model = Autoencoder(ckpt['input_dim']).to(self.device)
        self.ae_model.load_state_dict(ckpt['model_state_dict'])
        self.ae_model.eval()
        
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
            
        self.dt_model = None
        if os.path.exists(dt_path):
            with open(dt_path, 'rb') as f:
                self.dt_model = pickle.load(f)
            print("[+] Loaded Stacked Decision Tree model")
        else:
            print("[-] Warning: Decision Tree model not found. Using Autoencoder only.")

        # 2. LOAD EBPF KERNEL MODULE
        print(f"[*] Attaching XDP program to {interface}...")
        self.bpf = BPF(text=bpf_text)
        self.bpf.attach_xdp(dev=interface, fn=self.bpf.load_func("xdp_packet_filter", BPF.XDP))
        self.flow_map = self.bpf.get_table("flow_map")
        self.blocked_ips_map = self.bpf.get_table("blocked_ips")
        self.interface = interface
        self.threshold2 = ckpt['threshold']
        print(f"[+] Protection active! (Threshold: {self.threshold2:.4f})")

    def ip_to_str(self, ip):
        return socket.inet_ntoa(struct.pack("<I", ip))
        
    def block_ip(self, ip_int, ip_str):
        # Add to BPF map (kernel will drop immediately in XDP)
        self.blocked_ips_map[ctypes.c_uint32(ip_int)] = ctypes.c_uint32(1)
        print(f"\n[!!!]  IP BLOCKED VIA XDP: {ip_str} \n")

    def predict_flow(self, feats_dict):
        x_vals = []
        # Construct feature vector based precisely on the training features
        for f in FEATURES:
            x_vals.append(feats_dict.get(f, 0.0))
            
        X = np.array([x_vals], dtype=np.float32)
        X_scaled = np.clip(self.scaler.transform(X), -5, 5).astype(np.float32)
        X_tensor = torch.tensor(X_scaled, device=self.device)
        
        err = self.ae_model.reconstruction_error(X_tensor)[0]
        
        is_anomaly = False
        method = "Autoencoder"
        
        if self.dt_model and (self.threshold - self.margin) < err < (self.threshold + self.margin):
            # Uncertain region: Use Decision tree
            dt_pred = self.dt_model.predict(X_scaled)[0]
            is_anomaly = bool(dt_pred == 1)
            method = "DecisionTree"
        else:
            is_anomaly = bool(err > self.threshold)
            
        return is_anomaly, err, method

    def poll(self):
        try:
            while True:
                time.sleep(2)
                for k, v in list(self.flow_map.items()):
                    now = time.monotonic_ns()
                    
                    # Simple features mapping
                    total_fwd_len = v.fwd_bytes
                    total_bwd_len = v.bwd_bytes
                    all_len = total_fwd_len + total_bwd_len
                    total_pkts = v.fwd_packets + v.bwd_packets
                    
                    min_len = min(v.fwd_pkt_len_min, v.bwd_pkt_len_min) if v.bwd_packets > 0 else v.fwd_pkt_len_min
                    max_len = max(v.fwd_pkt_len_max, v.bwd_pkt_len_max)
                    avg_size = all_len / total_pkts if total_pkts > 0 else 0
                    
                    flow_dur = max(0, v.flow_last_ns - v.flow_start_ns) / 1000.0  # microseconds
                    
                    sport = socket.ntohs(k.src_port)
                    dport = socket.ntohs(k.dst_port)
                    srv_port = sport if sport < dport else dport
                    
                    feat_dict = {
                        'Destination Port': srv_port,
                        'Total Fwd Packets': v.fwd_packets,
                        'Total Backward Packets': v.bwd_packets,
                        'Total Length of Fwd Packets': total_fwd_len,
                        'Total Length of Bwd Packets': total_bwd_len,
                        'Fwd Packet Length Max': v.fwd_pkt_len_max,
                        'Fwd Packet Length Min': v.fwd_pkt_len_min,
                        'Bwd Packet Length Max': v.bwd_pkt_len_max,
                        'Bwd Packet Length Min': v.bwd_pkt_len_min,
                        'Min Packet Length': min_len,
                        'Max Packet Length': max_len,
                        'Average Packet Size': avg_size,
                        'Avg Fwd Segment Size': total_fwd_len / v.fwd_packets if v.fwd_packets > 0 else 0,
                        'Avg Bwd Segment Size': total_bwd_len / v.bwd_packets if v.bwd_packets > 0 else 0,
                        'Flow Duration': flow_dur,
                        
                        'Flow IAT Max': max(v.fwd_iat_max, v.bwd_iat_max) / 1000.0,
                        'Flow IAT Min': min(v.fwd_iat_min, v.bwd_iat_min) / 1000.0 if v.bwd_iat_min > 0 else v.fwd_iat_min / 1000.0,
                        'Fwd IAT Total': v.fwd_iat_total / 1000.0,
                        'Fwd IAT Max': v.fwd_iat_max / 1000.0,
                        'Fwd IAT Min': v.fwd_iat_min / 1000.0,
                        'Bwd IAT Total': v.bwd_iat_total / 1000.0,
                        'Bwd IAT Max': v.bwd_iat_max / 1000.0,
                        'Bwd IAT Min': v.bwd_iat_min / 1000.0,
                        
                        'FIN Flag Count': v.fin_count,
                        'SYN Flag Count': v.syn_count,
                        'RST Flag Count': v.rst_count,
                        'PSH Flag Count': v.psh_count,
                        'ACK Flag Count': v.ack_count,
                        'URG Flag Count': v.urg_count,
                        
                        'Init_Win_bytes_forward': v.fwd_win_init,
                        'Init_Win_bytes_backward': v.bwd_win_init,
                        
                        'Subflow Fwd Packets': v.fwd_packets,
                        'Subflow Bwd Packets': v.bwd_packets,
                        'Subflow Fwd Bytes': total_fwd_len,
                        'Subflow Bwd Bytes': total_bwd_len,
                        
                        'Down/Up Ratio': v.bwd_packets / v.fwd_packets if v.fwd_packets > 0 else 0,
                        'act_data_pkt_fwd': v.fwd_packets - 1 if v.fwd_packets > 0 else 0,
                        'min_seg_size_forward': 32 if k.protocol == 6 else 8
                    }
                    
                    src_str = self.ip_to_str(k.src_ip)
                    dst_str = self.ip_to_str(k.dst_ip)
                    
                    # 1. PREDICT using unified model
                    is_anom, err, method = self.predict_flow(feat_dict)
                    
                    status = "[!] ANOMALY" if is_anom else "[OK] NORMAL"
                    err = err/100
                    
                    print(f"Flow {src_str}:{socket.ntohs(k.src_port)} -> {dst_str}:{socket.ntohs(k.dst_port)} | {status} (Err: {err:.4f}, by {method})")
                    
                    # 2. BLOCK IP AT KERNEL LEVEL WITH XDP IF ANOMALY
                    ENABLE_BLOCKING = False 
                    
                    if is_anom:
                        if ENABLE_BLOCKING:
                            self.block_ip(k.src_ip, src_str)
                        else:
                            print(f"      [!] Would have blocked {src_str} via XDP (but ENABLE_BLOCKING is False)")
                    
                    # Delete processed flow
                    del self.flow_map[k]
                    
        except KeyboardInterrupt:
            print("\nDetaching from interface...")
            self.bpf.remove_xdp(self.interface, 0)
            print("Exit.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 integrated_nids.py <network_interface>")
        sys.exit(1)
        
    nids = UnifiedNIDS(sys.argv[1])
    nids.poll()
