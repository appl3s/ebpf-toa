// echo 1 > /sys/kernel/tracing/tracing_on
// cat /sys/kernel/tracing/trace_pipe
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in6.h>

//

// cannot be larger than 5: "invalid indirect read from stack off -44+5 size 6"
// #define CC_LENGTH 5

// struct bpf_map_def SEC("maps") cong_map = {
// 	.type = BPF_MAP_TYPE_ARRAY,
// 	.key_size = sizeof(__u32),
// 	.value_size = CC_LENGTH,
// 	.max_entries = 10,
// };

// static inline void init_map()
// {
// 	__u32 key0 = 0;
// 	__u32 key1 = 1;
// 	__u32 key2 = 2;
// 	__u32 key3 = 3;
// 	char a[]="vegas";
// 	char b[]="reno";
// 	char c[]="bbr";
// 	char d[]="cubic";

// 	bpf_map_update_elem(&cong_map, &key0, a, BPF_ANY);
// 	bpf_map_update_elem(&cong_map, &key1, b, BPF_ANY);
// 	bpf_map_update_elem(&cong_map, &key2, c, BPF_EXIST);
// 	bpf_map_update_elem(&cong_map, &key3, d, BPF_EXIST);
// }

int _version SEC("version") = 1;

struct toa_v4_data {
	__u8 kind;
	__u8 len;
	__u16 port;
    __u32 ip;
};

struct toa_v6_data {
	__u8 kind;
	__u8 len;
	__u16 port;
    struct in6_addr ip6;
};

struct toa_v4_data toav4 = {
	.kind = 254,
	.len = sizeof(toav4),
	.port = 8080,
	.ip = bpf_htonl(0x04040404),
};

struct toa_v6_data toav6 = {
	.kind = 253,
	.len = sizeof(toav6),
	.port = 8080,
	.ip6 = {
		.in6_u.u6_addr32 = {
			bpf_htonl(0x20010000), 0x00,0x00, bpf_htonl(0x00008888)
		},
	},
};

static inline void sockops_tcp_store_hdr(struct bpf_sock_ops *skops) 
{
	if((skops->skb_tcp_flags & 0x0002) != 0x0002) {
		// only set in syn packet
		bpf_printk("only set in syn packet, got %02x", skops->skb_tcp_flags);
		return;
	}

	bpf_store_hdr_opt(skops, &toav4, sizeof(toav4), 0);
	// bpf_store_hdr_opt(skops, &toav6, sizeof(toav6), 0);
}

SEC("sockops")
int bpf_sockops_toa(struct bpf_sock_ops *skops)
{
	int op = (int) skops->op;

	switch(op) {
		case BPF_SOCK_OPS_TCP_CONNECT_CB:
			//bpf_printk("BPF_SOCK_OPS_TCP_CONNECT_CB");
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // 设置flag
			//sockops_set_hdr_cb_flags
			bpf_sock_ops_cb_flags_set(skops,
				skops->bpf_sock_ops_cb_flags |
				BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
			break;
		case BPF_SOCK_OPS_HDR_OPT_LEN_CB: // 保留长度
			//bpf_printk("BPF_SOCK_OPS_HDR_OPT_LEN_CB");
			bpf_reserve_hdr_opt(skops, sizeof(toav4), 0);
			// bpf_reserve_hdr_opt(skops, sizeof(toav6), 0);
			break;
		case BPF_SOCK_OPS_WRITE_HDR_OPT_CB: // 写入
			//bpf_printk("BPF_SOCK_OPS_WRITE_HDR_OPT_CB");
			sockops_tcp_store_hdr(skops);
			bpf_printk("TOA ebpf written");
			break;
	}

	return 1;
}

char _license[] SEC("license") = "GPL";
