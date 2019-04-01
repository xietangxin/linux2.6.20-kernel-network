/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>

/* 
 * linux 中定义TCP首部
 */
struct tcphdr {
	__be16	source; // 16位源端口号
	__be16	dest;   // 16位目的端口号
	__be32	seq;    // 32位序号
	__be32	ack_seq;// 32位确认序号
/* 大小端数据排序不同 */
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4, // 4位首部长度
		doff:4,     // 4位保留
		fin:1,      // fin
		syn:1,      // syn
		rst:1,      // rst
		psh:1,      // psh
		ack:1,      // ack
		urg:1,      // urg
		ece:1,      // ece
		cwr:1;      // cwr
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window; // 16位窗口大小
	__sum16	check;  // 16位校验和
	__be16	urg_ptr;// 16位紧急指针
};

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr { 
	struct tcphdr hdr;
	__be32 		  words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = __constant_htonl(0x00800000), 
	TCP_FLAG_ECE = __constant_htonl(0x00400000), 
	TCP_FLAG_URG = __constant_htonl(0x00200000), 
	TCP_FLAG_ACK = __constant_htonl(0x00100000), 
	TCP_FLAG_PSH = __constant_htonl(0x00080000), 
	TCP_FLAG_RST = __constant_htonl(0x00040000), 
	TCP_FLAG_SYN = __constant_htonl(0x00020000), 
	TCP_FLAG_FIN = __constant_htonl(0x00010000),
	TCP_RESERVED_BITS = __constant_htonl(0x0F000000),
	TCP_DATA_OFFSET = __constant_htonl(0xF0000000)
}; 

/* TCP socket options */
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */

#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8

enum tcp_ca_state
{
	TCP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)
	TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
	TCP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)
	TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
	TCP_CA_Loss = 4
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)
};

struct tcp_info
{
	__u8	tcpi_state;
	__u8	tcpi_ca_state;
	__u8	tcpi_retransmits;
	__u8	tcpi_probes;
	__u8	tcpi_backoff;
	__u8	tcpi_options;
	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

	__u32	tcpi_rto;
	__u32	tcpi_ato;
	__u32	tcpi_snd_mss;
	__u32	tcpi_rcv_mss;

	__u32	tcpi_unacked;
	__u32	tcpi_sacked;
	__u32	tcpi_lost;
	__u32	tcpi_retrans;
	__u32	tcpi_fackets;

	/* Times. */
	__u32	tcpi_last_data_sent;
	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32	tcpi_last_data_recv;
	__u32	tcpi_last_ack_recv;

	/* Metrics. */
	__u32	tcpi_pmtu;
	__u32	tcpi_rcv_ssthresh;
	__u32	tcpi_rtt;
	__u32	tcpi_rttvar;
	__u32	tcpi_snd_ssthresh;
	__u32	tcpi_snd_cwnd;
	__u32	tcpi_advmss;
	__u32	tcpi_reordering;

	__u32	tcpi_rcv_rtt;
	__u32	tcpi_rcv_space;

	__u32	tcpi_total_retrans;
};

/* for TCP_MD5SIG socket option */
#define TCP_MD5SIG_MAXKEYLEN	80

struct tcp_md5sig {
	struct __kernel_sockaddr_storage tcpm_addr;	/* address associated */
	__u16	__tcpm_pad1;				/* zero */
	__u16	tcpm_keylen;				/* key length */
	__u32	__tcpm_pad2;				/* zero */
	__u8	tcpm_key[TCP_MD5SIG_MAXKEYLEN];		/* key (binary) */
};

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <linux/dmaengine.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

struct tcp_options_received {
/*	PAWS/RTTM data	*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	u32	ts_recent;	/* Time stamp to echo next		*/
	u32	rcv_tsval;	/* Time stamp value             	*/
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		dsack : 1,	/* D-SACK is scheduled			*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
		sack_ok : 4,	/* SACK seen on SYN packet		*/
		snd_wscale : 4,	/* Window scaling received from sender	*/
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/
/*	SACKs data	*/
	u8	eff_sacks;	/* Size of SACK array to send with next packet */
	u8	num_sacks;	/* Number of SACK blocks		*/
	u16	user_mss;  	/* mss requested by user in ioctl */
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

struct tcp_request_sock {
	struct inet_request_sock 	req;
#ifdef CONFIG_TCP_MD5SIG
	/* Only used by TCP MD5 Signature so far. */
	struct tcp_request_sock_ops	*af_specific;
#endif
	u32			 	rcv_isn; //客户端的初始序号
	u32			 	snt_isn; //服务端的初始序号
};

static inline struct tcp_request_sock *tcp_rsk(const struct request_sock *req)
{
	return (struct tcp_request_sock *)req;
}

/* tcp_sock 结构是TCP协议的控制块，它在inet_connection_sock结构的基础上
 * 扩张了滑动窗口协议,拥塞控制算法等一些TCP专有属性。
 */
struct tcp_sock {
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;
	/* TCP 首部长度，包括TCP选项 */
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/
	/* 记录该套接口发送到网络设备段的长度
	 * 在不支持TSO的情况下，其值等于MSS
	 * 如果网卡支持TSO且采用TSO进行发送，则需要重新计算
	 */
	u16	xmit_size_goal;	/* Goal for segmenting output packets	*/

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 *   首部预测标志
 */
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 *   rcv_nxt:等待接收的下一个TCP段的序号，每接收一个TCP段之后都会更新该值
 *   snd_nxt:等待发送下一个TCP段的序号
 */
 	u32	rcv_nxt;	/* What we want to receive next 	*/
 	u32	snd_nxt;	/* Next sequence we send		*/

    /* 在输出的段中，最早一个未确认段的序号 */
 	u32	snd_una;	/* First byte we want an ack for	*/
 	/* 最近发送的小包(小于MSS的段)的最后一个字节序号，在发送成功段后，如果报文小于MSS,
 	 * 即更新该字段，主要用来判断是否启动Nagle算法
 	 */
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
 	/* 最近一次收到ACK段的时间，用于TCP保活 */
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
	/* 最近一次发送数据包的时间，主要用于拥塞窗口的设置 */
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */

	/* Data for direct copy to user 
	 * 用来控制复制数据到用户进程的控制块
	 */
	struct {
	    /* 如果未启动tcp_low_latency,TCP段将首先缓存到此队列，
	      * 直到进程主要读取到才真正地接收到接收到接收队列中并处理
	      */
		struct sk_buff_head	prequeue;
		/* 在未启动tcp_low_latency情况下，当前正在读取TCP流的进程，如果NULL则表示暂时没有进程对其进行读取 */
		struct task_struct	*task;
		/* 在未启动tcp_low_latency情况下，用来存放数据的用户空间地址，在接收处理TCP段时直接复制到用户空间 */
		struct iovec		*iov;
		/* prequeue队列当前消耗的内存 */
		int			memory;
		/* 用户缓存中当前可以使用的缓存大小，由recv等系统调用的len参数初始化 */
		int			len;

		/* 网络设备的DMA相关 */
#ifdef CONFIG_NET_DMA
		/* members for async copy */
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;

    /* 记录更新发送窗口的那个ACK段序号，用来判断是否需要更新窗口
      * 如果后续收到的ACK段的序号大于snd_wll,则需要更新窗口，否则无需更新
      */
	u32	snd_wl1;	/* Sequence for window update		*/
	/* 接收方提供的接受窗口大小，即发送方发送窗口大小  */
	u32	snd_wnd;	/* The window we expect to receive	*/
	/* 接收方通告过的最大接受窗口值 */
	u32	max_window;	/* Maximal window ever seen from peer	*/
	/* 发送方当前有效的MSS */
	u32	mss_cache;	/* Cached effective mss, not including SACKS */

    /* 滑动窗口的最大值，滑动窗口大小在变化过程中始终不能超过该值。 
      * 在TCP建立连接时，该字段被初始化，置为最大的16位整数左移窗口的扩大因子的位数
      */
	u32	window_clamp;	/* Maximal window to advertise		*/
	/* 当前接收窗口大小的阈值  */
	u32	rcv_ssthresh;	/* Current window clamp			*/

	u32	frto_highmark;	/* snd_nxt when RTO occurred */
	u8	reordering;	/* Packet reordering metric.		*/
	u8	frto_counter;	/* Number of new acks after RTO */
	/* 标识是否允许Nagle算法 */
	u8	nonagle;	/* Disable Nagle algorithm?             */
	/* 保活探测次数，最大值为127 */
	u8	keepalive_probes; /* num of allowed keep alive probes	*/

/* RTT measurement */
    /* 平滑的RTT,为避免浮点运算，是指将其放大8倍后存储的 */
	u32	srtt;		/* smoothed round trip time << 3	*/
	/* RTT平均偏差，由RTT与RTT均值偏差绝对值加权平均而得到，其值越大说明RTT抖动得越厉害 */
	u32	mdev;		/* medium deviation			*/
	/* 跟踪每次发生窗口内的段被全部确认过程中，RTT平均偏差的最大值，描述RTT抖动的最大范围 */
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/
	/* 平滑的RTT平均偏差，由mdev计算得到，用来计算RTO */
	u32	rttvar;		/* smoothed mdev_max			*/
	u32	rtt_seq;	/* sequence number to update rttvar	*/

	u32	packets_out;	/* Packets which are "in flight"	*/
	u32	left_out;	/* Packets which leaved network	*/
	u32	retrans_out;	/* Retransmitted packets out		*/
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	u32	snd_ssthresh;	/* Slow start size threshold		*/
 	u32	snd_cwnd;	/* Sending congestion window		*/
 	u16	snd_cwnd_cnt;	/* Linear increase counter		*/
	u16	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
	u32	snd_cwnd_used;
	u32	snd_cwnd_stamp;

	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */

 	u32	rcv_wnd;	/* Current receiver window		*/
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*/
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	u32	copied_seq;	/* Head of yet unread data		*/

/*	SACKs data	*/
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	struct tcp_sack_block recv_sack_cache[4];

	/* from STCP, retrans queue hinting */
	struct sk_buff* lost_skb_hint;

	struct sk_buff *scoreboard_skb_hint;
	struct sk_buff *retransmit_skb_hint;
	struct sk_buff *forward_skb_hint;
	struct sk_buff *fastpath_skb_hint;

	int     fastpath_cnt_hint;
	int     lost_cnt_hint;
	int     retransmit_cnt_hint;
	int     forward_cnt_hint;

	u16	advmss;		/* Advertised MSS			*/
	u16	prior_ssthresh; /* ssthresh saved at recovery start	*/
	u32	lost_out;	/* Lost packets			*/
	u32	sacked_out;	/* SACK'd packets			*/
	u32	fackets_out;	/* FACK'd packets			*/
	u32	high_seq;	/* snd_nxt at onset of congestion	*/

	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	u32	undo_marker;	/* tracking retrans started here. */
	int	undo_retrans;	/* number of undoable retransmissions. */
	u32	urg_seq;	/* Seq of received urgent pointer */
	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u8	urg_mode;	/* In urgent mode		*/
	u8	ecn_flags;	/* ECN status bits.			*/
	u32	snd_up;		/* Urgent pointer		*/

	u32	total_retrans;	/* Total retransmits for entire connection */
	u32	bytes_acked;	/* Appropriate Byte Counting - RFC3465 */

	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */
	int			linger2;

	unsigned long last_synq_overflow; 

	u32	tso_deferred;

/* Receiver side RTT estimation */
	struct {
		u32	rtt;
		u32	seq;
		u32	time;
	} rcv_rtt_est;

/* Receiver queue space */
	struct {
		int	space;
		u32	seq;
		u32	time;
	} rcvq_space;

/* TCP-specific MTU probe information. */
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signagure Option information */
	struct tcp_md5sig_info	*md5sig_info;
#endif
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
	u32			  tw_rcv_nxt;
	u32			  tw_snd_nxt;
	u32			  tw_rcv_wnd;
	u32			  tw_ts_recent;
	long			  tw_ts_recent_stamp;
#ifdef CONFIG_TCP_MD5SIG
	u16			  tw_md5_keylen;
	u8			  tw_md5_key[TCP_MD5SIG_MAXKEYLEN];
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

#endif

#endif	/* _LINUX_TCP_H */
