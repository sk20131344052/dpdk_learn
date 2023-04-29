


#include <rte_common.h>


#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>


#include <rte_kni.h>

#include <stdio.h>

#include <linux/if_ether.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define ENABLE_KNI	1

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191

#define MBUF_CACHE_SIZE 0
#define MAX_PACKET_SIZE	2048
#define MBUF_DATA_SIZE	(MAX_PACKET_SIZE+RTE_PKTMBUF_HEADROOM)

#define BURST_SIZE 128

#define DPDK_QUEUE_ID_RX 0

#define UDP_PORT    8888

int g_dpdkPortId = -1;


struct rte_mempool *pktmbuf_pool = NULL;


static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN },
#if ENABLE_KNI
	.txmode = { .mq_mode = ETH_MQ_TX_NONE}
#endif
};

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))


static uint32_t g_src_ip = MAKE_IPV4_ADDR(192, 168, 0, 120);
static uint32_t g_dest_ip = MAKE_IPV4_ADDR(192, 168, 0, 113);
static uint8_t g_dest_mac_mac_addr[RTE_ETHER_ADDR_LEN] = {0xEC, 0xF4, 0xBB, 0x4A, 0xA3, 0xB2};//{ 0x00, 0x0c, 0x29, 0x18, 0xef, 0x9d };
static uint8_t g_src_mac_addr[RTE_ETHER_ADDR_LEN];

static void port_init(struct rte_mempool *mbuf_pool) {

    g_dpdkPortId = 0;
	
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
	if (nb_sys_ports == 0)
		rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");
	
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf local_port_conf = port_conf_default;
	
	rte_eth_dev_info_get(g_dpdkPortId, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;
    if (rte_eth_dev_configure(g_dpdkPortId, num_rx_queues, num_tx_queues, &port_conf)) {
        rte_exit(EXIT_FAILURE, "rte_eth_dev_configure() failed.\n");
    }
	
	uint16_t nb_txd = TX_RING_SIZE;
	uint16_t nb_rxd = RX_RING_SIZE;
	rte_eth_dev_adjust_nb_rx_tx_desc(g_dpdkPortId, &nb_rxd, &nb_txd);

    // Set up RX queue.
    struct rte_eth_rxconf rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = local_port_conf.rxmode.offloads;
    if (rte_eth_rx_queue_setup(g_dpdkPortId, DPDK_QUEUE_ID_RX, RX_RING_SIZE,
            rte_eth_dev_socket_id(g_dpdkPortId), &rxq_conf, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "Couldn't setup RX queue.\n");
    }
	
	// Set up TX queue.
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = local_port_conf.txmode.offloads;
	if (rte_eth_tx_queue_setup(g_dpdkPortId, 0, nb_txd,
            rte_eth_dev_socket_id(g_dpdkPortId), &txq_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Couldn't setup TX queue.\n");
    }

    // Start the Ethernet port.
    if (rte_eth_dev_start(g_dpdkPortId) < 0) {
        rte_exit(EXIT_FAILURE, "Device start failed.\n");
    }

    // Enable RX in promiscuous mode for the Ethernet device.
    rte_eth_promiscuous_enable(g_dpdkPortId);
}

static void create_eth_ip_udp_pkt(uint8_t *msg, size_t total_len, uint8_t *dst_mac,
    uint32_t src_ip, uint32_t dst_ip, uint16_t udp_src_port, uint16_t udp_dst_port, 
    uint8_t *data, int length) {

	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->s_addr.addr_bytes, g_src_mac_addr, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    size_t ip_len = total_len - sizeof(struct rte_ether_hdr);
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons((uint16_t)ip_len);
    ip->packet_id = 0;
	ip->fragment_offset = 0;
    ip->time_to_live = 64;
	ip->next_proto_id = IPPROTO_UDP;
	
	ip->src_addr = src_ip;
	ip->dst_addr = dst_ip;
	
	ip->hdr_checksum = 0;
    ip->hdr_checksum =  rte_ipv4_cksum(ip);

    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
    //size_t udp_len = ip_len - sizeof(struct rte_ipv4_hdr);
    udp->src_port = htons(udp_src_port);
    udp->dst_port = htons(udp_dst_port);
    udp->dgram_len = htons((uint16_t)(length + sizeof(struct rte_udp_hdr)));

    uint32_t *payload = (uint32_t *)(udp + 1);
    rte_memcpy(payload, data, length);

	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

}



static void do_send_udp(struct rte_mempool *mbuf_pool, unsigned char *data, int length) {

	const unsigned eth_total_len = length + 42;

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "Cannot alloc mbuf\n");
	}

	mbuf->pkt_len = eth_total_len;
    mbuf->data_len = eth_total_len;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	const int udp_port = UDP_PORT;

	create_eth_ip_udp_pkt(pkt_data, eth_total_len, g_dest_mac_mac_addr, 
		g_src_ip, g_dest_ip, udp_port, udp_port, data, length);

	rte_eth_tx_burst(g_dpdkPortId, 0, &mbuf, 1);

	rte_pktmbuf_free(mbuf);

}

static void create_eth_arp_pkt(uint8_t *msg, uint8_t *dst_mac,
    uint32_t src_ip, uint32_t dst_ip) {

	
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->s_addr.addr_bytes, g_src_mac_addr, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);

	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = htons(2);

	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, g_src_mac_addr, RTE_ETHER_ADDR_LEN);
	rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

	arp->arp_data.arp_sip = src_ip;
	arp->arp_data.arp_tip = dst_ip;

	
	struct in_addr addr;

	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, (struct rte_ether_addr*)&arp->arp_data.arp_sha);

	addr.s_addr = arp->arp_data.arp_sip;
	printf(" arp src: %s, mac: %s", inet_ntoa(addr), buf);

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, (struct rte_ether_addr*)&arp->arp_data.arp_tha);
	addr.s_addr = arp->arp_data.arp_tip;
	printf(", dst: %s, mac: %s \n", inet_ntoa(addr), buf);

	

}


static void do_send_arp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "Cannot alloc mbuf\n");
	}

	mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;
	
	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	create_eth_arp_pkt(pkt_data, dst_mac, sip, dip);

	rte_eth_tx_burst(g_dpdkPortId, 0, &mbuf, 1);
	
	rte_pktmbuf_free(mbuf);

}


#if ENABLE_KNI


static struct rte_kni *kni = NULL;
static rte_atomic32_t kni_stop = RTE_ATOMIC32_INIT(0);
static rte_atomic32_t kni_pause = RTE_ATOMIC32_INIT(0);

int kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[]);
int kni_config_network_if(uint16_t port_id, uint8_t if_up);
int kni_change_mtu(uint16_t port_id, unsigned int new_mtu);


int kni_change_mtu(uint16_t port_id, unsigned int new_mtu) {

	int ret;
	uint16_t nb_txd = TX_RING_SIZE;
	uint16_t nb_rxd = RX_RING_SIZE;
	
	struct rte_eth_conf conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		printf("Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	printf("Change MTU of port %d to %u\n", port_id, new_mtu);

	/* Stop specific port */
	rte_eth_dev_stop(port_id);

	memcpy(&conf, &port_conf_default, sizeof(conf));
	/* Set new MTU */
	if (new_mtu > RTE_ETHER_MAX_LEN)
		conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
	else
		conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_JUMBO_FRAME;

	/* mtu + length of header + length of FCS = max pkt length */
 	conf.rxmode.max_rx_pkt_len = new_mtu + 14 + 4;
	
	ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
	if (ret < 0) {
		printf("Fail to reconfigure port %d\n", port_id);
		return ret;
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
				"for port%u (%d)\n", (unsigned int)port_id,
				ret);

	rte_eth_dev_info_get(port_id, &dev_info);
	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = conf.rxmode.offloads;
	ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
		rte_eth_dev_socket_id(port_id), &rxq_conf, pktmbuf_pool);
	if (ret < 0) {
		printf("Fail to setup Rx queue of port %d\n",
				port_id);
		return ret;
	}

	// Set up TX queue.
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = conf.txmode.offloads;
	if (rte_eth_tx_queue_setup(port_id, 0, nb_txd,
            rte_eth_dev_socket_id(port_id), &txq_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Couldn't setup TX queue.\n");
    }

	/* Restart specific port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		printf("Fail to restart port %d\n", port_id);
		return ret;
	}

	rte_eth_promiscuous_enable(port_id);

	return 0;

}

int kni_config_network_if(uint16_t port_id, uint8_t if_up) {

	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		printf("Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	printf("Configure network interface of %d %s\n",
					port_id, if_up ? "up" : "down");

	rte_atomic32_inc(&kni_pause);

	if (if_up != 0) { /* Configure network interface up */
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	} else /* Configure network interface down */
		rte_eth_dev_stop(port_id);

	rte_atomic32_dec(&kni_pause);

	if (ret < 0)
		printf("Failed to start port %d\n", port_id);

	return ret;

}

int kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[]) {

	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		printf("Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	printf("Configure mac address of %d\n", port_id);
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, (struct rte_ether_addr*)mac_addr);
	printf("\tAddress: %s\n", buf);

	ret = rte_eth_dev_default_mac_addr_set(port_id,
					(struct rte_ether_addr *)mac_addr);
	if (ret < 0)
		printf("Failed to config mac_addr for port %d\n",
			port_id);

	return ret;

}

static int init_kni(void) {

	uint16_t num_of_kni_ports = rte_eth_dev_count_avail();
	if (num_of_kni_ports != 1)
		rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");
	
	rte_kni_init(num_of_kni_ports);

	struct rte_kni_conf conf;
	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", g_dpdkPortId);
	conf.group_id = (uint16_t)g_dpdkPortId;
	conf.mbuf_size = MAX_PACKET_SIZE;

	struct rte_eth_dev_info dev_info;
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(g_dpdkPortId, &dev_info);

	rte_eth_macaddr_get(g_dpdkPortId, (struct rte_ether_addr*)&conf.mac_addr);
	rte_eth_dev_get_mtu(g_dpdkPortId, &conf.mtu);

	struct rte_kni_ops ops;
	memset(&ops, 0, sizeof(ops));
	ops.port_id = g_dpdkPortId;
	ops.change_mtu = kni_change_mtu;
	ops.config_network_if = kni_config_network_if;
	ops.config_mac_address = kni_config_mac_address;

	kni = rte_kni_alloc(pktmbuf_pool, &conf, &ops);
	if (!kni)
			rte_exit(EXIT_FAILURE, "Fail to create kni for "
						"port: %d\n", g_dpdkPortId);

	return 0;

}

static int free_kni(uint16_t port_id) {

	rte_kni_release(kni);
	rte_eth_dev_stop(port_id);

	return 0;
}

static void
log_link_state(struct rte_kni *kni, int prev, struct rte_eth_link *link)
{
	if (kni == NULL || link == NULL)
		return;

	if (prev == ETH_LINK_DOWN && link->link_status == ETH_LINK_UP) {
		printf( "%s NIC Link is Up %d Mbps %s %s.\n",
			rte_kni_get_name(kni),
			link->link_speed,
			link->link_autoneg ?  "(AutoNeg)" : "(Fixed)",
			link->link_duplex ?  "Full Duplex" : "Half Duplex");
	} else if (prev == ETH_LINK_UP && link->link_status == ETH_LINK_DOWN) {
		printf( "%s NIC Link is Down.\n",
			rte_kni_get_name(kni));
	}
}


static void *
monitor_all_ports_link_status(void *arg)
{
	uint16_t portid;
	struct rte_eth_link link;
	unsigned int i;
	uint32_t ports_mask = 0x1;
	
	int prev;
	(void) arg;

	while (1) {
		rte_delay_ms(500);
			
		memset(&link, 0, sizeof(link));
		rte_eth_link_get_nowait(g_dpdkPortId, &link);
			
		prev = rte_kni_update_link(kni, link.link_status);
		log_link_state(kni, prev, &link);
	}
	return NULL;
}



#endif

static void burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}




int main(int argc, char *argv[]) {
    // Initialize the Environment Abstraction Layer. All DPDK apps must do this.
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    // Creates a new mempool in memory to hold the mbufs.
    pktmbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pktmbuf_pool) {
        rte_exit(EXIT_FAILURE, "Couldn't create mbuf pool\n");
    }
	printf("rte_pktmbuf_pool_create\n");
	
    port_init(pktmbuf_pool);
	rte_eth_macaddr_get(g_dpdkPortId, (struct rte_ether_addr*)g_src_mac_addr);
#if ENABLE_KNI
	init_kni();
/*
	pthread_t kni_link_tid;
	int ret = rte_ctrl_thread_create(&kni_link_tid,
				     "KNI link status check", NULL,
				     monitor_all_ports_link_status, NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"Could not create link status thread!\n");
			*/
#endif
    while (1) {

#if ENABLE_KNI

		struct rte_mbuf *pkts_burst[BURST_SIZE];
		unsigned num_rx_recvd = rte_kni_rx_burst(kni, pkts_burst, BURST_SIZE);
		if (unlikely(num_rx_recvd > BURST_SIZE)) {
			printf("Error receiving from KNI\n");
			continue;
		}
		unsigned j = 0;
		for (j = 0;j < num_rx_recvd;j ++) {

			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(pkts_burst[j], struct rte_ether_hdr*);
			printf(" kni : ehdr->ether_type --> %x\n", ntohs(ehdr->ether_type));

		}

		unsigned nb_tx = rte_eth_tx_burst(g_dpdkPortId, 0, pkts_burst, (uint16_t)num_rx_recvd);
		//if (unlikely(nb_tx < num_rx_recvd)) {
		burst_free_mbufs(pkts_burst, num_rx_recvd);
			
		//}

#endif



        struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(g_dpdkPortId, DPDK_QUEUE_ID_RX, mbufs, BURST_SIZE);
		if (unlikely(num_recvd > BURST_SIZE)) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}

		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {
			
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);

			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {

				struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

				if (arp_hdr->arp_data.arp_tip == g_src_ip) {

					// sip change to dip and dip change to sip
					// dmac change to smac and smac change to dmac
					printf("do_send_arp\n");
					do_send_arp(pktmbuf_pool, arp_hdr->arp_data.arp_sha.addr_bytes, arp_hdr->arp_data.arp_tip, arp_hdr->arp_data.arp_sip);
					
				}

			} else if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {

#if ENABLE_KNI
				unsigned num = rte_kni_tx_burst(kni, mbufs, num_recvd);
				rte_kni_handle_request(kni);
				
				//printf(" eth: ehdr->ether_type --> %x, num: %d\n", ntohs(ehdr->ether_type), num);
#endif
				
			} else {
				
				struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
				if (ip_hdr->next_proto_id == IPPROTO_UDP) {

					struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *) ((unsigned char *) ip_hdr + sizeof(struct rte_ipv4_hdr));
 	
					if (UDP_PORT == ntohs(udp_hdr->src_port)) {

						
						printf("Received packet: ");
												
						uint16_t length = ntohs(udp_hdr->dgram_len);
						*((char *)udp_hdr + length) = '\0';
						
						struct in_addr addr;
						addr.s_addr = ip_hdr->src_addr;
						printf(" src: %s:%d", inet_ntoa(addr), ntohs(udp_hdr->src_port));

						addr.s_addr = ip_hdr->dst_addr;
						printf(", dst: %s:%d --> length:%d, %s\n", inet_ntoa(addr), ntohs(udp_hdr->dst_port), length, (char *)(udp_hdr+1));
				
						do_send_udp(pktmbuf_pool, (unsigned char *)(udp_hdr+1), length-8);

					}
					
					//rte_pktmbuf_free(mbufs[i]);

					//continue;
				}
#if ENABLE_KNI
				else {

					unsigned num = rte_kni_tx_burst(kni, mbufs, num_recvd);
					rte_kni_handle_request(kni);
					
					printf(" eth: ip_hdr->next_proto_id --> %d, num: %d\n", ip_hdr->next_proto_id, num);
				}
#endif
			}
		}
		burst_free_mbufs(mbufs, num_recvd); 


		
    }

    return 0;
}
