#include <linux/module.h>       // included for all kernel modules
#include <linux/kernel.h>       // included for KERN_INFO
#include <linux/init.h>         // included for __init and __exit macros
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>    // net_device
#include <linux/vmalloc.h>
#include <linux/skbuff.h>       // skb
#include <linux/socket.h>       // PF_INET
#include <linux/ip.h>           // iphdr
#include <net/arp.h>            // arptable
#include <net/neighbour.h>      // neighbour
#include <net/net_namespace.h>  // net

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Asphaltt");
MODULE_DESCRIPTION("A add_arp_records Module");

enum {
  NF_IP_PRE_ROUTING,
    NF_IP_LOCAL_IN,
    NF_IP_FORWARD,
    NF_IP_LOCAL_OUT,
    NF_IP_POST_ROUTING,
    NF_IP_NUMHOOKS
};

enum {
  NF_BR_PRE_ROUTING,
  NF_BR_LOCAL_IN,
  NF_BR_FORWARD,
  NF_BR_LOCAL_OUT,
  NF_BR_POST_ROUTING,
  NF_BR_BROUTING,
  NF_BR_NUMHOOKS,
};

enum nf_br_hook_priorities {
  NF_BR_PRI_FIRST = INT_MIN,
  NF_BR_PRI_NAT_DST_BRIDGED = -300,
  NF_BR_PRI_FILTER_BRIDGED = -200,
  NF_BR_PRI_BRNF = 0,
  NF_BR_PRI_NAT_DST_OTHER = 100,
  NF_BR_PRI_FILTER_OTHER = 200,
  NF_BR_PRI_NAT_SRC = 300,
  NF_BR_PRI_LAST = INT_MAX,
};


struct tcphdr {
  __be16  source;
  __be16  dest;
  __be32  seq;
  __be32  ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
  __u16 res1:4,
    doff:4,
    fin:1,
    syn:1,
    rst:1,
    psh:1,
    ack:1,
    urg:1,
    ece:1,
    cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
  __u16 doff:4,
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
#error  "Adjust your <asm/byteorder.h> defines"
#endif
  __be16  window;
  __sum16 check;
  __be16  urg_ptr;
};

unsigned int add_arp_records_hook(void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
  __be32 saddr, daddr;

  struct net_device *dev, *brtproxy;
  struct ethhdr *ethhdr;
  struct iphdr *iphdr;
  struct tcphdr *tcphdr;
  struct neighbour *nei;

  dev = (struct net_device *)skb->dev;
  brtproxy = dev_get_by_name(dev->nd_net.net, "brtproxy");
  if (!brtproxy) {
      printk(KERN_INFO "[add_arp_records] cannot find device[brtproxy]\n");
      return 0;
  }

  ethhdr = (struct ethhdr *)skb_mac_header(skb);
  if (ethhdr->h_proto == ntohs(ETH_P_IP)) {
    iphdr = (struct iphdr *)skb_network_header(skb);
    saddr = iphdr->saddr;
    daddr = iphdr->daddr;
    if (iphdr->protocol == IPPROTO_TCP) {
      tcphdr = (struct tcphdr *)skb_transport_header(skb);
      if (tcphdr->syn) {
        // arp record for source ip
        saddr = iphdr->saddr;
        nei = neigh_lookup(&arp_tbl, &saddr, brtproxy);
        if (nei == NULL) {
          nei = __neigh_create(&arp_tbl, &saddr, brtproxy, false);
          memcpy(nei->ha, ethhdr->h_source, ETH_ALEN);
        }
        neigh_update(nei, (unsigned char *)nei->ha, NUD_PERMANENT, NEIGH_UPDATE_F_OVERRIDE, 0);
        printk(KERN_INFO "[add_arp_records] [sip->smac] arp record for interface[brtproxy] [%2x:%2x:%2x:%2x:%2x:%2x -> %pI4]\n",
          nei->ha[0], nei->ha[1], nei->ha[2], nei->ha[3], nei->ha[4], nei->ha[5],
          (unsigned char *)(&saddr));

        // arp record for dest ip
        daddr = iphdr->daddr;
        nei = NULL;
        nei = neigh_lookup(&arp_tbl, &daddr, brtproxy);
        if (nei == NULL) {
          nei = __neigh_create(&arp_tbl, &daddr, brtproxy, false);
          memcpy(nei->ha, ethhdr->h_dest, ETH_ALEN);
        }
        neigh_update(nei, (unsigned char *)nei->ha, NUD_PERMANENT, NEIGH_UPDATE_F_OVERRIDE, 0);
        printk(KERN_INFO "[add_arp_records] [dip->dmac] arp record for interface[brtproxy] [%2x:%2x:%2x:%2x:%2x:%2x -> %pI4]\n",
          nei->ha[0], nei->ha[1], nei->ha[2], nei->ha[3], nei->ha[4], nei->ha[5],
          (unsigned char *)(&daddr));

        printk(KERN_INFO "[add_arp_records] [%d:%s] [%2x:%2x:%2x:%2x:%2x:%2x -> %2x:%2x:%2x:%2x:%2x:%2x] [%pI4:%d -> %pI4:%d]\n",
          dev->ifindex, dev->name,
          ethhdr->h_source[0], ethhdr->h_source[1], ethhdr->h_source[2], ethhdr->h_source[3], ethhdr->h_source[4], ethhdr->h_source[5],
          ethhdr->h_dest[0], ethhdr->h_dest[1], ethhdr->h_dest[2], ethhdr->h_dest[3], ethhdr->h_dest[4], ethhdr->h_dest[5],
          (unsigned char *)(&saddr), ntohs(tcphdr->source),
          (unsigned char *)(&daddr), ntohs(tcphdr->dest));
      }
    }
  }
  return NF_ACCEPT;
}

static struct nf_hook_ops nfhook;    //net filter hook option struct

static int init_add_arp_records_netfilter_hook(struct net *net)
{
  nfhook.hook = add_arp_records_hook;
  nfhook.hooknum = NF_BR_PRE_ROUTING;
  nfhook.pf = PF_BRIDGE;
  nfhook.priority = NF_BR_PRI_FIRST;

  nf_register_net_hook(net, &nfhook);
  return 0;
}

static int add_arp_records_net_init(struct net *net)
{
    printk(KERN_INFO "[+] Register add_arp_records module!\n");
    init_add_arp_records_netfilter_hook(net);
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void add_arp_records_net_exit(struct net *net)
{
  nf_unregister_net_hook(net, &nfhook);
  printk(KERN_INFO "[-] Cleaning up add_arp_records module.\n");
}

static int add_arp_records_init(void)
{
  return add_arp_records_net_init(&init_net);
}

static void add_arp_records_exit(void)
{
  add_arp_records_net_exit(&init_net);
}

module_init(add_arp_records_init);
module_exit(add_arp_records_exit);
