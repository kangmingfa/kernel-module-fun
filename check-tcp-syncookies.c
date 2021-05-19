#include <linux/module.h>           // included for all kernel modules
#include <linux/kernel.h>           // included for KERN_INFO
#include <linux/init.h>             // included for __init and __exit macros
#include <linux/netfilter.h>        // struct nf_hook_ops
#include <linux/netfilter_ipv4.h>   // NF_IP_PRE_ROUTING
#include <linux/skbuff.h>           // struct sk_buff
#include <linux/ip.h>               // struct iphdr
#include <linux/tcp.h>              // struct tcphdr
#include <net/net_namespace.h>      // struct net
#include <net/tcp.h>                // __cookie_v4_check

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Asphaltt");
MODULE_DESCRIPTION("A check_tcp_syncookies Module");


unsigned int check_tcp_syncookies_hook(void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
  __be32 saddr, daddr;
  __u32 mss;

  struct ethhdr *ethhdr;
  struct iphdr *iphdr;
  struct tcphdr *tcphdr;

  ethhdr = (struct ethhdr *)skb_mac_header(skb);
  if (ethhdr->h_proto != ntohs(ETH_P_IP))
    return NF_ACCEPT;

  iphdr = (struct iphdr *)skb_network_header(skb);
  saddr = iphdr->saddr;
  daddr = iphdr->daddr;
  if (iphdr->protocol != IPPROTO_TCP)
    return NF_ACCEPT;

  tcphdr = (struct tcphdr *)skb_transport_header(skb);
  if (tcphdr->ack && !(tcphdr->fin|tcphdr->syn|tcphdr->psh)) {
    mss = __cookie_v4_check(iphdr, tcphdr, ntohl(tcphdr->ack_seq) - 1);
    if (mss != 0)
      printk(KERN_INFO "[check_tcp_syncookies] [%pI4:%d -> %pI4:%d] mss:%d\n",
        (unsigned char *)(&saddr), ntohs(tcphdr->source),
        (unsigned char *)(&daddr), ntohs(tcphdr->dest), mss);
  }

  return NF_ACCEPT;
}

static struct nf_hook_ops nfhook;    //net filter hook option struct

static int init_check_tcp_syncookies_hook(struct net *net)
{
  nfhook.hook = check_tcp_syncookies_hook;
  nfhook.hooknum = NF_INET_PRE_ROUTING;
  nfhook.pf = PF_INET;
  nfhook.priority = NF_IP_PRI_FIRST;

  nf_register_net_hook(net, &nfhook);
  return 0;
}

static int check_tcp_syncookies_net_init(struct net *net)
{
    printk(KERN_INFO "[+] Register check_tcp_syncookies module!\n");
    init_check_tcp_syncookies_hook(net);
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void check_tcp_syncookies_net_exit(struct net *net)
{
  nf_unregister_net_hook(net, &nfhook);
  printk(KERN_INFO "[-] Cleaning up check_tcp_syncookies module.\n");
}

static int check_tcp_syncookies_init(void)
{
  return check_tcp_syncookies_net_init(&init_net);
}

static void check_tcp_syncookies_exit(void)
{
  check_tcp_syncookies_net_exit(&init_net);
}

module_init(check_tcp_syncookies_init);
module_exit(check_tcp_syncookies_exit);

