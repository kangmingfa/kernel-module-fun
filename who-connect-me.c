#include <linux/module.h>      // included for all kernel modules
#include <linux/kernel.h>      // included for KERN_INFO
#include <linux/init.h>        // included for __init and __exit macros
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/vmalloc.h>
#include <linux/skbuff.h>      // skb
#include <linux/socket.h>      // PF_INET
#include <linux/ip.h>          // iphdr
#include <net/net_namespace.h> // net

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Asphaltt");
MODULE_DESCRIPTION("A who-connect-me Module");

enum {
    NF_IP_PRE_ROUTING,
    NF_IP_LOCAL_IN,
    NF_IP_FORWARD,
    NF_IP_LOCAL_OUT,
    NF_IP_POST_ROUTING,
    NF_IP_NUMHOOKS
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

unsigned int who_connect_me_hook(void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
  __be32 saddr, daddr;

  struct iphdr *iphdr;
  struct tcphdr *tcphdr;

  iphdr = (struct iphdr *)skb_network_header(skb);
  saddr = iphdr->saddr;
  daddr = iphdr->daddr;
  if (iphdr->protocol == IPPROTO_TCP) {
      tcphdr = (struct tcphdr *)skb_transport_header(skb);
      if (tcphdr->syn) {
      printk(KERN_INFO "[who_connect_me] [%pI4:%d -> %pI4:%d]\n",
          (unsigned char *)(&saddr), ntohs(tcphdr->source),
          (unsigned char *)(&daddr), ntohs(tcphdr->dest));
      }
  }
  return NF_ACCEPT;
}

static struct nf_hook_ops nfhook;    //net filter hook option struct

static int init_who_connect_me_netfilter_hook(struct net *net)
{
  nfhook.hook = who_connect_me_hook;
  nfhook.hooknum = NF_IP_PRE_ROUTING;
  nfhook.pf = PF_INET;
  nfhook.priority = NF_IP_PRI_FIRST;

  nf_register_net_hook(net, &nfhook);
  return 0;
}

static int who_connect_me_net_init(struct net *net)
{
    printk(KERN_INFO "[+] Register who_connect_me module!\n");
    init_who_connect_me_netfilter_hook(net);
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void who_connect_me_net_exit(struct net *net)
{
  nf_unregister_net_hook(net, &nfhook);
  printk(KERN_INFO "[-] Cleaning up who_connect_me module.\n");
}

static int who_connect_me_init(void)
{
  return who_connect_me_net_init(&init_net);
}

static void who_connect_me_exit(void)
{
  who_connect_me_net_exit(&init_net);
}

module_init(who_connect_me_init);
module_exit(who_connect_me_exit);

