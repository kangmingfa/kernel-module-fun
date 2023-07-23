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
MODULE_AUTHOR("Test");
MODULE_DESCRIPTION("A add-tcp-options Module");

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

static char my_buf[64];
static char option_tm[8] = {0xfd, 0x08, 0x03, 0x48, 0x5a, 0x5a, 0x5a, 0x5b};   //the tcp option that will be appended on tcp header 

void add_tcp_options_fun(struct sk_buff *skb,  struct iphdr * iph, struct tcphdr *tcph) {
    int hdr_len;
    char *d;
    int i;
    int datalen;


    /*
    '''
    postroutig skb : iph tcph data

    '''
    */
    if( skb->data[0]==0x45 && iph->protocol==0x06 ) {  //ipv4 and tcp packet
        hdr_len = (iph->ihl + tcph->doff)*4;    //original header length, ip header + tcp header
	    memcpy(my_buf, skb->data, 64 );	        //copy original header to tmp buf; copy 64B to tmp buf; 64B is bigger than hdr_len;
		memcpy(my_buf+hdr_len, option_tm, 8);   //append new tcp option on original header to generate a new header;
	    d = my_buf;
        printk(KERN_INFO"print the new header \n");
		for(i=0; i<(hdr_len+8); i++) {          //print the new header
			printk("%02x", (*d)&0xff);
			d++;
		}
        skb_pull( skb, hdr_len );               //remove original header
        skb_push( skb, hdr_len+8 );             //add new header
		memcpy(skb->data, my_buf, hdr_len+8 );	//copy new header into skb;

        //update header offset in skb
        skb->transport_header = skb->transport_header -8 ;
        skb->network_header   = skb->network_header   -8 ;
        //update ip header and checksum
        iph = ip_hdr(skb);  //update iph point to new ip header
        iph->tot_len = htons(skb->len);
        iph->check = 0;     //re-calculate ip checksum
        iph->check = ip_fast_csum( iph, iph->ihl);
        //update tcp header and checksum
	    tcph =  (struct tcphdr *) skb_transport_header(skb); //update tcph point to new tcp header
		printk(KERN_INFO"old tcp_checksum=%x \n", tcph->check );
	    tcph->doff = tcph->doff+2;
    	tcph->check = 0;
		datalen = (skb->len - iph->ihl*4);  //tcp segment length
        ////re-calculate tcp checksum
        //tcp checksum = tcp segment checksum and tcp pseudo-header checksum
        tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                        datalen, iph->protocol,
                                        csum_partial((char *)tcph, datalen, 0));
        skb->ip_summed = CHECKSUM_UNNECESSARY;  //the reason is not clear, but without it, it seems the hardware will re-calcuate the checksum
        printk(KERN_INFO"new tcp_checksum=%x \n", tcph->check    );
    }
}

unsigned int add_tcp_options_hook(void *priv,
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
      if (tcphdr->syn != 1 && ntohs(tcphdr->source) == 8888) {
        add_tcp_options_fun(skb,iphdr,tcphdr);
        printk(KERN_INFO "[add_tcp_options] [%pI4:%d -> %pI4:%d]\n",
            (unsigned char *)(&saddr), ntohs(tcphdr->source),
            (unsigned char *)(&daddr), ntohs(tcphdr->dest));
        return NF_ACCEPT;
      }
  }
  return NF_ACCEPT;
}

static struct nf_hook_ops nfhook;    //net filter hook option struct

static int init_add_tcp_options_netfilter_hook(struct net *net)
{
  nfhook.hook = add_tcp_options_hook;
  nfhook.hooknum = NF_IP_POST_ROUTING;
  nfhook.pf = PF_INET;
  nfhook.priority = NF_IP_PRI_FIRST;

  nf_register_net_hook(net, &nfhook);
  return 0;
}

static int add_tcp_options_net_init(struct net *net)
{
    printk(KERN_INFO "[+] Register add_tcp_options module!\n");
    init_add_tcp_options_netfilter_hook(net);
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void add_tcp_options_net_exit(struct net *net)
{
  nf_unregister_net_hook(net, &nfhook);
  printk(KERN_INFO "[-] Cleaning up add_tcp_options module.\n");
}

static int add_tcp_options_init(void)
{
  return add_tcp_options_net_init(&init_net);
}

static void add_tcp_options_exit(void)
{
  add_tcp_options_net_exit(&init_net);
}

module_init(add_tcp_options_init);
module_exit(add_tcp_options_exit);
