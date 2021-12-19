#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>               // included for all kernel modules
#include <linux/kernel.h>               // included for KERN_INFO
#include <linux/init.h>                 // included for __init and __exit macros
#include <linux/filter.h>               // struct bpf_prog
#include <linux/skbuff.h>               // struct sk_buff
#include <linux/netfilter.h>            // struct nf_hook_ops
#include <linux/ip.h>                   // struct iphdr
#include <uapi/linux/netfilter_ipv4.h>  // NF_HOOK

#include <linux/netfilter/xt_bpf.h>

MODULE_AUTHOR("Leon Huayra <hffilwlqm@gmail.com>");
MODULE_DESCRIPTION("run an eBPF program in a custom netfilter hook");
MODULE_LICENSE("GPL");

static char *bpf_path = "";
module_param(bpf_path, charp, S_IRUGO);

static struct bpf_prog *bp = NULL;

static int __bpf_check_path(struct bpf_prog **ret) {
  if (strnlen(bpf_path, XT_BPF_PATH_MAX) == XT_BPF_PATH_MAX) return -EINVAL;

  *ret = bpf_prog_get_type_path(bpf_path, BPF_PROG_TYPE_SOCKET_FILTER);
  return PTR_ERR_OR_ZERO(*ret);
}

static bool run_bpf_prog(struct sk_buff *skb) {
  return !!bpf_prog_run_save_cb(bp, skb);
}

unsigned int run_bpf_prog_hook(void *priv, struct sk_buff *skb,
                               const struct nf_hook_state *state) {
  __be32 saddr, daddr;

  struct iphdr *iphdr;

  if (!run_bpf_prog(skb)) return NF_ACCEPT;

  iphdr = (struct iphdr *)skb_network_header(skb);
  saddr = iphdr->saddr;
  daddr = iphdr->daddr;
  printk(KERN_INFO "[run_bpf_prog] %pI4 -> %pI4\n", &saddr, &daddr);
  return NF_ACCEPT;
}

static struct nf_hook_ops nfhook;  // net filter hook option struct

static int init_run_bpf_prog_netfilter_hook(struct net *net) {
  nfhook.hook = run_bpf_prog_hook;
  nfhook.hooknum = NF_INET_LOCAL_OUT;
  nfhook.pf = PF_INET;
  nfhook.priority = NF_IP_PRI_FIRST;

  nf_register_net_hook(net, &nfhook);
  return 0;
}

static int run_bpf_prog_net_init(struct net *net) {
  if (__bpf_check_path(&bp) != 0) {
    printk(KERN_ERR "[x] Register run_bpf_prog module failed\n");
    return 0;
  }

  printk(KERN_INFO "[+] bpf prog path: %s\n", bpf_path);
  init_run_bpf_prog_netfilter_hook(net);
  printk(KERN_INFO "[+] Register run_bpf_prog module!\n");
  return 0;  // Non-zero return means that the module couldn't be loaded.
}

static void run_bpf_prog_net_exit(struct net *net) {
  nf_unregister_net_hook(net, &nfhook);
  printk(KERN_INFO "[-] Cleaning up run_bpf_prog module.\n");
}

static int run_bpf_prog_init(void) { return run_bpf_prog_net_init(&init_net); }

static void run_bpf_prog_exit(void) { run_bpf_prog_net_exit(&init_net); }

module_init(run_bpf_prog_init);
module_exit(run_bpf_prog_exit);