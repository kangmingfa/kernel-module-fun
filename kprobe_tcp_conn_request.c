#include <linux/module.h>             // included for all kernel modules
#include <linux/kernel.h>             // included for KERN_INFO
#include <linux/init.h>               // included for __init and __exit macros
#include <linux/skbuff.h>             // struct sk_buff
#include <linux/ip.h>                 // struct iphdr
#include <linux/tcp.h>                // struct tcphdr

#include <linux/kprobes.h>            // for bpf kprobe/kretprobe

#include "bpf_tracing.h"


#define MAX_ARGLEN 256
#define MAX_ARGS 20
#define NARGS 6
#define NULL ((void *)0)
typedef unsigned long args_t;


#define MAX_SYMBOL_LEN    64
static char symbol_tcp_conn_request[MAX_SYMBOL_LEN] = "tcp_conn_request";

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp_request = {
    .symbol_name    = symbol_tcp_conn_request,
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int kp_request_prehandler(struct kprobe *p, struct pt_regs *ctx)
{
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *tcph;

    skb = (struct sk_buff *)PT_REGS_PARM4(ctx); // 获取 skb 参数
    iph = (struct iphdr *)(skb->head + skb->network_header);
    tcph = (struct tcphdr *)((unsigned char *)iph + iph->ihl*4);

    pr_info("[tcp_conn_request] [%pI4:%d -> %pI4:%d]\n",
        &iph->saddr, ntohs(tcph->source),
        &iph->daddr, ntohs(tcph->dest));

    return 0;
}


/*
 *  * fault_handler: this is called if an exception is generated for any
 *   * instruction within the pre- or post-handler, or when Kprobes
 *    * single-steps the probed instruction.
 *     */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    pr_info("kprobe fault_handler(%s): p->addr = 0x%p, trap #%d\n", p->symbol_name, p->addr, trapnr);
    /* Return 0 because we don't handle the fault. */
    return 0;
}

static int __init probe_init(void)
{
    int ret;
    kp_request.pre_handler = kp_request_prehandler;
    kp_request.fault_handler = handler_fault;

    ret = register_kprobe(&kp_request);
    if (ret < 0) {
        pr_err("[x] register kprobe tcp_conn_request failed, returned %d\n", ret);
        return ret;
    }

    pr_info("[+] Planted kprobe tcp_conn_request at %p\n", kp_request.addr);
    return 0;
}

static void __exit probe_exit(void)
{
    pr_info("[-] kprobe at %p unregistered\n", kp_request.addr);

    unregister_kprobe(&kp_request);
}

module_init(probe_init);
module_exit(probe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HF");
MODULE_DESCRIPTION("A kprobe_tcp_conn_request Module");
