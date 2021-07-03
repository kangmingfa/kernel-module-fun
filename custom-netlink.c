#include <linux/module.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Asphaltt");
MODULE_DESCRIPTION("A custom_netlink Module");

#define NETLINK_CUSTOM 31

struct sock *nl_sk = NULL;

enum
{
    nlresp_result_unspec,
    nlresp_result_ok,
    nlresp_result_invalid
};

typedef struct
{
    __u32 result;
    unsigned char data[0];
} custom_nl_resp_data_t;

static int custom_nl_send_msg(struct nlmsghdr *nlh, __u32 result, const unsigned char *data, __u32 data_size)
{
    custom_nl_resp_data_t *resp;
    struct nlmsghdr *nlh_resp;
    struct sk_buff *skb;
    int pid = nlh->nlmsg_pid, res = -1;
    const unsigned char *resp_msg = "Echo from kernel: ";

    if (data_size != 0)
        data_size += 18;
    data_size += 4;
    resp = kzalloc(data_size, GFP_KERNEL);
    if (!resp)
        return res;
    if (data_size != 4)
    {
        memcpy(resp->data, resp_msg, 18);
        memcpy(resp->data + 18, data, data_size - 4);
    }
    resp->result = result;

    skb = nlmsg_new(data_size, GFP_KERNEL);
    if (!skb)
        goto out;

    nlh_resp = nlmsg_put(skb, pid, nlh->nlmsg_seq, NLMSG_DONE, data_size, 0);
    memcpy(NLMSG_DATA(nlh_resp), resp, data_size);
    res = nlmsg_unicast(nl_sk, skb, pid);

out:
    kfree(resp);
    return res;
}

static void custom_nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    unsigned char *nl_data;
    unsigned char *msg;
    __u32 msg_size;

    nlh = nlmsg_hdr(skb);
    nl_data = (unsigned char *)NLMSG_DATA(nlh);
    msg_size = *(__u32 *)nl_data;
    if (msg_size > 1024)
    {
        custom_nl_send_msg(nlh, nlresp_result_invalid, NULL, 0);
        return;
    }

    msg = nl_data + 4;
    msg[msg_size - 1] = '\0';
    printk(KERN_INFO "[Y] [custom netlink] receive msg from user: %s\n", msg);

    custom_nl_send_msg(nlh, nlresp_result_ok, msg, msg_size);
}

static int __init custom_nl_init(void)
{
    //This is for 3.6 kernels and above.
    struct netlink_kernel_cfg cfg = {
        .input = custom_nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_CUSTOM, &cfg);
    //nl_sk = netlink_kernel_create(&init_net, NETLINK_CUSTOM, 0, custom_nl_recv_msg,NULL,THIS_MODULE);
    if (!nl_sk)
    {
        printk(KERN_ALERT "[x] [custom netlink] failed to create netlink socket.\n");
        return -10;
    }

    printk(KERN_INFO "[+] registered custom_netlink module!\n");
    return 0;
}

static void __exit custom_nl_exit(void)
{

    netlink_kernel_release(nl_sk);
    printk(KERN_INFO "[-] unregistered custom_netlink module.\n");
}

module_init(custom_nl_init);
module_exit(custom_nl_exit);
