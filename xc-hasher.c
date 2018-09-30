#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/net_namespace.h>
#include <linux/proc_fs.h>	/* Necessary because we use the proc fs */
#include <linux/sched.h>
#include <asm/uaccess.h>	/* for copy_from_user */
#include <linux/slab.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define MAX_ARRAY_SIZE 10


char *msg;
long devider = 1;

static ssize_t read_proc(struct file *filp, char *buf, size_t count, loff_t *offp )
{
	int len = 0;
	if (*offp > 0 )
		return 0;

	len = sprintf(msg, "%ld\n", devider);
	if (copy_to_user(buf, msg, len))
		return -EFAULT;
	*offp = len;
	return len;
}

static ssize_t write_proc(struct file *filp, const char *buf, size_t count, loff_t *offp)
{
	if (count > MAX_ARRAY_SIZE)
		return count;
	copy_from_user(msg, buf, count);
	
	char nMsg[count];
	int success;
       	snprintf(nMsg, count, "%s", msg); 	
	success = kstrtol(nMsg, 0, &devider);
	if (success) {
		printk(KERN_ERR "xc-hasher: hash value should be a number, %s\n", nMsg);
	}
	else {
		printk(KERN_INFO "xc-hasher: new value  %ld\n", devider);
	}
	return count;
}

struct file_operations proc_fops = {
	read: read_proc,
	write: write_proc
};

void create_new_proc_entry(void)  //use of void for no arguments is compulsory now
{
	proc_create("xc_hasher",0,NULL,&proc_fops);
	msg = kmalloc(MAX_ARRAY_SIZE * sizeof(char), GFP_KERNEL);

}



/* This function to be called by hook. */
static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state )
{
    u8 digit;
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);    

    digit = devider;
    if (skb->mark == 0xff) { 
	if (ip_header->protocol == 17) { 
        	udp_header = (struct udphdr *)skb_transport_header(skb) + sizeof(struct iphdr);
		digit = (ip_header->saddr + ip_header->daddr + udp_header->dest + udp_header->source) % devider;
	}else if(ip_header->protocol == 6) {
        	tcp_header = (struct tcphdr *)skb_transport_header(skb) + sizeof(struct iphdr);
		digit = (ip_header->saddr + ip_header->daddr + tcp_header->dest + tcp_header->source) % devider;
	}

	if (digit == 0) 
		digit = devider;
	
	skb->mark = digit;
        
	printk(KERN_INFO "xc-hasher: snat packet (saddr:%d.%d.%d.%d, daddr:%d.%d.%d.%d, sport:%d, dport:%d, mark:%x) \n", 
			NIPQUAD(ip_header->saddr), 
			NIPQUAD(ip_header->daddr),
			udp_header->source,	
		        udp_header->dest,
			skb->mark);
    }
    
    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook       = hook_func,
    .hooknum    = NF_INET_PRE_ROUTING, /* NF_IP_LOCAL_IN */
    .pf         = PF_INET,
    //.priority   = NF_IP_PRI_FIRST,
    .priority   = -200,
};

static int __init init_nf(void)
{
    
    printk(KERN_INFO "Register XCloudNetwork hasher module.\n");
    nf_register_net_hook(&init_net, &nfho);
    create_new_proc_entry();
    return 0;
}

static void __exit exit_nf(void)
{

    printk(KERN_INFO "Unregister XCloudNetworks hasher module.\n");
    nf_unregister_net_hook(&init_net, &nfho); 
    remove_proc_entry("xc_hasher",NULL);
    kfree(msg);
}

module_init(init_nf);
module_exit(exit_nf);
MODULE_LICENSE("GPL");
