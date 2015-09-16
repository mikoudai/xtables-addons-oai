/*
   GTPu klm for Linux/iptables

   Copyright (c) 2010-2011 Polaris Networks
   Author: Pradip Biswas <pradip_biswas@polarisnetworks.net>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation.

*/

#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/route.h>
#include <linux/time.h>
#include <linux/version.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/inet_sock.h>
#include <net/route.h>
#include <net/addrconf.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/kthread.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/delay.h>
#include <linux/inet.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/uio.h>
#endif
// CONNMARK
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_connmark.h>
#if defined(CONFIG_IP6_NF_IPTABLES) || defined(CONFIG_IP6_NF_IPTABLES_MODULE)
#  define GTPUSP_WITH_IPV6 1
#else
#  define GTPUSP_WITH_IPV6 0
#endif
#include "xt_GTPUSP.h"

#define INT_MODULE_PARM(n, v) static int n = v; module_param(n, int, 0444)
#define STRING_MODULE_PARM(s, v) static char* s = v; module_param(s, charp, 0000);

#define FLAG_GTPV1U_KERNEL_THREAD_SOCK_NO_WAIT 1
//-----------------------------------------------------------------------------

static void  gtpusp_tg4_add (
  struct sk_buff *old_skb_pP,
  const struct xt_action_param *par_pP);

#if GTPUSP_WITH_IPV6
static void gtpusp_tg6_add (
  struct sk_buff *old_skb_pP,
  const struct xt_action_param *par_pP);

static unsigned int gtpusp_tg6 (
  struct sk_buff *skb_pP,
  const struct xt_action_param *par_pP);
#endif

static unsigned int gtpusp_tg4 (
  struct sk_buff *skb_pP,
  const struct xt_action_param *par_pP);

static int __init gtpusp_tg_init (
  void);

static void __exit gtpusp_tg_exit (
  void);

//-----------------------------------------------------------------------------
#define MODULE_NAME "GTPUSP"
MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("Pradip Biswas <pradip_biswas@polarisnetworks.net>");
MODULE_DESCRIPTION ("GTPu Data Path extension on netfilter modified by EURECOM (www.eurecom.fr) Lionel GAUTHIER");
//-----------------------------------------------------------------------------
static struct xt_target                 gtpusp_tg_reg[] __read_mostly = {
  {
   .name = MODULE_NAME,
   .revision = 0,
   .family = NFPROTO_IPV4,
   .hooks = (1 << NF_INET_POST_ROUTING) | (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) | (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_POST_ROUTING),
   .table = "mangle",
   .target = gtpusp_tg4,
   .targetsize = sizeof (struct xt_gtpusp_target_info),
   .me = THIS_MODULE,
   },
#ifdef GTPUSP_WITH_IPV6
  {
   .name = MODULE_NAME,
   .revision = 0,
   .family = NFPROTO_IPV6,
   .hooks = (1 << NF_INET_POST_ROUTING) | (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) | (1 << NF_INET_LOCAL_OUT) | (1 << NF_INET_POST_ROUTING),
   .table = "mangle",
   .target = gtpusp_tg6,
   .targetsize = sizeof (struct xt_gtpusp_target_info),
   .me = THIS_MODULE,
   },
#endif
};

#define GTP_ECHO_REQ           1
#define GTP_ECHO_RSP           2
#define GTP_ERROR_INDICATION   26
#define GTP_GPDU               255

typedef struct gtpv1u_msg_s {
  unsigned char                           version;
  unsigned char                           protocol_type;
  unsigned char                           ext_hdr_flag;
  unsigned char                           seq_num_flag;
  u_int16_t                               npdu_num_flag;
  u_int32_t                               msg_type;
  u_int16_t                               msg_len;
  u_int32_t                               teid;
  u_int16_t                               seq_num;
  unsigned char                           npdu_num;
  unsigned char                           next_ext_hdr_type;
  u_int32_t                               msg_buf_len;
  u_int32_t                               msg_buf_offset;
  struct gtpv1u_msg_s                    *next;
} gtpv1u_msg_t;

struct gtpuhdr {
  char                                    flags;
  unsigned char                           msgtype;
  u_int16_t                               length;
  u_int32_t                               tunid;
};

typedef struct gtpusp_data_priv_s {
  struct sockaddr_in                      addr;
  struct sockaddr_in                      addr_send;
  struct udp_port_cfg                     udp_conf;
  struct socket                          *sock;
#define GTPUSP_GTP_RX_BUFFER_SIZE       8192
#define GTPUSP_GTP_TX_BUFFER_SIZE       1024
  //unsigned char                           gtp_rx_buf[GTPUSP_GTP_RX_BUFFER_SIZE];
  unsigned char                           gtp_tx_buf[GTPUSP_GTP_TX_BUFFER_SIZE];
} gtpusp_data_priv_t;

//-----------------------------------------------------------------------------
#define GTPU_HDR_PNBIT 1
#define GTPU_HDR_SBIT 1 << 1
#define GTPU_HDR_EBIT 1 << 2
#define GTPU_ANY_EXT_HDR_BIT (GTPU_HDR_PNBIT | GTPU_HDR_SBIT | GTPU_HDR_EBIT)

#define GTPU_FAILURE 1
#define GTPU_SUCCESS !GTPU_FAILURE
#define GTPUSP_2_PRINT_BUFFER_LEN 8192

#define IP_MORE_FRAGMENTS 0x2000
#define NIPADDR(addr) \
  (uint8_t)(addr & 0x000000FF), \
  (uint8_t)((addr & 0x0000FF00) >> 8), \
  (uint8_t)((addr & 0x00FF0000) >> 16), \
  (uint8_t)((addr & 0xFF000000) >> 24)
//-----------------------------------------------------------------------------
gtpusp_data_priv_t                           gtpusp_data;
static char                             gtpusp_print_buffer[GTPUSP_2_PRINT_BUFFER_LEN];
INT_MODULE_PARM (gtpu_sgw_port, 2152);
MODULE_PARM_DESC (gtpu_sgw_port, "UDP port number for S1U interface (s-GW side)");
INT_MODULE_PARM (gtpu_enb_port, 2153);
MODULE_PARM_DESC (gtpu_enb_port, "UDP port number for S1U interface (eNB side)");
STRING_MODULE_PARM (sgw_addr, "127.0.0.1");
MODULE_PARM_DESC (sgw_addr, "IPv4 address of the S1U IP interface");


//-----------------------------------------------------------------------------
void
_gtpusp_print_hex_octets(const unsigned char const * data_pP, const unsigned short sizeP)
{

  unsigned long octet_index = 0;
  unsigned long buffer_marker = 0;
  unsigned char aindex;
  struct timeval tv;
  char timeofday[64];
  unsigned int h,m,s;

  if (data_pP == NULL) {
    return;
  }

  if (sizeP > 2000) {
    return;
  }

  do_gettimeofday(&tv);
  h = (tv.tv_sec/3600) % 24;
  m = (tv.tv_sec / 60) % 60;
  s = tv.tv_sec % 60;
  snprintf(timeofday, 64, "%02d:%02d:%02d.%06ld", h,m,s,tv.tv_usec);

  buffer_marker+=snprintf(&gtpusp_print_buffer[buffer_marker], GTPUSP_2_PRINT_BUFFER_LEN - buffer_marker,"%s------+-------------------------------------------------+\n",timeofday);
  buffer_marker+=snprintf(&gtpusp_print_buffer[buffer_marker], GTPUSP_2_PRINT_BUFFER_LEN - buffer_marker,"%s      |  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f |\n",timeofday);
  buffer_marker+=snprintf(&gtpusp_print_buffer[buffer_marker], GTPUSP_2_PRINT_BUFFER_LEN - buffer_marker,"%s------+-------------------------------------------------+\n",timeofday);
  pr_info("%s",gtpusp_print_buffer);
  buffer_marker = 0;

  for (octet_index = 0; octet_index < sizeP; octet_index++) {
    if ((octet_index % 16) == 0) {
      if (octet_index != 0) {
        buffer_marker+=snprintf(&gtpusp_print_buffer[buffer_marker], GTPUSP_2_PRINT_BUFFER_LEN - buffer_marker, " |\n");
        pr_info("%s",gtpusp_print_buffer);
        buffer_marker = 0;
      }

      buffer_marker+=snprintf(&gtpusp_print_buffer[buffer_marker], GTPUSP_2_PRINT_BUFFER_LEN - buffer_marker, "%s %04ld |",timeofday, octet_index);
    }

    /*
     * Print every single octet in hexadecimal form
     */
    buffer_marker+=snprintf(&gtpusp_print_buffer[buffer_marker], GTPUSP_2_PRINT_BUFFER_LEN - buffer_marker, " %02x", data_pP[octet_index]);
    /*
     * Align newline and pipes according to the octets in groups of 2
     */
  }

  /*
   * Append enough spaces and put final pipe
   */
  for (aindex = octet_index; aindex < 16; ++aindex)
    buffer_marker+=snprintf(&gtpusp_print_buffer[buffer_marker], GTPUSP_2_PRINT_BUFFER_LEN - buffer_marker, "   ");

  //SGI_IF_DEBUG("   ");
  buffer_marker+=snprintf(&gtpusp_print_buffer[buffer_marker], GTPUSP_2_PRINT_BUFFER_LEN - buffer_marker, " |\n");
  pr_info("%s",gtpusp_print_buffer);
}
//-----------------------------------------------------------------------------
#if 0 // GTPUSP_TRACE_PACKET 
static char *
gtpusp_icmph_type_2_string (
  uint8_t typeP)
{
  switch (typeP) {
  case ICMP_ECHOREPLY:
    return "ECHOREPLY";
    break;

  case ICMP_DEST_UNREACH:
    return "DEST_UNREACH";
    break;

  case ICMP_SOURCE_QUENCH:
    return "SOURCE_QUENCH";
    break;

  case ICMP_REDIRECT:
    return "REDIRECT";
    break;

  case ICMP_ECHO:
    return "ECHO";
    break;

  case ICMP_TIME_EXCEEDED:
    return "TIME_EXCEEDED";
    break;

  case ICMP_PARAMETERPROB:
    return "PARAMETERPROB";
    break;

  case ICMP_TIMESTAMP:
    return "TIMESTAMP";
    break;

  case ICMP_TIMESTAMPREPLY:
    return "TIMESTAMPREPLY";
    break;

  case ICMP_INFO_REQUEST:
    return "INFO_REQUEST";
    break;

  case ICMP_INFO_REPLY:
    return "INFO_REPLY";
    break;

  case ICMP_ADDRESS:
    return "ADDRESS";
    break;

  case ICMP_ADDRESSREPLY:
    return "ADDRESSREPLY";
    break;

  default:
    return "TYPE?";
  }
}

//-----------------------------------------------------------------------------
static char                            *
gtpusp_nf_inet_hook_2_string (
  int nf_inet_hookP)
{
  switch (nf_inet_hookP) {
  case NF_INET_PRE_ROUTING:
    return "NF_INET_PRE_ROUTING";
    break;

  case NF_INET_LOCAL_IN:
    return "NF_INET_LOCAL_IN";
    break;

  case NF_INET_FORWARD:
    return "NF_INET_FORWARD";
    break;

  case NF_INET_LOCAL_OUT:
    return "NF_INET_LOCAL_OUT";
    break;

  case NF_INET_POST_ROUTING:
    return "NF_INET_POST_ROUTING";
    break;

  default:
    return "NF_INET_UNKNOWN";
  }
}
#endif 
// for uplink GTPU traffic on S-GW
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
/* Callback from net/ipv4/udp.c to receive packets */
static int gtpusp_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
  struct gtpuhdr      *gtph_p    = NULL;
  gtpv1u_msg_t         gtpv1u_msg;
  int                  gtpu_extra_length = 0;
  const unsigned char *rx_buf_p  = NULL;
  struct iphdr        *iph_p     = NULL;
  struct iphdr        *new_iph_p = NULL;
  struct rtable       *rt        = NULL;
  struct sk_buff      *skb_p     = NULL;
  struct flowi         fl = {
    .u = {
          .ip4 = {
                  .daddr = 0,
                  .flowi4_tos = 0,
                  .flowi4_scope = RT_SCOPE_UNIVERSE,
                  }
          }
  };

  /* Need gtpu and ip header to be present */
  if (!pskb_may_pull(skb, sizeof(struct gtpuhdr) + sizeof(struct iphdr)))
    goto error;

  /* Return packets with reserved bits set */
  gtph_p = (struct gtpuhdr *)(udp_hdr(skb) + 1);

  //_gtpusp_print_hex_octets((const unsigned char*)skb->data, skb->len);
  switch (gtph_p->msgtype) {
    case GTP_ECHO_REQ:
      printk("%s: TODO GTP ECHO_REQ, SEND TO GTPV1U TASK USER SPACE\n",MODULE_NAME);
      //TODO;
      goto drop;
      break;

    case GTP_ERROR_INDICATION:
      printk("%s:TODO GTP ERROR INDICATION, SEND TO GTPV1U TASK USER SPACE\n",MODULE_NAME);
      //TODO;
      goto drop;
      break;

    case GTP_ECHO_RSP:
      printk("%s:GTP ECHO_RSP, SEND TO GTPV1U TASK USER SPACE\n",MODULE_NAME);
      goto drop;
      break;

    case GTP_GPDU:
      //printk("%s:GTP GPDU\n",MODULE_NAME);
      gtpv1u_msg.version       = ((gtph_p->flags) & 0xE0) >> 5;
      gtpv1u_msg.protocol_type = ((gtph_p->flags) & 0x10) >> 4;
      gtpv1u_msg.ext_hdr_flag  = ((gtph_p->flags) & 0x04) >> 2;
      gtpv1u_msg.seq_num_flag  = ((gtph_p->flags) & 0x02) >> 1;
      gtpv1u_msg.npdu_num_flag = ((gtph_p->flags) & 0x01);
      gtpv1u_msg.teid          = ntohl (gtph_p->tunid);
      rx_buf_p = (const unsigned char *)&gtph_p[1];

      if (gtpv1u_msg.ext_hdr_flag || gtpv1u_msg.seq_num_flag || gtpv1u_msg.npdu_num_flag) {
        gtpv1u_msg.seq_num = ntohs (*(((u_int16_t *) rx_buf_p)));
        rx_buf_p += 2;
        gtpu_extra_length += 2;
        gtpv1u_msg.npdu_num = *(rx_buf_p++);
        gtpv1u_msg.next_ext_hdr_type = *(rx_buf_p++);
        gtpu_extra_length += 2;
      }

      if (iptunnel_pull_header(skb, sizeof(struct udphdr) + sizeof(struct gtpuhdr) + gtpu_extra_length, htons(ETH_P_IP)))
        goto drop;

      skb_reset_network_header(skb);
      skb_reset_mac_header(skb);
      skb->mark = gtpv1u_msg.teid;

      // LG: Here some work to do: do not copy skb but forward it in the good way (still to be understood)
      // here it is not a network driver (have a look at kernel src drivers/net/vxlan.c)

      iph_p = (struct iphdr *)(skb->data);
      fl.u.ip4.daddr = iph_p->daddr;
      fl.u.ip4.flowi4_tos = RT_TOS (iph_p->tos);
      rt = ip_route_output_key (&init_net, &fl.u.ip4);

      if (rt == NULL) {
        printk("%s: Failed to route packet to dst 0x%x.\n",MODULE_NAME, fl.u.ip4.daddr);
        return NF_DROP;
      }

      if (rt->dst.dev == NULL) {
        printk("%s: dst dev NULL\n",MODULE_NAME);
        return 0;
      }
      //printk("%s: dst dev %s\n",MODULE_NAME, rt->dst.dev->name);

      skb_p = alloc_skb (LL_MAX_HEADER + ntohs (iph_p->tot_len), GFP_ATOMIC); // may be when S5 add more room

      if (skb_p == NULL) {
        return 0;
      }

      skb_p->priority = rt_tos2priority (iph_p->tos);
      //skb_p->pkt_type = PACKET_OTHERHOST;
      skb_dst_set (skb_p, dst_clone (&rt->dst));
      skb_p->dev = skb_dst (skb_p)->dev;
      skb_reserve (skb_p, LL_MAX_HEADER + ntohs (iph_p->tot_len));
      skb_p->protocol = htons (ETH_P_IP);
      new_iph_p = (void *)skb_push (skb_p, ntohs (iph_p->tot_len) - (iph_p->ihl << 2));
      skb_reset_transport_header (skb_p);
      new_iph_p = (void *)skb_push (skb_p, iph_p->ihl << 2);
      memcpy (new_iph_p, iph_p, ntohs (iph_p->tot_len));
      skb_reset_network_header (skb_p);
      skb_reset_inner_network_header (skb_p);
      skb_reset_inner_transport_header (skb_p);
      skb_p->mark = gtpv1u_msg.teid;
      new_iph_p->ttl = ip4_dst_hoplimit (skb_dst (skb_p));
      skb_p->ip_summed = CHECKSUM_NONE;

      if (skb_p->len > dst_mtu (skb_dst (skb_p))) {
        printk("%s: Dropped skb\n",MODULE_NAME);
        kfree_skb (skb_p);
        goto drop;
      }
      if ((rt->dst.dev->name[0] == 'l') && (rt->dst.dev->name[1] == 'o')) {
        skb_p->pkt_type = PACKET_HOST;
      } else {
        skb_p->pkt_type = PACKET_OTHERHOST;
      }
      // could be ip_send_skb() but ip_local_out is what is done inside ip_send_skb()
      ip_local_out (skb_p);
      goto drop;

      return 0;
      break;
  }

drop:
  /* Consume bad ... and good packet */
  kfree_skb(skb);
  return 0;

error:
  /* Return non gtp pkt */
  return 1;
}


#ifdef GTPUSP_WITH_IPV6
//-----------------------------------------------------------------------------
static void
gtpusp_tg6_add (
  struct sk_buff *old_skb_pP,
  const struct xt_action_param *par_pP)
{
}
#endif

//-----------------------------------------------------------------------------
static void
gtpusp_tg4_add (
  struct sk_buff *old_skb_pP,
  const struct xt_action_param *par_pP)
{
  struct sk_buff                         *new_skb_p  = NULL;
  struct iphdr                           *old_iph_p  = ip_hdr (old_skb_pP);
  struct gtpuhdr                         *gtpuh      = NULL;
  uint16_t                                orig_iplen = 0;

  // CONNMARK
  enum ip_conntrack_info                  ctinfo;
  struct nf_conn                         *ct         = NULL;
  u_int32_t                               newmark    = 0;
  int                                     ret        = 0;
  struct rtable                          *rt         = NULL;

  struct flowi                            fl         = {
    .u = {
          .ip4 = {
                  .daddr = ((const struct xt_gtpusp_target_info *)(par_pP->targinfo))->raddr,
                  .flowi4_tos = RT_TOS (old_iph_p->tos),
                  .flowi4_scope = RT_SCOPE_UNIVERSE,
                  }
          }
  };

  if (skb_linearize (old_skb_pP) < 0) {
    printk("%s: skb no linearize\n",MODULE_NAME);
    return;
  }

  orig_iplen = ntohs (old_iph_p->tot_len);
  rt = ip_route_output_key (&init_net, &fl.u.ip4);

  //----------------------------------------------------------------------------
  // CONNMARK
  //----------------------------------------------------------------------------
  ct = nf_ct_get (old_skb_pP, &ctinfo);

  if (ct == NULL) {
    printk("%s: _gtpusp_target_add force targinfo ltun %u to skb_pP mark %u\n",
           MODULE_NAME, ((const struct xt_gtpusp_target_info *)(par_pP->targinfo))->ltun, old_skb_pP->mark);
    newmark = ((const struct xt_gtpusp_target_info *)(par_pP->targinfo))->ltun;
  } else {
    //XT_CONNMARK_RESTORE:
    newmark = old_skb_pP->mark ^ ct->mark;
    //printk("%s: _gtpusp_target_add restore mark %u (skb mark %u ct mark %u) len %u sgw addr %x\n",
    //       MODULE_NAME, newmark, old_skb_pP->mark, ct->mark, orig_iplen, ((const struct xt_gtpusp_target_info *)(par_pP->targinfo))->raddr);

    if (newmark != ((const struct xt_gtpusp_target_info *)(par_pP->targinfo))->ltun) {
      printk("%s:WARNING _gtpusp_target_add restore mark 0x%x mismatch ltun 0x%x (rtun 0x%x)", 
             MODULE_NAME, newmark,
             ((const struct xt_gtpusp_target_info *)(par_pP->targinfo))->ltun, 
             ((const struct xt_gtpusp_target_info *)(par_pP->targinfo))->rtun);
    }
  }


  new_skb_p = skb_copy_expand(old_skb_pP,
                              sizeof(struct gtpuhdr) + sizeof(struct udphdr) + sizeof(struct iphdr)+ LL_MAX_HEADER,
                              0,GFP_ATOMIC);
  if (NULL != new_skb_p) {

    /*
     * Add GTPu header
     */
    gtpuh = (struct gtpuhdr*)skb_push(new_skb_p, sizeof(*gtpuh));

    gtpuh->flags   = 0x30;         /* v1 and Protocol-type=GTP */
    gtpuh->msgtype = 0xff;         /* T-PDU */
    gtpuh->length  = htons (orig_iplen);
    gtpuh->tunid   = htonl (((const struct xt_gtpusp_target_info *)(par_pP->targinfo))->rtun);
    //_gtpusp_print_hex_octets((const unsigned char*)new_skb_p->data, new_skb_p->len);

    ret =  udp_tunnel_xmit_skb(gtpusp_data.sock,
                          rt,
                          new_skb_p,
                          ((const struct xt_gtpusp_target_info *)(par_pP->targinfo))->laddr,
                          ((const struct xt_gtpusp_target_info *)(par_pP->targinfo))->raddr,
                          old_iph_p->tos,
                          old_iph_p->ttl,
                          old_iph_p->frag_off,
                          htons(gtpu_sgw_port),
                          htons(gtpu_enb_port),
                          0 /*bool xnet*/);
  } else {
    printk("%s: _gtpusp_target_add skb_copy_expand returned NULL\n", MODULE_NAME);
  }
  return;
}

#ifdef GTPUSP_WITH_IPV6
//-----------------------------------------------------------------------------
static unsigned int
gtpusp_tg6 (
  struct sk_buff *skb_pP,
  const struct xt_action_param *par_pP)
{
  const struct xt_gtpusp_target_info     *tgi_p = par_pP->targinfo;

  if (tgi_p == NULL) {
    return NF_ACCEPT;
  }

  if (tgi_p->action == PARAM_GTPUSP_ACTION_ADD) {
    gtpusp_tg6_add (skb_pP, par_pP);
    return NF_DROP;             // TODO
  }

  return NF_ACCEPT;
}
#endif

//-----------------------------------------------------------------------------
static unsigned int
gtpusp_tg4 (
  struct sk_buff *skb_pP,
  const struct xt_action_param *par_pP)
{
  const struct xt_gtpusp_target_info     *tgi_p = par_pP->targinfo;

  if (tgi_p == NULL) {
    return NF_ACCEPT;
  }

  if (tgi_p->action == PARAM_GTPUSP_ACTION_ADD) {
    gtpusp_tg4_add (skb_pP, par_pP);
    return NF_DROP;
  }

  return NF_ACCEPT;
}

//-----------------------------------------------------------------------------
static int
__init gtpusp_tg_init(void)
{
  int                                     err;
  struct udp_tunnel_sock_cfg              tunnel_cfg;

  printk("%s: init (udptun version)\n",MODULE_NAME);
  // UDP socket socket
  memset (&gtpusp_data, 0, sizeof (gtpusp_data_priv_t));

  gtpusp_data.udp_conf.family            = AF_INET;
  gtpusp_data.udp_conf.local_ip.s_addr   = in_aton (sgw_addr); // may use INADDR_ANY
  gtpusp_data.udp_conf.use_udp_checksums = 1;
  gtpusp_data.udp_conf.local_udp_port    = htons(gtpu_sgw_port);

  /* Open UDP socket */
  err = udp_sock_create(&init_net, &gtpusp_data.udp_conf, &gtpusp_data.sock);
  if (err < 0) {
    return err;
  }

  gtpusp_data.addr.sin_family           = AF_INET;
  gtpusp_data.addr.sin_port             = htons (gtpu_sgw_port);
  gtpusp_data.addr.sin_addr.s_addr      = in_aton (sgw_addr);
  gtpusp_data.addr_send.sin_family      = AF_INET;
  gtpusp_data.addr_send.sin_port        = htons (gtpu_enb_port);
  gtpusp_data.addr_send.sin_addr.s_addr = in_aton (sgw_addr);

  /* Mark socket as an encapsulation socket. */
  tunnel_cfg.sk_user_data  = NULL;
  tunnel_cfg.encap_type    = 1;
  tunnel_cfg.encap_rcv     = gtpusp_udp_encap_recv;
  tunnel_cfg.encap_destroy = NULL;

  // parameter#1=net unused in setup_udp_tunnel_sock (3.19.8/net/ipv4/udp_tunnel.c:57)
  setup_udp_tunnel_sock(&init_net, gtpusp_data.sock, &tunnel_cfg);

  return xt_register_targets (gtpusp_tg_reg, ARRAY_SIZE (gtpusp_tg_reg));
}

//-----------------------------------------------------------------------------
static void __exit
gtpusp_tg_exit (
  void)
{
  /*
   * free allocated resources before exit
   */
  if (gtpusp_data.sock != NULL) {
    udp_tunnel_sock_release(gtpusp_data.sock);
    gtpusp_data.sock = NULL;
  }

  xt_unregister_targets (gtpusp_tg_reg, ARRAY_SIZE (gtpusp_tg_reg));
  printk("%s: exited\n",MODULE_NAME);
}


module_init (gtpusp_tg_init);
module_exit (gtpusp_tg_exit);
MODULE_ALIAS ("ipt6_GTPUSP");
MODULE_ALIAS ("ipt_GTPUSP");
