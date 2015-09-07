/* Shared header file for iptables extension for the GTPU target and GTPu KLM
 *
 * Copyright (c) 2010-2011 Polaris Networks
 * Author: Pradip Biswas <pradip_biswas@polarisnetworks.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#ifndef _LINUX_NETFILTER_XT_GTPUSP_H
#define _LINUX_NETFILTER_XT_GTPUSP_H 1
enum xt_gtpusp_mode_ {
  PARAM_GTPUSP_ACTION_ADD = 1 << 8,
};

struct xt_gtpusp_target_info {
  u_int32_t laddr   __attribute__((aligned(8)));
  u_int32_t raddr   __attribute__((aligned(8)));
  u_int32_t ltun    __attribute__((aligned(8)));
  u_int32_t rtun    __attribute__((aligned(8)));
  u_int32_t action  __attribute__((aligned(8)));
};
#endif /* _LINUX_NETFILTER_XT_GTPUSP_H */

