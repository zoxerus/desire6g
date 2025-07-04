/* packet-PROTOABBREV.c
* Routines for PROTONAME dissection
* Copyright 2000, YOUR_NAME
*
* $Id: README.developer,v 1.86 2003/11/14 19:20:24 guy Exp $
*
* Wireshark – Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* Copied from WHATEVER_FILE_YOU_USED (where “WHATEVER_FILE_YOU_USED”
* is a dissector file; if you just copied this from README.developer,
* don’t bother with the “Copied from” – you don’t even need to put
* in a “Copied from” if you copied an existing dissector, especially
* if the bulk of the code in the new dissector is your code)
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place – Suite 330, Boston, MA 02111-1307, USA.
*/


#include “config.h”

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <sys/stat.h>

#include

#include

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

// #include “packet-lwm.h”


#define INT_IP_PROTO 253

statin int proto_ibnt;

/* Register the protocol with Wireshark
/* this format is required because a script is used to build
/* the C function that calls all the protocol registration.
*/
void proto_register_ibnt(void)
{
/* Register the protocol name and description */
proto_ibnt = proto_register_protocol(
    “InBand Network Telemetry”,  /* full name */
    “INT_MD”,                    /* short name */   
    “INT”);                      /* filter name */ 


}

void proto_reg_handoff_ibnt(void)
{
static dissector_handle_t ibnt_handle;

ibnt_handle = create_dissector_handle(dissect_ibnt, proto_ibnt);

dissector_add_uint(“ip.proto”, INT_IP_PROTO , ibnt_handle);
}