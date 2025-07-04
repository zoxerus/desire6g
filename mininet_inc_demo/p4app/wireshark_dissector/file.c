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

static const value_string ibnt_header_types[] = {
    {0x00, "INT Report"},
    {0x01, "INT Summary"}
}


static const value_string ibnt_original_protocols[] = {
    {0x11, "UDP Protocol"},
    {0x06, "TCP Protocol"}
}


static int hf_ibnt_type = -1;
static int hf_ibnt_oproto = -1;
static int hf_ibnt_ran_d = -1;
static int hf_ibnt_pdp_d = -1;
static int hf_ibnt_pid = -1;
static int hf_ibnt_ran_avg = -1;
static int hf_ibnt_pdp_avg = -1;


/* Register the protocol with Wireshark
/* this format is required because a script is used to build
/* the C function that calls all the protocol registration.
*/
void proto_register_ibnt(void)
{
/* Setup list of header fields */
static hf_register_info hf[] = {
{ &hf_ibnt_type,
{ “Header Type”,
“int.type”,
FT_UINT8, BASE_HEX,  VALS(ibnt_header_types), 0x0, “Type of INT Message”, HFILL } 
},

{ &hf_ibnt_oproto,
{ “Original IP Protocol”,
“int.oproto”,
FT_UNIT8, BASE_HEX, VALS(ibnt_original_protocols) , 0x0, “Original IP Protocol”, HFILL }
},

{ &hf_ibnt_ran_d,
{ “RAN Latency”,
“int.ran_d”,
FT_UNIT48, BASE_HEX, NULL , 0x0, “Delay in the RAN Segment”, HFILL }
},

{ &hf_ibnt_ran_d,
{ “PDP Latency”,
“int.pdp_d”,
FT_UNIT48, BASE_HEX, NULL , 0x0, “Delay in the PDP Segment”, HFILL }
},

{ &hf_ibnt_pid,
{ “Path ID”,
“int.pid”,
FT_UNIT32, BASE_HEX, NULL , 0x0, “ID of the Network Path”, HFILL }
},

{ &hf_ibnt_ran_avg,
{ “RAN Averaged Delay”,
“int.ran_avg”,
FT_UNIT48, BASE_HEX, NULL , 0x0, “Averaged Delay for RAN Segment”, HFILL }
},

{ &hf_ibnt_pdp_avg,
{ “PDP Averaged Delay”,
“int.pdp_avg”,
FT_UNIT48, BASE_HEX, NULL , 0x0, “Averaged Delay for PDP Segment”, HFILL }
},

};



/* Setup protocol subtree array */
static gint *ett[] = {
&ett_ibnt,
&ett_ibnt_hdr_tree
};
/* Register the protocol name and description */
proto_ibnt = proto_register_protocol(“InBand Network Telemetry”, “INT_MD”, “INT”,HFILL);

/* Required function calls to register the header fields and subtree used */
proto_register_field_array(proto_ibnt, hf, array_length(hf));
proto_register_subtree_array(ett, array_length(ett));

/* Register dissector with Wireshark. */
register_dissector(“INT”, dissect_int, proto_int);

}

static gboolean dissect_PROTOABBREV(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
/* Assume it’s your packet and do dissection */
return (TRUE);
}




void proto_reg_handoff_ibnt(void)
{
static int ibnt_inited = FALSE;

if ( !ibnt_inited )
{
/* register as heuristic dissector for both TCP and UDP */
heur_dissector_add(“ip”, dissect_ibnt, proto_ibnt);

}
}