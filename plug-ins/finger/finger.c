/*
    finger -- ettercap plugin -- fingerprint a remote host.

    it sends a syn to an open port and collect the passive ACK fingerprint.

    Copyright (C) ALoR & NaGA
    
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

    $Id: finger.c,v 1.1 2003/10/12 15:26:33 alor Exp $
*/


#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */
#include <ec_fingerprint.h>
#include <ec_packet.h>
#include <ec_hook.h>
#include <ec_socket.h>

#include <stdlib.h>
#include <string.h>

/* globals */

struct ip_addr ip;
u_int16 port;
char fingerprint[FINGER_LEN + 1];

/* protos */
int plugin_load(void *);
static int finger_init(void *);
static int finger_fini(void *);

static void get_finger(struct packet_object *po);
static int get_target(struct ip_addr *ip, u_int16 *port);

/* plugin operations */

struct plugin_ops finger_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   ettercap_version: EC_VERSION,                        
   /* the name of the plugin */
   name:             "finger",  
    /* a short description of the plugin (max 50 chars) */                    
   info:             "Fingerprint a remote host",  
   /* the plugin version. note: 15 will be displayed as 1.5 */                    
   version:          "1.0",   
   /* the pluging type: PL_STANDALONE or PL_HOOK */                    
   type:             PL_STANDALONE,
   /* activation function */
   init:             &finger_init,
   /* deactivation function */                     
   fini:             &finger_fini,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   return plugin_register(handle, &finger_ops);
}

/******************* SANDARD FUNCTIONS *******************/

static int finger_init(void *dummy) 
{
   char tmp[MAX_ASCII_ADDR_LEN];
   char os[OS_LEN + 1];
   
   /* don't show packets while operating */
   GBL_OPTIONS->quiet = 1;
   
   /* wipe the global vars */
   memset(fingerprint, 0, sizeof(fingerprint));
   memset(&ip, 0, sizeof(struct ip_addr));
   port = 0;

   /* get the target for the fingerprint */
   if (get_target(&ip, &port) != ESUCCESS) {
      INSTANT_USER_MSG("Cannot fingerprint %s:%d\n", ip_addr_ntoa(&ip, tmp), port);
      return PLUGIN_FINISHED;
   }
  
   /* convert the in ascii ip address */
   ip_addr_ntoa(&ip, tmp);

   /* 
    * add the hook to collect tcp SYN+ACK packets from 
    * the target and extract the passive fingerprint
    */
   hook_add(PACKET_TCP, &get_finger);
   
   INSTANT_USER_MSG("Fingerprinting %s:%d...\n\n", tmp, port);
   
   /* 
    * open the connection and close it immediately.
    * this ensure that a SYN will be sent to the port
    */
   close_socket(open_socket(tmp, port));

   /* wait for the response */
   sleep(1);

   /* remove the hook, we have collected the finger */
   hook_del(PACKET_TCP, &get_finger);

   INSTANT_USER_MSG(" FINGERPRINT      : %s\n", fingerprint);

   /* decode the finterprint */
   if (fingerprint_search(fingerprint, os) == ESUCCESS)
      INSTANT_USER_MSG(" OPERATING SYSTEM : %s \n\n", os);
   else {
      INSTANT_USER_MSG(" OPERATING SYSTEM : unknown fingerprint (please submit it) \n");
      INSTANT_USER_MSG(" NEAREST ONE IS   : %s \n\n", os);
   }  
      
   
   return PLUGIN_FINISHED;
}


static int finger_fini(void *dummy) 
{
   return PLUGIN_FINISHED;
}

/*********************************************************/

/*
 * sends a SYN to a specified port and collect the 
 * passive fingerprint for that host 
 */
static void get_finger(struct packet_object *po)
{
  
   /* check that the source is our host and the fingerprint was collecter */
   if (!ip_addr_cmp(&ip, &po->L3.src) && strcmp(po->PASSIVE.fingerprint, "")) 
      memcpy(fingerprint, &po->PASSIVE.fingerprint, FINGER_LEN);
}

/*
 * get the target
 * form GBL_TARGETS if it was specified
 * else from user input
 */
static int get_target(struct ip_addr *ip, u_int16 *port)
{
   struct ip_list *host;
   struct in_addr ipaddr;
   char input[64];
   char *p;
   
   /* is it possible to get it from GBL_TARGETS ? */
   if ((host = SLIST_FIRST(&GBL_TARGET1->ips)) != NULL) {
      
      /* copy the ip address */
      memcpy(ip, &host->ip, sizeof(struct ip_addr));
      
      /* find the port */
      for (*port = 0; *port < 0xffff; (*port)++) {
         if (BIT_TEST(GBL_TARGET1->ports, *port)) {
            break;
         }
      }
      
      /* port was found */
      if (*port != 0xffff)
         return ESUCCESS;
      
   }

   /* get the user input */
   ui_input("Insert ip:port : ", input, sizeof(input));

   /* get the hostname */
   if ((p = strtok(input, ":")) != NULL) {
      if (inet_aton(p, &ipaddr) == 0)
         return -EINVALID;

      ip_addr_init(ip, AF_INET, (char *)&ipaddr);

      /* get the port */
      if ((p = strtok(NULL, ":")) != NULL) {
         *port = atoi(p);

         /* correct parsing */
         if (*port != 0)
            return ESUCCESS;
      }
   }

   return -EINVALID;
}

/* EOF */

// vim:ts=3:expandtab
 
