
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
  SYN_SENT,
  SYN_RECEIVED,
  ESTABLISHED,
  CLOSE_WAIT,
  LAST_ACK,
  FIN_WAIT_1,
  FIN_WAIT_2,
  CLOSING,
  TIME_WAIT,
  CLOSED
} sr_nat_connection_state;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip;  /* associated ip */
  uint32_t client_isn; /* isn of the client*/
  uint32_t server_isn; /* isn of the server */
  time_t last_updated;
  sr_nat_connection_state state;
  struct sr_nat_connection *next;
  
};
typedef struct sr_nat_connection sr_nat_connection_t;

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};
typedef struct sr_nat_mapping sr_nat_mapping_t;

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  int cur_port;
  int max_port;
  int min_port;
  int icmp_timeout;
  int tcp_established_timeout;
  int tcp_transitory_timeout;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};
typedef struct sr_nat sr_nat_t;


int   sr_nat_init(struct sr_nat *nat, int icmp_t, int tcp_t_t, int tcp_e_t);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Get the connection associated with given mapping */
struct sr_nat_connection *sr_nat_lookup_con(struct sr_nat_mapping *mapping, uint32_t ip_con);

/* Insert a new connection into the list of a mapping */
struct sr_nat_connection *sr_nat_insert_con(struct sr_nat_mapping *mapping, uint32_t ip_con)

#endif
