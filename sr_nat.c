
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int sr_nat_init(struct sr_nat *nat, int icmp_t, int tcp_t_t, int tcp_e_t) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  nat->max_port = 5000;
  nat->min_port = 1024;
  nat->cur_port = nat->min_port;
  nat->icmp_timeout = icmp_t;
  nat->tcp_established_timeout = tcp_e_t;
  nat->tcp_transitory_timeout = tcp_t_t;
  return success;
}


/*----------------------------------------------------------------
NOT THREAD SAFE ON ITS OWN

only called in sr_nat_destroy, iterates through the connection 
linked list.
------------------------------------------------------------------*/
int sr_nat_connection_destroy(struct sr_nat_connection *nat_conn){
  sr_nat_connection_t *new_next = NULL;
  sr_nat_connection_t *next = nat_conn;
  while(next){
    new_next = next;
    free(next);
    next = new_next;
  }

  return 1;
}

int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));
  sr_nat_mapping_t *new_next = NULL;
  sr_nat_mapping_t *next_map = nat->mappings;

  /* free nat memory here */
  /*  iterate through mapping, deleting each entry */
  while(next_map){
    /*free struct sr_nat_connection *conns; */
    new_next = next_map->next;
    if(!sr_nat_connection_destroy(next_map->conns)){
      fprintf(stderr, "could not free nat connection mapping!\n");
    }
    free(next_map);
    next_map = new_next;
  }

  pthread_kill(nat->thread, SIGKILL);
  int return_val = pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));
  return return_val;

}


void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timeout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);
    sr_nat_mapping_t *map = nat->mappings;
    sr_nat_mapping_t *prev_map = NULL;
    sr_nat_mapping_t *old_map = NULL;
    while(map){
      if(map->type == nat_mapping_tcp){
        sr_nat_connection_t *prev_conn = NULL;
        sr_nat_connection_t *old_conn = NULL;
        sr_nat_connection_t *conn = map->conns;

        while(conn){
          sr_nat_connection_state state = conn->state;
          int timeout = 100000;
          if(state == SYN_SENT || state == SYN_RECEIVED || state == LAST_ACK || state == CLOSING || state == TIME_WAIT){
            timeout = nat->tcp_established_timeout;
          } else if (state == ESTABLISHED || state == FIN_WAIT_1 || state == FIN_WAIT_2 || state == CLOSE_WAIT){
            timeout = nat->tcp_transitory_timeout;
          }
          
          if(curtime > timeout + map->last_updated){
            old_conn = conn;
            if(!prev_conn){
              map->conns = conn->next;
            } else{
              prev_conn->next = conn->next;
            }
            conn = conn->next;
            free(old_conn);
          }else{
            prev_conn = conn;
            conn = conn->next;
          }
        }
      
        if(!map->conns){
          old_map = map;
          if(!prev_map){
            nat->mappings = map->next;
          } else {
            prev_map->next = map->next;
          }
          map = map->next;
          free(old_map);

        }else{
          prev_map = map;
          map = map->next;
        }
      }else if(map->type == nat_mapping_icmp){
        if(curtime > nat->icmp_timeout + map->last_updated){
          old_map = map;
          if(!prev_map){
            nat->mappings = map->next;
          } else {
            prev_map->next = map->next;
          }
          map = map->next;
          free(old_map);
        } else {
          prev_map = map;
          map = map->next;
        }
      }

    }
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}
/*-----------------------------------------------------------------
returns a copy of a given mapping, or null on failure.

NOT THREAD SAFE: SHOULD ONLY BE CALLED IN CONTEXT WHERE MUTEX
IS LOCKED.
-----------------------------------------------------------------*/
struct sr_nat_mapping *copy_nat_mapping(struct sr_nat_mapping *mapping){
  sr_nat_mapping_t *copy = malloc(sizeof(sr_nat_mapping_t));
  if(!memcpy(copy, mapping, sizeof(sr_nat_mapping_t))){return NULL;}
      /*copy connections:*/
      struct sr_nat_connection *next_conn = mapping->conns;
      struct sr_nat_connection *new_conns = NULL;
      struct sr_nat_connection *curr_new_conns = NULL;
      while(!next_conn){
        if(!new_conns){
          /*first iteration add to new_conns*/
          if(!(new_conns = malloc(sizeof(sr_nat_connection_t)))){return NULL;}
          if(!memcpy(new_conns, next_conn, sizeof(sr_nat_connection_t))){
            fprintf(stderr, "could not memcpy in copy_nat_mapping\n");
            return NULL;
          }
          curr_new_conns = new_conns;

        }else{
          if(!(curr_new_conns->next = malloc(sizeof(sr_nat_connection_t)))){return NULL;}

          if(!memcpy(curr_new_conns->next, next_conn, sizeof(sr_nat_connection_t))){
            fprintf(stderr, "could not memcpy in copy_nat_mapping\n");
            return NULL;
          }

          curr_new_conns = curr_new_conns->next;
        }
        next_conn = next_conn->next;
      }

  return copy;
}


/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  sr_nat_mapping_t *next_map = nat->mappings;
  while(next_map){
    if(next_map->aux_ext == aux_ext){
      next_map->last_updated = time(NULL);
      copy = copy_nat_mapping(next_map);
    }
  }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}


/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));
  sr_nat_mapping_t *next_nat = nat->mappings;
  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  while(next_nat){
    if((next_nat->ip_int == ip_int) && (next_nat->aux_int == aux_int)){
      next_nat->last_updated = time(NULL);
      copy = copy_nat_mapping(next_nat);
      
      break;
    } else {
      next_nat = next_nat->next;
    }
  }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}


int get_port(struct sr_nat *nat){
  int port = 0;
  if(nat->cur_port < nat->max_port){
    port = nat->cur_port;
    (nat->cur_port)++;
  
  }else{
    int i;
    for(i=nat->min_port; i < nat->max_port; i++){
      sr_nat_mapping_t *next = nat->mappings;
      while(next){
        if(next->aux_ext != port){
          port = next->aux_ext;
          break;
        }else{
          next = next->next;
        }
      }
      if(port != 0){
        break;
      }
    }
  }
  return port;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.

   RETURNS NULL IF PORT COULD NOT BE ASSIGNED
 */
sr_nat_mapping_t *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  int port = get_port(nat);
  sr_nat_mapping_t *new_map;
  sr_nat_mapping_t *mapping;
  if(port != 0){
    new_map = malloc(sizeof(sr_nat_mapping_t));
    mapping = malloc(sizeof(sr_nat_mapping_t));
    if(!mapping || !new_map){return NULL;}
    new_map->ip_int = ip_int;
    new_map->aux_int = aux_int;
    new_map->type = type;
    new_map->aux_ext = port;
    new_map->last_updated = time(NULL);
    new_map->conns = NULL;
    *mapping = *new_map;
  }

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}
/* Get the connection associated with the given IP in the NAT entry
   Returns a copy to the connection
   */
struct sr_nat_connection *sr_nat_lookup_con(struct sr_nat_mapping *mapping, uint32_t ip_con){
   struct sr_nat_connection *curr_conn = mapping->conns;
    
    /* ----------handle look up here--------*/
    while (curr_conn != NULL) {
        if (curr_conn->ip == ip_con) {
        return curr_conn;
    }
        curr_conn = curr_conn->next;
  }

    return NULL;      
};





/* Insert a new connection associated with the given IP in the NAT entry
   Returns a copy to the new connection
   */
struct sr_nat_connection *sr_nat_insert_con(struct sr_nat_mapping *mapping, uint32_t ip_con) {
   struct sr_nat_connection *new_conn = malloc(sizeof(struct sr_nat_connection));
    
    assert(new_conn != NULL);
    memset(new_conn, 0, sizeof(struct sr_nat_connection));

    new_conn->last_updated = time(NULL);
    new_conn->ip = ip_con;
    new_conn->tcp_state = CLOSED;

    struct sr_nat_connection *curr_conn = mapping->conns;

    mapping->conns = new_conn;
    new_conn->next = curr_conn;

    return new_conn;
}
}
