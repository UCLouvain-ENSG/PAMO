#include "suricata-common.h"
#include "suricata.h"
#include "threadvars.h"
#include "util-debug.h"

#include <stdlib.h>
#include "biased.h"


void lock2_init(lock2 *lock) {
    lock->interested[0] = false;
    lock->interested[1] = false;
    lock->turn = 0;
}

void lockN_init(lockN *lock) {
    atomic_store(&lock->lock, 0);
}
void biased_init(BiasedLock *l, int owner) {
    //SCLogNotice("Init biased lock %p, owner %d", l, owner);
    l->owner = -2567;//owner;
    lock2_init(&l->t);
    lockN_init(&l->n);
}

/**
 * @brief Valid only before the lock is used !
 * 
 * @param l 
 * @param owner 
 */
void biased_set_owner(BiasedLock *l, int owner) {
   // SCLogNotice("Set biased owner %p, owner %d", l, owner);
    l->owner = owner;
}

void biased_destroy(BiasedLock *l) {
    SCLogLock("Destroy biased lock %p, owner %d", l, l->owner);
    l->owner = -2567;
}