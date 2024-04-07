#ifndef BIASED_H
#define BIASED_H
#include <stdbool.h>
#include <stdatomic.h>

#define SCLogLock(...) //SCLogDebug(__VA_ARGS__)

extern thread_local int thread_id; // Thread ID for the current thread

typedef struct lock2_ {
    volatile bool interested[2];
    volatile int turn;
} lock2;


typedef struct {
    volatile int lock; // Single atomic lock for N-process
} lockN;


typedef struct BiasedLock_ {
    int owner;
    lock2 t;
    lockN n; /* N−process lock */
} BiasedLock;


void lockN_init(lockN *lock);
void biased_set_owner(BiasedLock *l, int owner);
void biased_init(BiasedLock *l, int owner);
void biased_destroy(BiasedLock *l);

void lock2_init(lock2 *lock);
/**
 * @brief id is 0 or 1
 * 
 * @param id 
 */
void lock2_acquire(lock2* l, int id)
{
    atomic_store(&l->interested[id], 1);
    atomic_store(&l->turn, 1 - id);

    while (atomic_load(&l->turn) == 1 - id
           && atomic_load(&l->interested[1 - id]) == 1);
}

void lock2_release(lock2* l, int id)
{
    atomic_store(&l->interested[id], 0);
}

/*

void lock2(lock2* lock, int id)
{
    atomic_store_explicit(&lock->interested[id], 1, memory_order_relaxed);
    atomic_exchange_explicit(&lock->turn, 1 - id, memory_order_acq_rel);

    while (atomic_load_explicit(&lock->interested[1 - id], memory_order_acquire) == 1
           && atomic_load_explicit(&lock->turn, memory_order_relaxed) == 1 - id);
}

void unlock2(lock2* lock, int id)
{
    atomic_store_explicit(&lock->interested[id], 0, memory_order_release);
}
*/


inline static void fence(void) {
    atomic_thread_fence(memory_order_seq_cst);
}

inline static int lockN_trylock(lockN *lock) {
    bool success;

    if (atomic_load(&lock->lock) == 0)
        return -EBUSY;
    int expected = 0;
    success = atomic_compare_exchange_strong(&lock->lock, &expected, 1);
    if (success)
        return 0; // Acquired
    else
        return -EBUSY; // Failed to acquire
}

inline static void lockN_acquire(lockN *lock) {
    bool success;
    do {
        while (atomic_load(&lock->lock) != 0) {} // Wait
        int expected = 0;
        success = atomic_compare_exchange_strong(&lock->lock, &expected, 1);
    } while (!success);
}

inline static  void lockN_release(lockN *lock) {
    atomic_store(&lock->lock, 0);
}

#if 0
inline static  void biased_lock(BiasedLock *l) {

        lockN_acquire(&l->n);

}

inline static int biased_trylock(BiasedLock *l) {

        return lockN_trylock(&l->n);

}

inline static void biased_unlock(BiasedLock *l) {

        lockN_release(&l->n);

}
#else





inline static void biased_lock(BiasedLock *l) {
    SCLogLock("[%d] Biased lock %p, owner %d", thread_id, l, l->owner);
    if (thread_id == l->owner) {
        lock2_acquire(&l->t, 0);

    } else {
        lockN_acquire(&l->n);
        SCLogLock("[%d] Biased lock %p N ackquired", thread_id, l);
        lock2_acquire(&l->t, 1);
        SCLogLock("[%d] Biased lock %p N finished", thread_id, l);
    }
}


inline static int biased_trylock(BiasedLock *l) {
    SCLogLock("[%d] Biased trylock %p, owner %d", thread_id,l, l->owner );
    //TODO : actually try
    if (thread_id == l->owner) {
        lock2_acquire(&l->t, 0);
    } else {
        if (lockN_trylock(&l->n) != 0)
            return -EBUSY;
        SCLogLock("[%d] Biased lock %p N ackquired", thread_id, l);
        lock2_acquire(&l->t, 1);
        SCLogLock("[%d] Biased lock %p N finished", thread_id, l);
    }
    return 0;

}

inline static void biased_unlock(BiasedLock *l) {
    SCLogLock("[%d] Biased unlock %p, owner %d", thread_id, l, l->owner );
    if (thread_id == l->owner) {
        lock2_release(&l->t, 0);
    } else {
         lock2_release(&l->t, 1);
         lockN_release(&l->n);
    }
    SCLogLock("[%d] Biased unlock %p finished", thread_id);
}
#endif

#endif