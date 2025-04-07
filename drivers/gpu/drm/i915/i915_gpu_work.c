#include "i915_gpu_work.h"
#include <linux/pid.h>
#include <linux/errno.h>

#include "gt/intel_context.h"
#include "gt/intel_engine.h"
#include "gem/i915_gem_context.h"

#define CREATE_TRACE_POINTS
#include "intel_power_gpu_work_period_trace.h"

static inline u32 get_stats_uid(s32 key, struct i915_work_stats *stats)
{
    // TODO: stats is always accessed under spinlock.
    // Do we really need the READ_ONCE? 
    return READ_ONCE(stats[key].uid);
}

static s32 get_uid_ctx(struct intel_context *ce)
{
    struct i915_gem_context *ctx = NULL;
    struct task_struct *task = NULL;
    const struct cred *cred = NULL;
    s32 ret;

    rcu_read_lock();
    ctx = rcu_dereference(ce->gem_context);
    /* ctx could be freed from right under our nose,
     * so check first if we are able to get a reference
     */
    if (ctx && !kref_get_unless_zero(&ctx->ref))
        ctx = NULL;
    rcu_read_unlock();

    if (!ctx) {
        ret = -EINVAL;
        goto out;
    }

    // TODO: Error handling
    task = get_pid_task(ctx->pid, PIDTYPE_PID);
    cred = get_task_cred(task);
    const unsigned int uid = cred->euid.val;
    ret = (s32)uid;

    put_cred(cred);
    put_task_struct(task);
    i915_gem_context_put(ctx);
out:
    return ret;
}

// TODO: Can this be called inside softirq?
static void emit_work_period_event(struct i915_engine_work *ew)
{
    struct i915_work_stats * const stats = &ew->stats[0];
    for (int itr = 0; itr < I915_ENGINE_WORK_STATS_COUNT; itr++) {
        struct i915_work_stats *stat = &stats[itr];
        if (!stat->uid)
            continue;

        trace_gpu_work_period(0, stat->uid,
            stat->start_time_ns, stat->end_time_ns,
            stat->total_active_duration_ns);

        // TODO: check concurrent accesses to num_entries
        if (!ew->num_entries--)
            break;
    }
    GEM_BUG_ON(ew->num_entries != 0);
    memset(stats, 0, sizeof(*stats) *
                 I915_ENGINE_WORK_STATS_COUNT);
    smp_wmb();
}

static void i915_work_period_event_worker(struct work_struct *work)
{
    struct i915_engine_work *ew =
                 container_of(work, typeof(*ew), event_work);
    spin_lock_bh(&ew->stats_lock);
    // TODO: Is it too expensive to be called inside softirq?
    emit_work_period_event(ew);
    spin_unlock_bh(&ew->stats_lock);
}

static inline u32 get_cur_dt(struct intel_context* ce)
{
    struct intel_context_stats *stats = &ce->stats;
    s32 dt = READ_ONCE(stats->runtime.dt);
    if (unlikely(dt < 0)) {
        return 0;
    }
    return dt;
}

static u64 get_active_duration_ns(struct intel_context* ce)
{
    u64 dur = get_cur_dt(ce);
	if (ce->ops->flags & COPS_RUNTIME_CYCLES)
		dur *= ce->engine->gt->clock_period_ns;
    return dur;
}

/*
 * Hash collision is handled here the same way we handle the situation
 * when our favourite urinal is occupied in a crowded office restroom.
 * Sorry!
 */
static s32 handle_collision(s32 key, struct i915_engine_work *ew)
{
    struct i915_work_stats * const stats = &ew->stats[0];
    u32 uid, count = 0;

    spin_lock(&ew->stats_lock);
    while (uid = get_stats_uid(key, stats)) {
        if (unlikely(count >=
                I915_ENGINE_WORK_STATS_COUNT)) {
            spin_unlock(&ew->stats_lock);
            return -ENOMEM;
        }

        if (key == I915_ENGINE_WORK_STATS_COUNT)
            key = 0;
        key++;
        count++;
    }
    spin_unlock(&ew->stats_lock);
    return key;
}

void i915_gpu_work_process_ctx(struct intel_context *ce,
                     struct i915_engine_work *ew)
{
    struct i915_work_stats * const stats = &ew->stats[0];
    struct i915_work_stats *stat = NULL;
    s32 key = 0, uid = 0;

    uid = get_uid_ctx(ce);
    // TODO: Handle this correctly
    if (uid < 0)
        return;

    key = HASH_MAP(uid);

    /* Hash collision. Find the next available key */
    if (get_stats_uid(key, stats) != uid)
        key = handle_collision(key, ew);

    if (unlikely(KEY_INVALID(key))) {
        /*
         * This can only happen if all the slots in our stats
         * array are occupied. Emit the events now and empty
         * all the slots.
         */
        spin_lock(&ew->stats_lock);
        emit_work_period_event(ew);
        spin_unlock(&ew->stats_lock);
        key = 0;
    }
    stat = &stats[key];

    spin_lock(&ew->stats_lock);
    /*
     * If the uid at our hash index is empty (zero)
     * this implies that our ctx is processed first
     * time since we emitted the events last time
     * and subsequently evicted all the slots.
     * 
     * So, we set the start time to the last time this
     * ctx was put into the active queue. We also set
     * the end time and the total active duration to
     * the current runtime of this ctx
     */
    if (!stat->uid) {
        stat->uid = uid;
        stat->start_time_ns = READ_ONCE(ce->start_time_ns);
        stat->total_active_duration_ns =
                 get_active_duration_ns(ce);
        stat->end_time_ns = get_active_duration_ns(ce);
        /* TODO: num_entries could be accessed concurrently
         * b/w two cpus (use atomic type?)
         */
        ew->num_entries++;
        goto out;
    }

    /*
     * Now we have the hash index but the slot
     * could be occupied by another uid that maps
     * to the same slot index.
     * So, we do a linear search from our index until
     * we find a slot with matching uid or we run
     * through all the slots.
     */
    u32 count = 0;
    while (stat->uid != uid) {
        /* Is this if condition really reuqired? */
        if (unlikely(count >=
                 I915_ENGINE_WORK_STATS_COUNT))
            goto out;

        if (key == I915_ENGINE_WORK_STATS_COUNT)
            key = 0;

        stat = &stats[++key];
        ++count;
    }

    /*
     * We set the endtime to the current time this ctx
     * is being processed and accumulate the current
     * runtime to the total active duration
     */
    stat->end_time_ns = ktime_get_raw_ns();
    stat->total_active_duration_ns +=
                 get_active_duration_ns(ce);

out:
    spin_unlock(&ew->stats_lock);
}

void i915_gpu_work_stats_init(struct intel_engine_cs *engine)
{
    struct i915_engine_work *ew = &engine->gpu_work;
    struct i915_work_stats * const stats = &ew->stats[0];

    ew->enabled = false;
    ew->num_entries = 0;
    memset(stats, 0, sizeof(*stats) *
                 I915_ENGINE_WORK_STATS_COUNT);

    spin_lock_init(&ew->stats_lock);
    INIT_WORK(&ew->event_work, i915_work_period_event_worker);
}
