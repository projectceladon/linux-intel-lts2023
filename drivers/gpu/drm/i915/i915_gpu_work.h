#ifndef __I915_GPU_WORK_H__
#define __I915_GPU_WORK_H__

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#define I915_ENGINE_WORK_STATS_COUNT 256
#define GPU_WORK_PERIOD_EVENT_TIMEOUT 10

#define HASH_MAP(x) (x & (I915_ENGINE_WORK_STATS_COUNT - 1))
#define KEY_INVALID(key) (key < 0 || key >= I915_ENGINE_WORK_STATS_COUNT)

struct intel_context;
struct intel_engine_cs;

struct i915_work_stats {
    u32 gpu_id;
    u32 uid;
    u64 start_time_ns;
    u64 end_time_ns;

    u64 total_active_duration_ns;
};

struct i915_engine_work {
    bool enabled; /* if engine work stats should be emitted */
    u32 num_entries; /* number of entries currently in work stats */
    /* serialize access to work stats array */
    spinlock_t stats_lock;
    /* work period stats record per engine */
    struct i915_work_stats stats[I915_ENGINE_WORK_STATS_COUNT];
    struct work_struct event_work;
};

void i915_gpu_work_process_ctx(struct intel_context *ctx, struct i915_engine_work *ew);

void i915_gpu_work_stats_init(struct intel_engine_cs *engine);
#endif /*__I915_GPU_WORK_H__*/