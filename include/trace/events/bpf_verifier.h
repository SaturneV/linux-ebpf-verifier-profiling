/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM bpf_verifier

#if !defined(_TRACE_BPF_VERIFIER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_BPF_VERIFIER_H

#include <linux/tracepoint.h>

/*
 * Tracepoint for BPF verifier aggregated per-program statistics.
 * Emitted once per program at the end of verification.
 * Note: Packed into single u64 fields to stay within BPF tracepoint limit of 12 args.
 * High 32 bits contain one mismatch category, low 32 bits contain another.
 */
TRACE_EVENT(bpf_verifier_prog_stats,

	TP_PROTO(const char *prog_name, u32 prog_len,
		 u32 total_states_compared, u32 total_states_matched, u32 total_states_mismatched,
		 u64 mismatch_pair1, u64 mismatch_pair2, u64 mismatch_pair3, u64 mismatch_pair4,
		 u32 max_mismatch_insn_idx, u32 max_mismatch_count),

	TP_ARGS(prog_name, prog_len,
		total_states_compared, total_states_matched, total_states_mismatched,
		mismatch_pair1, mismatch_pair2, mismatch_pair3, mismatch_pair4,
		max_mismatch_insn_idx, max_mismatch_count),

	TP_STRUCT__entry(
		__string(prog_name, prog_name)
		__field(u32, prog_len)
		__field(u32, total_states_compared)
		__field(u32, total_states_matched)
		__field(u32, total_states_mismatched)
		__field(u32, mismatch_callback_depth)
		__field(u32, mismatch_curframe)
		__field(u32, mismatch_speculative)
		__field(u32, mismatch_sleepable)
		__field(u32, mismatch_refsafe)
		__field(u32, mismatch_callsite)
		__field(u32, mismatch_registers)
		__field(u32, mismatch_stack)
		__field(u32, max_mismatch_insn_idx)
		__field(u32, max_mismatch_count)
	),

	TP_fast_assign(
		__assign_str(prog_name);
		__entry->prog_len = prog_len;
		__entry->total_states_compared = total_states_compared;
		__entry->total_states_matched = total_states_matched;
		__entry->total_states_mismatched = total_states_mismatched;
		__entry->mismatch_callback_depth = (u32)(mismatch_pair1 & 0xFFFFFFFF);
		__entry->mismatch_curframe = (u32)((mismatch_pair1 >> 32) & 0xFFFFFFFF);
		__entry->mismatch_speculative = (u32)(mismatch_pair2 & 0xFFFFFFFF);
		__entry->mismatch_sleepable = (u32)((mismatch_pair2 >> 32) & 0xFFFFFFFF);
		__entry->mismatch_refsafe = (u32)(mismatch_pair3 & 0xFFFFFFFF);
		__entry->mismatch_callsite = (u32)((mismatch_pair3 >> 32) & 0xFFFFFFFF);
		__entry->mismatch_registers = (u32)(mismatch_pair4 & 0xFFFFFFFF);
		__entry->mismatch_stack = (u32)((mismatch_pair4 >> 32) & 0xFFFFFFFF);
		__entry->max_mismatch_insn_idx = max_mismatch_insn_idx;
		__entry->max_mismatch_count = max_mismatch_count;
	),

	TP_printk("prog_name=%s prog_len=%u total_compared=%u matched=%u mismatched=%u "
		  "mismatch_breakdown(cbdepth=%u curframe=%u spec=%u sleepable=%u refsafe=%u callsite=%u regs=%u stack=%u) "
		  "max_mismatch_insn=%u count=%u",
		  __get_str(prog_name), __entry->prog_len,
		  __entry->total_states_compared, __entry->total_states_matched, __entry->total_states_mismatched,
		  __entry->mismatch_callback_depth, __entry->mismatch_curframe, __entry->mismatch_speculative,
		  __entry->mismatch_sleepable, __entry->mismatch_refsafe, __entry->mismatch_callsite,
		  __entry->mismatch_registers, __entry->mismatch_stack,
		  __entry->max_mismatch_insn_idx, __entry->max_mismatch_count)
);

/*
 * Tracepoint for BPF verifier aggregated per-instruction statistics.
 * Emitted for each instruction that has state comparisons.
 * Mismatch categories packed into u64 pairs to stay within 12 arg limit.
 * pair1: callback_depth(low), curframe(high)
 * pair2: speculative(low), sleepable(high)
 * pair3: refsafe(low), callsite(high)
 * pair4: registers(low), stack(high)
 */
TRACE_EVENT(bpf_verifier_insn_stats,

	TP_PROTO(const char *prog_name, u32 insn_idx,
		 u32 states_compared, u32 states_matched, u32 states_mismatched,
		 u64 mismatch_pair1, u64 mismatch_pair2, u64 mismatch_pair3, u64 mismatch_pair4),

	TP_ARGS(prog_name, insn_idx,
		states_compared, states_matched, states_mismatched,
		mismatch_pair1, mismatch_pair2, mismatch_pair3, mismatch_pair4),

	TP_STRUCT__entry(
		__string(prog_name, prog_name)
		__field(u32, insn_idx)
		__field(u32, states_compared)
		__field(u32, states_matched)
		__field(u32, states_mismatched)
		__field(u32, mismatch_callback_depth)
		__field(u32, mismatch_curframe)
		__field(u32, mismatch_speculative)
		__field(u32, mismatch_sleepable)
		__field(u32, mismatch_refsafe)
		__field(u32, mismatch_callsite)
		__field(u32, mismatch_registers)
		__field(u32, mismatch_stack)
	),

	TP_fast_assign(
		__assign_str(prog_name);
		__entry->insn_idx = insn_idx;
		__entry->states_compared = states_compared;
		__entry->states_matched = states_matched;
		__entry->states_mismatched = states_mismatched;
		__entry->mismatch_callback_depth = (u32)(mismatch_pair1 & 0xFFFFFFFF);
		__entry->mismatch_curframe = (u32)((mismatch_pair1 >> 32) & 0xFFFFFFFF);
		__entry->mismatch_speculative = (u32)(mismatch_pair2 & 0xFFFFFFFF);
		__entry->mismatch_sleepable = (u32)((mismatch_pair2 >> 32) & 0xFFFFFFFF);
		__entry->mismatch_refsafe = (u32)(mismatch_pair3 & 0xFFFFFFFF);
		__entry->mismatch_callsite = (u32)((mismatch_pair3 >> 32) & 0xFFFFFFFF);
		__entry->mismatch_registers = (u32)(mismatch_pair4 & 0xFFFFFFFF);
		__entry->mismatch_stack = (u32)((mismatch_pair4 >> 32) & 0xFFFFFFFF);
	),

	TP_printk("prog_name=%s insn_idx=%u compared=%u matched=%u mismatched=%u "
		  "mismatch_breakdown(cbdepth=%u curframe=%u spec=%u sleepable=%u refsafe=%u callsite=%u regs=%u stack=%u)",
		  __get_str(prog_name), __entry->insn_idx,
		  __entry->states_compared, __entry->states_matched, __entry->states_mismatched,
		  __entry->mismatch_callback_depth, __entry->mismatch_curframe, __entry->mismatch_speculative,
		  __entry->mismatch_sleepable, __entry->mismatch_refsafe, __entry->mismatch_callsite,
		  __entry->mismatch_registers, __entry->mismatch_stack)
);

#endif

/* This part must be outside protection */
#include <trace/define_trace.h>
