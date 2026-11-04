<script lang="ts">
	import type { GetDashboardResponse } from '#lib/gen/nokku/v1/dashboard_pb.js';
	import { formatBytes } from '#lib/utils.js';
	import type { Tone } from '#lib/tone.js';
	import { headline, type Issue } from './issues';

	interface Props {
		data?: GetDashboardResponse;
		issues: Issue[];
		workspace: string;
		updatedAt: number;
		/** Access requests waiting for an answer. */
		requests?: number;
	}

	let { data, issues, workspace, updatedAt, requests = 0 }: Props = $props();

	const summary = $derived(headline(data ? issues : undefined, false, requests));
	// The same tones, in the colors that hold on the console background.
	const onConsole: Partial<Record<Tone, string>> = {
		muted: 'text-terminal-dim',
		success: 'text-terminal-ok',
		warning: 'text-terminal-warn',
		destructive: 'text-terminal-err'
	};

	const recording = $derived(data?.liveSessions.filter((s) => s.recording).length ?? 0);
	const quota = $derived(Number(data?.recordingQuotaBytes ?? -1));

	// Ticks the "refreshed" age without a refetch.
	let now = $state(Date.now());
	$effect(() => {
		const id = setInterval(() => (now = Date.now()), 5_000);
		return () => clearInterval(id);
	});
	const age = $derived(Math.max(0, Math.round((now - updatedAt) / 1000)));
</script>

{#snippet row(key: string, value: string, tone = '')}
	<div class="flex min-w-0 flex-col gap-0.5">
		<dt class="text-xs text-terminal-dim">{key}</dt>
		<dd class={['min-w-0 text-pretty', tone]}>{value}</dd>
	</div>
{/snippet}

<section
	class="flex flex-col gap-4 overflow-hidden rounded-xl border bg-terminal p-5 font-terminal text-sm text-terminal-foreground"
	aria-label="Workspace status"
>
	<div class="flex items-center justify-between gap-3 text-xs text-terminal-dim">
		<span class="truncate">
			<span class="text-terminal-accent">$</span> nokku status
			<span class="text-terminal-foreground">{workspace}</span>
		</span>
		{#if data}
			<span class="shrink-0">refreshed {age < 5 ? 'just now' : `${age}s ago`}</span>
		{/if}
	</div>

	<p class={['flex items-center gap-2 text-lg font-bold', onConsole[summary.tone]]} role="status">
		<span aria-hidden="true">{summary.mark}</span>
		{summary.text}
	</p>

	{#if data}
		<dl class="grid grid-cols-[repeat(auto-fit,minmax(12rem,1fr))] gap-x-6 gap-y-3">
			{@render row(
				'servers',
				`${data.targets} total · ${data.targetsOnline} online${data.targetsManual ? ` · ${data.targetsManual} via nk sync` : ''}`,
				data.targets && data.targetsOnline + data.targetsManual < data.targets
					? 'text-terminal-warn'
					: ''
			)}
			{@render row(
				'daemons',
				`${data.daemonsOnline}/${data.daemons - data.pendingDaemons.length} connected${data.pendingDaemons.length ? ` · ${data.pendingDaemons.length} pending` : ''}${data.daemonsBehind ? ` · ${data.daemonsBehind} behind` : ''}`,
				data.offlineServers.length || data.daemonsBehind ? 'text-terminal-err' : ''
			)}
			{@render row(
				'sessions',
				`${data.liveSessions.length} live${recording ? ` · ${recording} recording` : ''}`
			)}
			{@render row('people', String(data.users))}
			{@render row(
				'storage',
				quota < 0
					? `${formatBytes(Number(data.recordingBytes))} of recordings`
					: `${formatBytes(Number(data.recordingBytes))} of ${formatBytes(quota)}`
			)}
		</dl>
	{:else}
		<div class="grid grid-cols-[repeat(auto-fit,minmax(12rem,1fr))] gap-x-6 gap-y-3">
			{#each { length: 5 }, i (i)}
				<div class="h-9 rounded-sm bg-terminal-foreground/10"></div>
			{/each}
		</div>
	{/if}
</section>
