<script lang="ts">
	import { MonitorPlay, Radio } from '@lucide/svelte';
	import { recordings } from '$lib/api/recordings.svelte';
	import * as Empty from '$lib/components/ui/empty';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import type { Recording } from '$lib/gen/nokku/v1/recordings_pb';
	import MiniBars from './MiniBars.svelte';
	import { formatBytes, formatD, formatTs, secToD, toDate } from '$lib/utils';

	interface Props {
		limit?: number;
		/** daemonId -> display name for the host a session ran on */
		hosts?: Record<string, string>;
		/** When set, only sessions by these SSH principals are shown */
		principals?: string[];
		title?: string;
	}

	let { limit = 6, hosts = {}, principals, title = 'Recent sessions' }: Props = $props();

	const list = recordings.list();

	const sessions = $derived.by(() => {
		let rs: Recording[] = list.data?.recordings ?? [];
		if (principals) {
			const set = new Set(principals);
			rs = rs.filter((r) => set.has(r.username));
		}
		return rs.slice(0, limit);
	});

	const sparkValues = $derived.by(() => {
		const days = 14;
		const out: number[] = Array(days).fill(0);
		const now = new Date();
		const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
		for (const r of list.data?.recordings ?? []) {
			if (!r.startedAt) continue;
			const diff = Math.floor(
				(startOfToday.getTime() - toDate(r.startedAt).getTime()) / 86_400_000
			);
			const idx = days - 1 + diff;
			if (idx >= 0 && idx < days) out[idx] += 1;
		}
		return out;
	});

	function hostLabel(r: Recording): string {
		return hosts[r.daemonId] ?? 'unknown host';
	}

	function duration(r: Recording): string {
		if (!r.startedAt || !r.endedAt) return '';
		const sec = (toDate(r.endedAt).getTime() - toDate(r.startedAt).getTime()) / 1000;
		return formatD(secToD(sec), 'compact');
	}
</script>

<div class="overflow-hidden rounded-xl border bg-card">
	<div class="flex items-center justify-between border-b px-4 py-3">
		<h3 class="text-sm font-semibold">{title}</h3>
		<div class="flex items-center gap-3">
			<span class="text-[10px] text-muted-foreground">14 days</span>
			<MiniBars values={sparkValues} />
			<a
				href="/recordings"
				class="text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
			>
				View all
			</a>
		</div>
	</div>

	{#if list.isPending}
		<div class="space-y-1 p-2">
			{#each Array(4) as _, i (i)}
				<div class="flex items-center gap-3 p-2">
					<Skeleton class="size-7 rounded-full" />
					<div class="flex-1 space-y-1.5">
						<Skeleton class="h-3.5 w-24" />
						<Skeleton class="h-3 w-32" />
					</div>
					<Skeleton class="h-3 w-12" />
				</div>
			{/each}
		</div>
	{:else if sessions.length === 0}
		<Empty.Root class="py-10">
			<Empty.Header>
				<Empty.Media variant="icon">
					<MonitorPlay />
				</Empty.Media>
				<Empty.Title>No sessions yet</Empty.Title>
				<Empty.Description>
					Recorded SSH sessions will appear here once daemons stream them.
				</Empty.Description>
			</Empty.Header>
		</Empty.Root>
	{:else}
		<ul class="divide-y">
			{#each sessions as r (r.id)}
				{@const live = !r.endedAt && r.startedAt}
				<li>
					<a
						href="/recordings"
						class="flex items-center gap-3 px-4 py-2.5 transition-colors hover:bg-muted/40"
					>
						<span
							class="flex size-7 shrink-0 items-center justify-center rounded-full bg-primary/10 font-mono text-xs font-bold text-primary uppercase"
						>
							{(r.username || '?').slice(0, 2)}
						</span>
						<div class="min-w-0 flex-1">
							<p class="truncate font-mono text-sm font-medium">{r.username || 'unknown'}</p>
							<p class="truncate text-xs text-muted-foreground">{hostLabel(r)}</p>
						</div>
						<div class="shrink-0 text-right">
							{#if live}
								<span class="inline-flex items-center gap-1.5 text-xs font-medium text-success">
									<Radio class="size-3 animate-pulse" />
									live
								</span>
							{:else}
								<p class="text-xs font-medium">{duration(r)}</p>
							{/if}
							<p class="text-xs text-muted-foreground">
								{formatBytes(Number(r.sizeBytes))} · {formatTs(r.startedAt, 'relative-short')}
							</p>
						</div>
					</a>
				</li>
			{/each}
		</ul>
	{/if}
</div>
