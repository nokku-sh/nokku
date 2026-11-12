<script lang="ts">
	import EventRow from '#lib/components/audit/EventRow.svelte';
	import { eventWhat } from '#lib/components/audit/audit.js';
	import ActivitySheet from '#lib/components/sheets/ActivitySheet.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import type { GetDashboardResponse } from '#lib/gen/nokku/v1/dashboard_pb.js';
	import type { EventLog } from '#lib/gen/nokku/v1/util_pb.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { formatTs, listNames } from '#lib/utils.js';
	import { ArrowRight } from '@lucide/svelte';
	import { SvelteSet } from 'svelte/reactivity';

	let { data }: { data?: GetDashboardResponse } = $props();

	const events = $derived(data?.activity.reduce((a, b) => a + b, 0) ?? 0);
	const failures = $derived(data?.failures.reduce((a, b) => a + b, 0) ?? 0);
	const peak = $derived(Math.max(1, ...(data?.activity ?? [])));
	const label = (i: number) => {
		const h = 23 - i;
		return h === 0 ? 'this hour' : `${h}h ago`;
	};
	const busiest = $derived(data ? data.activity.indexOf(Math.max(...data.activity)) : -1);
	// The bars only speak to eyes, so the chart says its numbers out loud.
	const summary = $derived(
		`Audit events per hour over the last 24 hours. ${events} in total${failures ? `, ${failures} failed` : ''}${events && busiest >= 0 ? `. Busiest: ${label(busiest)}, ${data?.activity[busiest]} events` : ''}.`
	);

	let selected = $state<EventLog>();

	const by = (log: EventLog) => `by ${log.actorName || 'system'}`;
	const what = (log: EventLog) => [eventWhat(log), by(log)].filter(Boolean).join(' · ');

	// A sync that adds ten people is one thing that happened, not ten. Same event, same actor, one row.
	const changes = $derived(
		Object.entries(
			Object.groupBy(
				data?.recentChanges ?? [],
				(log) => `${log.action}:${log.actorId}:${String(log.details?.['method'] ?? '')}`
			)
		).map(([key, logs = []]) => ({ key, logs, first: logs[0] }))
	);
	const unfolded = new SvelteSet<string>();
	const toggle = (key: string) => (unfolded.has(key) ? unfolded.delete(key) : unfolded.add(key));
</script>

<ActivitySheet log={selected} onClose={() => (selected = undefined)} />

{#snippet change(log: EventLog)}
	<EventRow
		{log}
		onclick={() => (selected = log)}
		subtitle={what(log)}
		meta={formatTs(log.timestamp, 'relative-short')}
	/>
{/snippet}

<Card.Root class="gap-4">
	<Card.Header>
		<Card.Title><h2>Last 24 hours</h2></Card.Title>
		<Card.Description>
			{events} audit events{failures ? `, ${failures} failed` : ''}{data?.recentChanges.length
				? ', and the changes worth knowing about'
				: ''}
		</Card.Description>
		<Card.Action>
			<Button size="sm" variant="ghost" href="/audit">
				Audit log
				<ArrowRight data-icon="inline-end" />
			</Button>
		</Card.Action>
	</Card.Header>
	<Card.Content class="flex flex-col gap-4">
		{#if !data}
			<Skeleton class="h-16 w-full" />
		{:else}
			<div class="flex flex-col gap-1">
				<div class="flex h-14 items-end gap-0.5" role="img" aria-label={summary}>
					{#each data.activity as n, i (i)}
						{@const failed = data.failures[i] ?? 0}
						<div
							class="flex flex-1 flex-col justify-end overflow-hidden rounded-xs bg-primary/15"
							style:height="{Math.max(4, (n / peak) * 100)}%"
							title="{label(i)}: {n} events{failed ? `, ${failed} failed` : ''}"
						>
							{#if failed}
								<div class="bg-destructive" style:height="{(failed / Math.max(1, n)) * 100}%"></div>
							{/if}
							<div class="flex-1 bg-primary/60"></div>
						</div>
					{/each}
				</div>
				<div class="flex justify-between font-mono text-2xs text-muted-foreground">
					<span>24h ago</span>
					<span>now</span>
				</div>
			</div>

			{#if changes.length}
				<div class="divide-y overflow-hidden rounded-lg border">
					{#each changes as group (group.key)}
						{#if group.logs.length === 1}
							{@render change(group.first)}
						{:else}
							{@const open = unfolded.has(group.key)}
							<EventRow
								log={group.first}
								onclick={() => toggle(group.key)}
								expanded={open}
								subtitle={[
									listNames(
										group.logs.flatMap((l) => eventWhat(l) ?? []),
										2
									),
									by(group.first)
								]
									.filter(Boolean)
									.join(' · ')}
								meta={formatTs(group.first.timestamp, 'relative-short')}
							>
								{#snippet badges()}
									<Badge variant="outline" class="font-mono">{group.logs.length}×</Badge>
								{/snippet}
							</EventRow>
							{#if open}
								<div class="divide-y bg-muted/30 pl-6">
									{#each group.logs as log (log.id)}
										{@render change(log)}
									{/each}
								</div>
							{/if}
						{/if}
					{/each}
				</div>
			{:else}
				<p class="text-sm text-muted-foreground">No changes in the last 24 hours. Quiet day.</p>
			{/if}
		{/if}
	</Card.Content>
</Card.Root>
