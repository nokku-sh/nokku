<script lang="ts">
	import { dashboard } from '#lib/api/dashboard.svelte.js';
	import { recordings } from '#lib/api/recordings.svelte.js';
	import * as HoverCard from '#lib/components/ui/hover-card/index.js';
	import { Progress } from '#lib/components/ui/progress/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { cn, formatBytes } from '#lib/utils.js';
	import { Database, TriangleAlert } from '@lucide/svelte';

	const list = recordings.list();
	// The plan itself is for admins, the dashboard carries the quota for every role here.
	const overview = dashboard.get(() => true);

	// -1 is unlimited.
	const limitBytes = $derived(Number(overview.data?.recordingQuotaBytes ?? 0));
	const unlimited = $derived(limitBytes <= 0);
	const usedBytes = $derived(Number(list.data?.totalBytes ?? 0));

	const pct = $derived(unlimited ? 0 : Math.min(100, (usedBytes / limitBytes) * 100));
	const level = $derived(pct >= 90 ? 'danger' : pct >= 75 ? 'warn' : 'ok');

	const pillClass = $derived(
		level === 'danger'
			? 'border-destructive/30 bg-destructive/10 text-destructive'
			: level === 'warn'
				? 'border-warning/30 bg-warning/10 text-warning'
				: ''
	);
	const progressClass = $derived(
		level === 'danger'
			? '[&_[data-slot=progress-indicator]]:bg-destructive'
			: level === 'warn'
				? '[&_[data-slot=progress-indicator]]:bg-warning'
				: ''
	);
</script>

<HoverCard.Root>
	<HoverCard.Trigger>
		{#snippet child({ props })}
			<div
				{...props}
				class={cn(
					'flex cursor-default items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium',
					pillClass
				)}
			>
				<Database size={12} />
				<span>
					{unlimited ? `${formatBytes(usedBytes)} stored` : `${Math.round(pct)}% storage used`}
				</span>
			</div>
		{/snippet}
	</HoverCard.Trigger>

	<HoverCard.Content align="end" side="bottom" class="flex w-64 flex-col gap-2">
		<p class="text-xs font-medium">Recording storage</p>
		{#if list.isPending}
			<Skeleton class="h-4 w-full" />
			<Skeleton class="h-1 w-full" />
		{:else if unlimited}
			<p class="text-xs text-muted-foreground">
				{formatBytes(usedBytes)} stored, no quota on your plan.
			</p>
		{:else}
			<div class="flex items-baseline justify-between text-xs">
				<span class="text-muted-foreground">
					{formatBytes(usedBytes)} of {formatBytes(limitBytes)} used
				</span>
				<span class="font-medium">{Math.round(pct)}%</span>
			</div>
			<Progress value={pct} class={progressClass} />
			{#if pct >= 90}
				<p class="flex items-start gap-1 text-xs text-destructive">
					<TriangleAlert size={12} class="mt-0.5 shrink-0" />
					Recordings older than a day are deleted to make room. If that is not enough, new ones wait on
					their server.
				</p>
			{/if}
		{/if}
	</HoverCard.Content>
</HoverCard.Root>
