<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import type { EventLog } from '#lib/gen/nokku/v1/util_pb.js';
	import {
		eventHappened,
		eventLabel,
		eventWhat,
		outcomeLabel,
		outcomeOf,
		setParams
	} from '#lib/components/audit/audit.js';
	import EventIcon from '#lib/components/audit/EventIcon.svelte';
	import { formatTs } from '#lib/utils.js';

	let { log }: { log: EventLog } = $props();

	const outcome = $derived(outcomeOf(log));
	const code = $derived(log.details?.['code'] as string | undefined);
	// Older events stored only the id, they show it as before.
	const what = $derived(eventWhat(log));
	const happened = $derived(eventHappened(log));
</script>

<div class="flex min-w-0 items-center gap-2.5">
	<EventIcon {log} class="size-7 rounded-md [&_svg]:size-3.5" />
	<div class="flex min-w-0 flex-col">
		<span class="flex items-center gap-1.5 text-sm font-medium">
			<span class="truncate">{eventLabel(log.action)}</span>
			{#if outcome !== 'succeeded'}
				<Tooltip.Root>
					<Tooltip.Trigger>
						{#snippet child({ props })}
							<Badge {...props} variant="destructive">
								{outcomeLabel[outcome]}
							</Badge>
						{/snippet}
					</Tooltip.Trigger>
					<Tooltip.Content>{code?.replace(/_/g, ' ') ?? 'No error code recorded'}</Tooltip.Content>
				</Tooltip.Root>
			{/if}
		</span>
		{#if log.target}
			<button
				type="button"
				class={[
					'max-w-80 truncate rounded-sm text-left text-xs text-muted-foreground underline decoration-muted-foreground/40 decoration-dotted underline-offset-2 hover:text-foreground hover:decoration-current focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
					!what && 'font-mono'
				]}
				title={`Show only events about this (${log.target})`}
				onclick={() => setParams({ target: log.target })}
			>
				{what ?? log.target}
			</button>
		{:else if what}
			<span class="max-w-80 truncate text-xs text-muted-foreground">{what}</span>
		{/if}
		{#if happened}
			<span class="text-xs text-muted-foreground">
				Happened {formatTs(happened, 'withTime')}, reported later
			</span>
		{/if}
	</div>
</div>
