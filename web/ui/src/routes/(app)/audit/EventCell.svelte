<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import type { EventLog } from '#lib/gen/nokku/v1/util_pb.js';
	import { eventLabel, outcomeLabel, outcomeOf, setParams } from '#lib/components/audit/audit.js';
	import EventIcon from '#lib/components/audit/EventIcon.svelte';

	let { log }: { log: EventLog } = $props();

	const outcome = $derived(outcomeOf(log));
	const code = $derived(log.details?.['code'] as string | undefined);
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
				class="max-w-64 truncate text-left font-mono text-xs text-muted-foreground hover:text-foreground hover:underline"
				title="Show only events for this target"
				onclick={() => setParams({ target: log.target })}
			>
				{log.target}
			</button>
		{/if}
	</div>
</div>
