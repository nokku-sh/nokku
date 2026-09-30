<script lang="ts">
	import type { Snippet } from 'svelte';
	import { describeAgent } from '$lib/agent';
	import { sessionMethodLabel } from '$lib/api/session.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import * as Item from '$lib/components/ui/item';
	import type { EventLog } from '$lib/gen/nokku/v1/util_pb';
	import { cn } from '$lib/utils';
	import EventIcon from './EventIcon.svelte';
	import { eventLabel, outcomeLabel, outcomeOf } from './audit';

	interface Props {
		log: EventLog;
		/** Makes the row a button, usually to open the ActivitySheet. */
		onclick?: () => void;
		title?: string;
		/** Right-aligned, usually a time. */
		meta?: string;
		/** Replaces the browser and IP line, e.g. with who did it. */
		subtitle?: string;
		/** Extra badges after the title. */
		badges?: Snippet;
	}

	let { log, onclick, title, meta, subtitle, badges }: Props = $props();

	const outcome = $derived(outcomeOf(log));
	const method = $derived.by(() => {
		const m = log.details?.['method'];
		return typeof m === 'string' && m ? sessionMethodLabel(m) : undefined;
	});
</script>

<Item.Root size="sm" class="rounded-none">
	{#snippet child({ props })}
		{#if onclick}
			<button
				type="button"
				{...props}
				class={cn(props.class as string, 'text-left hover:bg-muted/40')}
				{onclick}
			>
				{@render body()}
			</button>
		{:else}
			<div {...props}>{@render body()}</div>
		{/if}
	{/snippet}
</Item.Root>

{#snippet body()}
	<Item.Media>
		<EventIcon {log} />
	</Item.Media>
	<Item.Content class="min-w-0">
		<Item.Title class="flex-wrap">
			{title ?? eventLabel(log.action)}
			{#if method}<Badge variant="secondary">{method}</Badge>{/if}
			{#if outcome !== 'succeeded'}<Badge variant="destructive">{outcomeLabel[outcome]}</Badge>{/if}
			{@render badges?.()}
		</Item.Title>
		<Item.Description class="truncate">
			{subtitle ?? `${describeAgent(log.userAgent)}${log.ip ? ` · ${log.ip}` : ''}`}
		</Item.Description>
	</Item.Content>
	{#if meta}
		<Item.Actions class="font-mono text-xs text-muted-foreground tabular-nums">{meta}</Item.Actions>
	{/if}
{/snippet}
