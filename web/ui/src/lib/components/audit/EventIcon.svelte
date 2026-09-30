<script lang="ts">
	import type { EventLog } from '$lib/gen/nokku/v1/util_pb';
	import { cn } from '$lib/utils';
	import { Activity } from '@lucide/svelte';
	import { areaOf, outcomeOf } from './audit';

	let { log, class: className }: { log: EventLog; class?: string } = $props();

	const Icon = $derived(areaOf(log.action)?.icon ?? Activity);
	const ok = $derived(outcomeOf(log) === 'succeeded');
</script>

<div
	class={cn(
		'flex size-8 shrink-0 items-center justify-center rounded-lg',
		ok ? 'bg-muted text-muted-foreground' : 'bg-destructive/10 text-destructive',
		className
	)}
>
	<Icon class="size-4" />
</div>
