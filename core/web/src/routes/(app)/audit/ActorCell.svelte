<script lang="ts">
	import type { EventLog } from '#lib/gen/nokku/v1/util_pb.js';
	import { kindIcon, kindOf, setParams } from '#lib/components/audit/audit.js';

	let { log }: { log: EventLog } = $props();

	const Icon = $derived(kindIcon(log.actorKind));
	// The filter only takes UUIDs, SCIM and system actors can't be picked.
	const filterable = $derived(/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(log.actorId));
	const name = $derived(log.actorName || (log.actorId ? `${log.actorId.slice(0, 8)}…` : 'unknown'));
	// An email is a machine value, set like the one in the users list.
	const mono = $derived(name.includes('@'));
</script>

<div class="flex min-w-0 items-center gap-2">
	<Icon class="size-4 shrink-0 text-muted-foreground" />
	<div class="flex min-w-0 flex-col">
		{#if filterable}
			<button
				type="button"
				class={[
					'truncate rounded-sm text-left underline decoration-muted-foreground/40 decoration-dotted underline-offset-2 hover:decoration-current focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
					mono ? 'font-mono text-xs' : 'text-sm'
				]}
				title="Show only events by this actor"
				onclick={() => setParams({ actor: log.actorId })}
			>
				{name}
			</button>
		{:else}
			<span class={['truncate', mono ? 'font-mono text-xs' : 'text-sm']}>{name}</span>
		{/if}
		<span class="text-xs text-muted-foreground">{kindOf(log.actorKind)?.one ?? log.actorKind}</span>
	</div>
</div>
