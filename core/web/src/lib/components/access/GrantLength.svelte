<script lang="ts">
	import { useFeatures } from '#lib/api/workspaces.svelte.js';
	import PlanBadge from '#lib/components/blocks/PlanBadge.svelte';
	import * as Select from '#lib/components/ui/select/index.js';
	import { formatHours } from '#lib/utils.js';
	import { Clock } from '@lucide/svelte';

	interface Props {
		/** Hours a new grant lasts, 0 is for good. */
		hours?: number;
	}

	let { hours = $bindable(0) }: Props = $props();

	const has = useFeatures();
	const lengths = [0, 1, 8, 24, 24 * 7, 24 * 30];
	const label = (h: number) => (h ? formatHours(h) : 'For good');
</script>

<div class="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
	<span id="grant-length">New grants last</span>
	<Select.Root
		type="single"
		value={String(hours)}
		onValueChange={(v) => (hours = Number(v))}
		disabled={has('expiring_access') !== true}
	>
		<Select.Trigger size="sm" aria-labelledby="grant-length">
			<Clock />
			{label(hours)}
		</Select.Trigger>
		<Select.Content>
			{#each lengths as h (h)}
				<Select.Item value={String(h)}>{label(h)}</Select.Item>
			{/each}
		</Select.Content>
	</Select.Root>
	<PlanBadge feature="expiring_access" />
</div>
