<script lang="ts">
	import RangeCalendar from '$lib/components/ui/range-calendar/range-calendar.svelte';
	import * as Popover from '$lib/components/ui/popover/index.js';
	import { Button } from '$lib/components/ui/button/index.js';
	import ChevronDownIcon from '@lucide/svelte/icons/chevron-down';
	import { getLocalTimeZone } from '@internationalized/date';
	import type { DateRange } from 'bits-ui';
	import { Calendar } from '@lucide/svelte';

	const id = $props.id();
	interface Props {
		value?: DateRange;
	}
	let { value = $bindable(), ...restProps }: Props = $props();

	let initialValue = $state<DateRange | undefined>(value);
	function reset() {
		value = initialValue ? initialValue : undefined;
	}
</script>

<Popover.Root {...restProps}>
	<Popover.Trigger id="{id}-dates">
		{#snippet child({ props })}
			<Button {...props} variant="outline" class="min-w-60 justify-between font-normal">
				<div class="flex items-center gap-2">
					<Calendar size={16} />
					{value?.start && value?.end
						? `${value.start.toDate(getLocalTimeZone()).toLocaleDateString()} - ${value.end.toDate(getLocalTimeZone()).toLocaleDateString()}`
						: 'Pick a date'}
				</div>
				<ChevronDownIcon />
			</Button>
		{/snippet}
	</Popover.Trigger>
	<Popover.Content class="w-auto overflow-hidden p-0" align="start">
		<RangeCalendar bind:value />
		<Button size="sm" variant="secondary" onclick={reset} class="mt-2 w-full bg-accent">
			Reset
		</Button>
	</Popover.Content>
</Popover.Root>
