<script lang="ts" module>
	import { timestampFromDate } from '@bufbuild/protobuf/wkt';
	import { getLocalTimeZone, today, type DateValue } from '@internationalized/date';

	const presets = [
		{ value: '30', label: '30 days' },
		{ value: '90', label: '90 days' },
		{ value: '365', label: '1 year' },
		{ value: 'never', label: 'Never' },
		{ value: 'custom', label: 'Custom' }
	];

	export class TokenExpiry {
		preset = $state('90');
		custom = $state<DateValue>();
		date = $derived.by(() => {
			if (this.preset === 'never') return undefined;
			if (this.preset === 'custom') return this.custom;
			return today(getLocalTimeZone()).add({ days: Number(this.preset) });
		});

		get timestamp() {
			return this.date ? timestampFromDate(this.date.toDate(getLocalTimeZone())) : undefined;
		}
	}
</script>

<script lang="ts">
	import { Button } from '#lib/components/ui/button/index.js';
	import { Calendar } from '#lib/components/ui/calendar/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import * as Popover from '#lib/components/ui/popover/index.js';
	import * as ToggleGroup from '#lib/components/ui/toggle-group/index.js';
	import { DateValueFormat } from '#lib/utils.js';
	import { CalendarIcon } from '@lucide/svelte';

	let { expiry }: { expiry: TokenExpiry } = $props();

	let calendarOpen = $state(false);
</script>

<Field.Set>
	<Field.Legend variant="label">Token expires</Field.Legend>
	<ToggleGroup.Root
		type="single"
		variant="outline"
		size="sm"
		value={expiry.preset}
		onValueChange={(v) => {
			if (!v) return;
			expiry.preset = v;
			calendarOpen = v === 'custom';
		}}
		class="w-full flex-wrap"
	>
		{#each presets as p (p.value)}
			<ToggleGroup.Item value={p.value} class="flex-1">{p.label}</ToggleGroup.Item>
		{/each}
	</ToggleGroup.Root>
	{#if expiry.preset === 'custom'}
		<Popover.Root bind:open={calendarOpen}>
			<Popover.Trigger>
				{#snippet child({ props })}
					<Button {...props} variant="outline" class="w-full justify-start font-normal">
						<CalendarIcon data-icon="inline-start" />
						{expiry.custom ? DateValueFormat(expiry.custom) : 'Pick a date'}
					</Button>
				{/snippet}
			</Popover.Trigger>
			<Popover.Content class="w-auto p-0" align="start">
				<Calendar
					type="single"
					bind:value={expiry.custom}
					minValue={today(getLocalTimeZone()).add({ days: 1 })}
					onValueChange={() => (calendarOpen = false)}
				/>
			</Popover.Content>
		</Popover.Root>
	{/if}
	<Field.Description>
		{#if expiry.date}
			Stops working on {DateValueFormat(expiry.date)}.
		{:else if expiry.preset === 'never'}
			Never expires. Revoke it if it leaks.
		{/if}
	</Field.Description>
</Field.Set>
