<script lang="ts" module>
	import { page } from '$app/state';
	import { timestampFromDate } from '@bufbuild/protobuf/wkt';
	import { getLocalTimeZone, parseDate, type DateValue } from '@internationalized/date';

	export const presets = [
		{ value: '24h', label: 'Last 24 hours', hours: 24 },
		{ value: '7d', label: 'Last 7 days', hours: 24 * 7 },
		{ value: '30d', label: 'Last 30 days', hours: 24 * 30 },
		{ value: '90d', label: 'Last 90 days', hours: 24 * 90 }
	];
	const DEFAULT = '7d';

	/** The active range from the URL: a preset, or custom whole days. */
	export function currentRange(utc: boolean) {
		const from = page.url.searchParams.get('from');
		const to = page.url.searchParams.get('to');
		const tz = utc ? 'UTC' : getLocalTimeZone();
		if (from && to) {
			try {
				const start = parseDate(from);
				const end = parseDate(to);
				return {
					label: `${start.toString()} – ${end.toString()}`,
					start,
					end,
					startDate: timestampFromDate(start.toDate(tz)),
					// The end day counts in full.
					endDate: timestampFromDate(end.add({ days: 1 }).toDate(tz))
				};
			} catch {
				// A hand edited URL falls back to the default preset.
			}
		}
		const preset =
			presets.find((p) => p.value === page.url.searchParams.get('range')) ??
			presets.find((p) => p.value === DEFAULT)!;
		// Open ended, so events that arrive while the page is open still show up.
		return {
			label: preset.label,
			preset: preset.value,
			startDate: timestampFromDate(new Date(Date.now() - preset.hours * 3600_000)),
			endDate: undefined
		};
	}
</script>

<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import * as Popover from '$lib/components/ui/popover';
	import RangeCalendar from '$lib/components/ui/range-calendar/range-calendar.svelte';
	import { Separator } from '$lib/components/ui/separator';
	import type { DateRange } from 'bits-ui';
	import { CalendarDays, ChevronDown } from '@lucide/svelte';
	import { setParams } from './audit';

	let { utc }: { utc: boolean } = $props();

	let open = $state(false);
	const range = $derived(currentRange(utc));
	let custom = $state<DateRange>();

	function pick(preset: string) {
		setParams({ range: preset === DEFAULT ? undefined : preset, from: undefined, to: undefined });
		open = false;
	}

	function applyCustom(value: DateRange | undefined) {
		const start = value?.start as DateValue | undefined;
		const end = value?.end as DateValue | undefined;
		if (!start || !end) return;
		setParams({ range: undefined, from: start.toString(), to: end.toString() });
		open = false;
	}
</script>

<Popover.Root bind:open>
	<Popover.Trigger>
		{#snippet child({ props })}
			<Button {...props} variant="outline" size="sm">
				<CalendarDays data-icon="inline-start" />
				{range.label}
				<ChevronDown data-icon="inline-end" />
			</Button>
		{/snippet}
	</Popover.Trigger>
	<Popover.Content align="end" class="w-auto p-0">
		<div class="flex flex-col sm:flex-row">
			<div class="flex flex-col gap-0.5 p-2 sm:w-40">
				{#each presets as p (p.value)}
					<Button
						variant={range.preset === p.value ? 'secondary' : 'ghost'}
						size="sm"
						class="justify-start"
						onclick={() => pick(p.value)}
					>
						{p.label}
					</Button>
				{/each}
			</div>
			<Separator orientation="vertical" class="hidden sm:block" />
			<RangeCalendar bind:value={custom} onValueChange={applyCustom} numberOfMonths={1} />
		</div>
	</Popover.Content>
</Popover.Root>
