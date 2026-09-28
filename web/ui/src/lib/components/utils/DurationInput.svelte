<script lang="ts">
	import { durationFromMs, durationMs, type Duration } from '@bufbuild/protobuf/wkt';
	import { ChevronDown, Clock } from '@lucide/svelte';
	import * as InputGroup from '$lib/components/ui/input-group';
	import * as DropdownMenu from '$lib/components/ui/dropdown-menu';
	import { cn } from '$lib/utils';

	type Unit = 'minutes' | 'hours' | 'days' | 'years';

	interface Props {
		value?: Duration | null;
		onchange?: (value: Duration) => void;
		placeholder?: string;
		disabled?: boolean;
		class?: string;
		min?: number;
		max?: number;
	}

	let {
		value = $bindable(),
		onchange,
		placeholder = 'Enter duration',
		disabled = false,
		class: className,
		min,
		max
	}: Props = $props();

	const units: { value: Unit; label: string; ms: number }[] = [
		{ value: 'minutes', label: 'Minutes', ms: 60 * 1000 },
		{ value: 'hours', label: 'Hours', ms: 60 * 60 * 1000 },
		{ value: 'days', label: 'Days', ms: 24 * 60 * 60 * 1000 },
		{ value: 'years', label: 'Years', ms: 365 * 24 * 60 * 60 * 1000 }
	];

	function getBestUnit(ms: number): Unit {
		if (ms === 0) return 'hours';
		const absMs = Math.abs(ms);

		for (let i = units.length - 1; i >= 0; i--) {
			if (absMs >= units[i].ms && absMs % units[i].ms === 0) {
				return units[i].value;
			}
		}

		if (absMs >= 365 * 24 * 60 * 60 * 1000) return 'years';
		if (absMs >= 24 * 60 * 60 * 1000) return 'days';
		if (absMs >= 60 * 60 * 1000) return 'hours';
		return 'minutes';
	}

	let selectedUnit = $state<Unit>(getBestUnit(value ? durationMs(value) : 0));

	let inputValue = $derived.by(() => {
		if (!value) return '';
		const ms = durationMs(value);
		const unit = units.find((u) => u.value === selectedUnit)!;
		const num = ms / unit.ms;
		return Number.isInteger(num) ? num.toString() : num.toFixed(2).replace(/\.?0+$/, '');
	});

	function getUnitMs(unit: Unit): number {
		return units.find((u) => u.value === unit)!.ms;
	}

	function handleInput(e: Event) {
		const target = e.target as HTMLInputElement;
		const num = parseFloat(target.value);

		if (isNaN(num) || target.value === '') {
			return;
		}

		let ms = num * getUnitMs(selectedUnit);

		if (min !== undefined) ms = Math.max(ms, min);
		if (max !== undefined) ms = Math.min(ms, max);

		const newDuration = durationFromMs(Math.round(ms));
		value = newDuration;
		onchange?.(newDuration);
	}

	function handleUnitChange(unit: Unit) {
		if (!value) {
			selectedUnit = unit;
			return;
		}

		selectedUnit = unit;
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
			e.preventDefault();
			const current = value ? durationMs(value) : 0;
			const step = getUnitMs(selectedUnit);
			const newMs = e.key === 'ArrowUp' ? current + step : Math.max(0, current - step);

			let ms = newMs;
			if (min !== undefined) ms = Math.max(ms, min);
			if (max !== undefined) ms = Math.min(ms, max);

			const newDuration = durationFromMs(Math.round(ms));
			value = newDuration;
			onchange?.(newDuration);
		}
	}

	const currentUnitLabel = $derived(units.find((u) => u.value === selectedUnit)?.value ?? 'hours');
</script>

<InputGroup.Root class={cn('w-full', className)}>
	<InputGroup.Addon class="text-muted-foreground">
		<Clock />
	</InputGroup.Addon>
	<InputGroup.Input
		type="number"
		value={inputValue}
		oninput={handleInput}
		onkeydown={handleKeydown}
		{placeholder}
		{disabled}
		class="[appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none"
	/>
	<InputGroup.Addon align="inline-end">
		<DropdownMenu.Root>
			<DropdownMenu.Trigger>
				{#snippet child({ props })}
					<InputGroup.Button
						{...props}
						variant="ghost"
						class="rounded-full bg-accent pe-1.5! text-xs font-medium"
						{disabled}
					>
						{currentUnitLabel}
						<ChevronDown class="ml-1 size-3" />
					</InputGroup.Button>
				{/snippet}
			</DropdownMenu.Trigger>
			<DropdownMenu.Content align="end" class="min-w-24">
				{#each units as unit}
					<DropdownMenu.Item
						class={cn(selectedUnit === unit.value && 'bg-accent')}
						onclick={() => handleUnitChange(unit.value)}
					>
						{unit.label}
					</DropdownMenu.Item>
				{/each}
			</DropdownMenu.Content>
		</DropdownMenu.Root>
	</InputGroup.Addon>
</InputGroup.Root>
