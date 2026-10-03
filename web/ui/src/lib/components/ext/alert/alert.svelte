<script lang="ts" module>
	import type { AlertVariant as BaseVariant } from '#lib/components/ui/alert/index.js';

	const tones = {
		success:
			'border-success/25 bg-success/5 text-success *:data-[slot=alert-description]:text-foreground/80',
		warning:
			'border-warning/25 bg-warning/5 text-warning *:data-[slot=alert-description]:text-foreground/80',
		info: 'border-info/25 bg-info/5 text-info *:data-[slot=alert-description]:text-foreground/80'
	};
	type Tone = keyof typeof tones;

	export type AlertVariant = BaseVariant | Tone;

	const isTone = (v: AlertVariant): v is Tone => typeof v === 'string' && v in tones;
</script>

<script lang="ts">
	import { Root } from '#lib/components/ui/alert/index.js';
	import { cn } from '#lib/utils.js';
	import type { ComponentProps } from 'svelte';

	let {
		ref = $bindable(null),
		variant = 'default',
		class: className,
		...restProps
	}: Omit<ComponentProps<typeof Root>, 'variant'> & { variant?: AlertVariant } = $props();
</script>

<Root
	bind:ref
	variant={isTone(variant) ? 'default' : variant}
	class={cn(isTone(variant) && tones[variant], className)}
	{...restProps}
/>
