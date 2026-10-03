<script lang="ts" module>
	import type { BadgeVariant as BaseVariant } from '#lib/components/ui/badge/index.js';

	const tones = {
		success: 'bg-success/10 text-success [a]:hover:bg-success/20',
		warning: 'bg-warning/10 text-warning [a]:hover:bg-warning/20',
		info: 'bg-info/10 text-info [a]:hover:bg-info/20',
		muted: 'bg-muted text-muted-foreground [a]:hover:bg-muted/80'
	};
	type Tone = keyof typeof tones;

	export type BadgeVariant = BaseVariant | Tone;

	const isTone = (v: BadgeVariant): v is Tone => typeof v === 'string' && v in tones;
</script>

<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { cn } from '#lib/utils.js';
	import type { ComponentProps } from 'svelte';

	let {
		ref = $bindable(null),
		variant = 'default',
		class: className,
		...restProps
	}: Omit<ComponentProps<typeof Badge>, 'variant'> & { variant?: BadgeVariant } = $props();
</script>

<Badge
	bind:ref
	variant={isTone(variant) ? 'secondary' : variant}
	class={cn(isTone(variant) && tones[variant], className)}
	{...restProps}
/>
