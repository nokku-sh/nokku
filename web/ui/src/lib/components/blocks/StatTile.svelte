<script lang="ts">
	import type { LucideIcon } from '@lucide/svelte';
	import type { Snippet } from 'svelte';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { toneText, type Tone } from '$lib/tone';
	import { cn } from '$lib/utils';

	interface Props {
		label: string;
		icon?: LucideIcon;
		value?: string | number;
		hint?: string;
		href?: string;
		/** Colors the value and border, e.g. destructive for failures. */
		tone?: Tone;
		loading?: boolean;
		/** Replaces the value line for richer content. */
		children?: Snippet;
		class?: string;
	}

	let {
		label,
		icon: Icon,
		value,
		hint,
		href,
		tone,
		loading = false,
		children,
		class: className
	}: Props = $props();
</script>

<svelte:element
	this={href ? 'a' : 'div'}
	{href}
	class={cn(
		'flex min-w-0 flex-col gap-1.5 rounded-xl border bg-card p-4',
		href && 'transition-colors hover:bg-muted/40',
		tone === 'destructive' && 'border-destructive/40',
		className
	)}
>
	<span class={['flex items-center gap-1.5 spec-label', tone && toneText[tone]]}>
		{#if Icon}<Icon class="size-3.5" />{/if}
		{label}
	</span>
	{#if loading}
		<Skeleton class="h-7 w-16" />
	{:else if children}
		{@render children()}
	{:else}
		<span class={['text-xl font-semibold tabular-nums', tone && toneText[tone]]}>{value}</span>
	{/if}
	{#if hint}
		<span class="truncate text-xs text-muted-foreground">{hint}</span>
	{/if}
</svelte:element>
