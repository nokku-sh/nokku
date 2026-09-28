<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { LucideIcon } from '@lucide/svelte';
	import * as Card from '$lib/components/ui/card';
	import { Skeleton } from '$lib/components/ui/skeleton';
	import { cn } from '$lib/utils';

	interface Props {
		label: string;
		value?: string | number;
		sub?: string;
		icon?: LucideIcon;
		href?: string;
		tone?: 'default' | 'success' | 'warn' | 'danger';
		loading?: boolean;
		children?: Snippet;
	}

	let {
		label,
		value,
		sub,
		icon: Icon,
		href,
		tone = 'default',
		loading,
		children
	}: Props = $props();

	const tones: Record<string, string> = {
		default: 'bg-primary/10 text-primary',
		success: 'bg-success/10 text-success',
		warn: 'bg-warning/10 text-warning',
		danger: 'bg-destructive/10 text-destructive'
	};

	const iconTone = $derived(tones[tone]);
</script>

{#snippet body()}
	<Card.Root
		class={cn(
			'gap-0 p-5 transition-all',
			href && 'group-hover:border-primary/30 group-hover:shadow-md'
		)}
	>
		<div class="flex items-start justify-between gap-3">
			<div class="min-w-0 space-y-1">
				<p class="text-xs font-medium tracking-wide text-muted-foreground uppercase">{label}</p>
				{#if loading}
					<Skeleton class="h-7 w-14" />
				{:else}
					<p class="text-2xl font-bold tracking-tight">{value}</p>
				{/if}
				{#if sub && !loading}
					<p class="truncate text-xs text-muted-foreground">{sub}</p>
				{/if}
				{@render children?.()}
			</div>
			{#if Icon}
				<div class={cn('shrink-0 rounded-lg p-2', iconTone)}>
					<Icon class="size-4" />
				</div>
			{/if}
		</div>
	</Card.Root>
{/snippet}

{#if href}
	<a
		{href}
		class="group block h-full rounded-xl outline-none focus-visible:ring-2 focus-visible:ring-ring"
	>
		{@render body()}
	</a>
{:else}
	<div class="h-full">{@render body()}</div>
{/if}
