<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { LucideIcon } from '@lucide/svelte';
	import { cn } from '#lib/utils.js';

	interface Props {
		title: string;
		icon?: LucideIcon;
		count?: number;
		description?: string;
		/** Right-aligned header action, e.g. an add button. */
		action?: Snippet;
		tone?: 'default' | 'destructive';
		class?: string;
		children: Snippet;
	}

	let {
		title,
		icon: Icon,
		count,
		description,
		action,
		tone = 'default',
		class: className,
		children
	}: Props = $props();
</script>

<section class={cn('flex flex-col gap-3 py-5 first:pt-0 last:pb-0', className)}>
	<header class="flex min-h-7 items-center gap-2">
		{#if Icon}
			<Icon
				class={cn('size-4', tone === 'destructive' ? 'text-destructive' : 'text-muted-foreground')}
			/>
		{/if}
		<h3 class={cn('text-sm font-medium', tone === 'destructive' && 'text-destructive')}>{title}</h3>
		{#if count !== undefined}
			<span class="rounded-full bg-muted px-1.5 py-px text-xs text-muted-foreground tabular-nums">
				{count}
			</span>
		{/if}
		{#if action}
			<div class="ml-auto flex items-center gap-1">{@render action()}</div>
		{/if}
	</header>
	{#if description}
		<p class="-mt-2 text-xs text-muted-foreground">{description}</p>
	{/if}
	{@render children()}
</section>
