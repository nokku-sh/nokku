<script lang="ts">
	import type { LucideIcon } from '@lucide/svelte';
	import type { Snippet } from 'svelte';
	import { page } from '$app/state';
	import { routeFor } from './routes';

	interface Props {
		title: string;
		description?: string;
		/** Only for pages outside the nav, others take the nav icon. */
		icon?: LucideIcon;
		/** Actions, right aligned. */
		children?: Snippet;
	}

	let { title, description, icon, children }: Props = $props();

	const Icon = $derived(routeFor(page.url.pathname)?.icon ?? icon);
</script>

<svelte:head>
	<title>{title} · Nokku</title>
	{#if description}
		<meta name="description" content={description} />
	{/if}
</svelte:head>

<header class="flex flex-wrap items-end justify-between gap-4">
	<div class="flex min-w-0 items-center gap-3">
		{#if Icon}
			<div
				class="flex size-11 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary"
			>
				<Icon class="size-5" />
			</div>
		{/if}
		<div class="flex min-w-0 flex-col">
			<h1 class="truncate text-2xl font-semibold tracking-tight">{title}</h1>
			{#if description}
				<p class="text-sm text-muted-foreground">{description}</p>
			{/if}
		</div>
	</div>
	{#if children}
		<div class="flex flex-wrap items-center gap-2">
			{@render children()}
		</div>
	{/if}
</header>
