<script lang="ts">
	import type { LucideIcon } from '@lucide/svelte';
	import type { Snippet } from 'svelte';

	interface Props {
		title: string;
		description?: string;
		icon?: LucideIcon;
		children?: Snippet;
	}

	let { title, description, icon: Icon, children }: Props = $props();
</script>

<svelte:head>
	<title>{title}</title>
	{#if description}
		<meta name="description" content={description} />
	{/if}
</svelte:head>

<div class="mb-4 flex items-center justify-between">
	<div class="flex items-center gap-2">
		{#if Icon}
			<div class="rounded-full bg-primary/10 p-2.5">
				<Icon class="text-primary" size={20} />
			</div>
		{/if}
		<div class="flex flex-col">
			<h1 class="text-2xl font-bold tracking-tight">{title}</h1>
			{#if description}
				<p class="text-muted-foreground">{description}</p>
			{/if}
		</div>
	</div>
	{#if children}
		<div class="flex items-center gap-2">
			{@render children()}
		</div>
	{/if}
</div>
