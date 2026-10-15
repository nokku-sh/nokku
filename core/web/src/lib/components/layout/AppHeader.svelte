<script lang="ts">
	import { page } from '$app/state';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Kbd from '#lib/components/ui/kbd/index.js';
	import { Separator } from '#lib/components/ui/separator/index.js';
	import * as Sidebar from '#lib/components/ui/sidebar/index.js';
	import { Search } from '@lucide/svelte';
	import { openPalette } from './CommandPalette.svelte';

	// The palette answers both, the hint shows the one this keyboard has.
	const mod = /Mac|iPhone|iPad/.test(navigator.userAgent) ? '⌘' : 'Ctrl ';

	// The URL as a shell path. Every prefix is a page, groups redirect to their first child.
	const segments = $derived(
		page.url.pathname
			.split('/')
			.filter(Boolean)
			.map((name, i, all) => ({ name, url: '/' + all.slice(0, i + 1).join('/') }))
	);
</script>

<header
	class="flex h-16 shrink-0 items-center gap-2 border-b transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-16"
>
	<div class="flex w-full items-center gap-1 px-4 lg:gap-2 lg:px-6">
		<Sidebar.Trigger class="-ml-1" />
		<!-- The trigger pads its icon, so the left margin is smaller to look centered. -->
		<Separator
			orientation="vertical"
			class="mr-2 ml-px data-vertical:h-4 data-vertical:self-center"
		/>

		<nav aria-label="Location" class="flex min-w-0 items-center font-mono text-sm">
			<a href="/" class="text-primary hover:underline" aria-label="Dashboard">~</a>
			{#each segments as seg, i (seg.url)}
				<span class="text-muted-foreground/60">/</span>
				{#if i === segments.length - 1}
					<span class="truncate text-foreground" aria-current="page">{seg.name}</span>
				{:else}
					<a href={seg.url} class="shrink-0 text-muted-foreground hover:text-foreground">
						{seg.name}
					</a>
				{/if}
			{/each}
		</nav>

		<Button
			variant="outline"
			size="sm"
			class="ml-auto gap-2 text-muted-foreground"
			aria-label="Search and commands"
			onclick={openPalette}
		>
			<Search data-icon="inline-start" />
			<span class="hidden sm:inline">Search</span>
			<Kbd.Root class="hidden sm:inline-flex">{mod}K</Kbd.Root>
		</Button>
	</div>
</header>
