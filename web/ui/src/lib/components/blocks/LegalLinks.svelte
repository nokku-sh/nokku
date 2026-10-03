<script lang="ts">
	import { util } from '#lib/api/workspaces.svelte.js';
	import { cn } from '#lib/utils.js';

	let { class: className }: { class?: string } = $props();

	const info = util.instanceInfo();
	const links = $derived(
		[
			{ label: 'Website', href: info.data?.websiteUrl },
			{ label: 'Terms', href: info.data?.termsUrl },
			{ label: 'Privacy', href: info.data?.privacyUrl },
			{ label: 'Imprint', href: info.data?.imprintUrl }
		].filter((l) => l.href)
	);
</script>

<!-- Whoever runs this server sets these. Self-hosted servers usually leave them out. -->
{#if info.data?.operatorName || links.length}
	<nav
		aria-label="Legal"
		class={cn(
			'flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground',
			className
		)}
	>
		{#if info.data?.operatorName}
			<span>&copy; {new Date().getFullYear()} {info.data.operatorName}</span>
		{/if}
		{#each links as l, i (l.label)}
			{#if i > 0 || info.data?.operatorName}
				<span aria-hidden="true" class="text-muted-foreground/40">·</span>
			{/if}
			<a
				href={l.href}
				target="_blank"
				rel="noopener"
				class="transition-colors hover:text-foreground"
			>
				{l.label}
			</a>
		{/each}
	</nav>
{:else}
	<span class={cn('text-xs text-muted-foreground', className)}>Powered by Nokku</span>
{/if}
