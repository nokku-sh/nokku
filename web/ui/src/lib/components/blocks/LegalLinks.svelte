<script lang="ts">
	import { ImprintURL, PrivacyURL, ToSURL } from '$lib/config';
	import { cn } from '$lib/utils';

	let { class: className }: { class?: string } = $props();

	const links = [
		{ label: 'Terms', href: ToSURL },
		{ label: 'Privacy', href: PrivacyURL },
		{ label: 'Imprint', href: ImprintURL }
	];
</script>

<!-- The imprint has to stay one click away on every page, so this lives in both footers. -->
<nav
	aria-label="Legal"
	class={cn('flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground', className)}
>
	<span>&copy; {new Date().getFullYear()} Mizuchi Labs</span>
	{#each links as l (l.label)}
		<span aria-hidden="true" class="text-muted-foreground/40">·</span>
		<a href={l.href} target="_blank" rel="noopener" class="transition-colors hover:text-foreground">
			{l.label}
		</a>
	{/each}
</nav>
