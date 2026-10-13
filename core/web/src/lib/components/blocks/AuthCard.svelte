<script lang="ts">
	import type { LucideIcon } from '@lucide/svelte';
	import type { Snippet } from 'svelte';
	import { Logo } from '#lib/assets/index.js';
	import { toneSoft, type Tone } from '#lib/tone.js';

	interface Props {
		title: string;
		description?: string;
		/** Replaces the logo, e.g. a check after a reset. */
		icon?: LucideIcon;
		/** Colors the icon. Unset is the brand color. */
		tone?: Tone;
		wide?: boolean;
		children?: Snippet;
		/** The muted strip under the card, usually a sign up or sign in link. */
		footer?: Snippet;
	}

	let { title, description, icon: Icon, tone, wide = false, children, footer }: Props = $props();
</script>

<svelte:head>
	<title>{title} · Nokku</title>
</svelte:head>

<div
	class={[
		'm-auto w-full overflow-hidden rounded-xl border bg-muted',
		wide ? 'max-w-md' : 'max-w-sm'
	]}
>
	<div
		class="-m-px flex flex-col gap-6 rounded-xl border bg-card p-6 **:data-[slot=field-separator-content]:bg-card"
	>
		<div class="flex flex-col items-center gap-3 text-center">
			{#if Icon}
				<div
					class={[
						'flex size-12 items-center justify-center rounded-full',
						tone ? toneSoft[tone] : 'bg-primary/15 text-primary'
					]}
				>
					<Icon class="size-6" />
				</div>
			{:else}
				<Logo class="w-10 py-2" />
			{/if}
			<div class="flex flex-col gap-1">
				<h1 class="text-xl font-semibold tracking-tight">{title}</h1>
				{#if description}
					<p class="text-sm text-balance text-muted-foreground">{description}</p>
				{/if}
			</div>
		</div>
		{@render children?.()}
	</div>
	{#if footer}
		<div class="p-3 text-center text-sm text-muted-foreground">{@render footer()}</div>
	{/if}
</div>
