<script lang="ts">
	import { mode, toggleMode } from 'mode-watcher';
	import { tick } from 'svelte';
	import { Sun, Moon } from '@lucide/svelte';
	import { Button } from '$lib/components/ui/button';

	let { ...restProps } = $props();

	async function handleToggleTheme(event: MouseEvent) {
		if (
			!document.startViewTransition ||
			window.matchMedia('(prefers-reduced-motion: reduce)').matches
		) {
			toggleMode();
			return;
		}

		const x = event.clientX;
		const y = event.clientY;

		const endRadius = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));

		const transition = document.startViewTransition(async () => {
			toggleMode();
			await tick(); // Wait for Svelte to update the DOM
		});

		transition.ready.then(() => {
			const clipPath = [`circle(0px at ${x}px ${y}px)`, `circle(${endRadius}px at ${x}px ${y}px)`];

			document.documentElement.animate(
				{
					clipPath: clipPath
				},
				{
					duration: 400,
					easing: 'ease-out',
					pseudoElement: '::view-transition-new(root)'
				}
			);
		});
	}
</script>

<Button
	variant="ghost"
	onclick={handleToggleTheme}
	size="icon-sm"
	aria-label="Toggle theme"
	{...restProps}
>
	{#if mode.current === 'dark'}
		<Sun />
	{:else}
		<Moon />
	{/if}
</Button>

<style>
	:global(::view-transition-old(root)),
	:global(::view-transition-new(root)) {
		animation: none !important;
		mix-blend-mode: normal !important;
	}

	:global(::view-transition-old(root)) {
		z-index: 1 !important;
	}

	:global(::view-transition-new(root)) {
		z-index: 2 !important;
	}
</style>
