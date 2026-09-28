<script lang="ts">
	import { onMount } from 'svelte';
	import { openTerminal } from '$lib/api/terminal.svelte';
	import type { TerminalHandle, TerminalSession } from '$lib/api/terminal.svelte';
	import '@xterm/xterm/css/xterm.css';

	interface Props {
		session: TerminalSession;
		visible?: boolean;
	}
	let { session, visible = true }: Props = $props();

	let containerEl: HTMLDivElement | undefined = $state();
	let handle: TerminalHandle | undefined = $state();

	onMount(() => {
		if (!containerEl) return;

		handle = openTerminal(session.daemonID, session.id, containerEl);

		const observer = new ResizeObserver(() => {
			handle?.fitAddon.fit();
		});
		observer.observe(containerEl);

		return () => {
			observer.disconnect();
			handle?.dispose();
		};
	});

	$effect(() => {
		if (visible && handle) {
			// Let the DOM settle after the display change.
			requestAnimationFrame(() => {
				handle?.fitAddon.fit();
				handle?.terminal.focus();
			});
		}
	});
</script>

<div
	class="h-full w-full overflow-hidden rounded-b-lg"
	class:hidden={!visible}
	bind:this={containerEl}
></div>
