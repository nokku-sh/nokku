<script lang="ts">
	import type { TerminalSession } from '#lib/api/terminal.svelte.js';
	import '@xterm/xterm/css/xterm.css';

	interface Props {
		session: TerminalSession;
		visible?: boolean;
	}
	let { session, visible = true }: Props = $props();

	function mount(el: HTMLElement) {
		session.attach(el);
		const observer = new ResizeObserver(() => session.fit());
		observer.observe(el);
		return () => observer.disconnect();
	}

	$effect(() => {
		if (visible) {
			// Let the DOM settle after the display change.
			requestAnimationFrame(() => {
				session.fit();
				session.focus();
			});
		}
	});
</script>

<!-- xterm only fills whole rows, the terminal color covers the rest. -->
<div
	class={['h-full w-full overflow-hidden bg-terminal', !visible && 'hidden']}
	{@attach mount}
></div>
