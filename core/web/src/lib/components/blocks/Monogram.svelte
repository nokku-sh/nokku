<script lang="ts" module>
	// Calm hues away from the red and amber that status uses.
	const hues = [205, 245, 285, 330, 150, 95];

	function hueOf(name: string): number {
		let h = 0;
		for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
		return hues[h % hues.length];
	}

	/** spry-mountain is SM, Platform team is PT, gateway is GA. */
	function initials(name: string): string {
		const words = name.split(/[\s._-]+/).filter(Boolean);
		const letters = words.length > 1 ? words[0][0] + words[1][0] : (words[0] ?? '?').slice(0, 2);
		return letters.toUpperCase();
	}
</script>

<script lang="ts">
	import { cn } from '#lib/utils.js';

	let { name, class: className }: { name: string; class?: string } = $props();
</script>

<!-- The same name always gets the same letters and tint, in a row and in its sheet. -->
<div
	class={cn(
		'flex size-8 shrink-0 items-center justify-center rounded-lg monogram text-xs font-semibold tracking-wide',
		className
	)}
	style:--hue={hueOf(name)}
	aria-hidden="true"
>
	{initials(name)}
</div>
