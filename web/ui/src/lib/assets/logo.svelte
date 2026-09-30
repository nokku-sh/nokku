<script lang="ts">
	import type { SVGAttributes } from 'svelte/elements';

	let { ...restProps }: SVGAttributes<SVGSVGElement> = $props();
</script>

<!-- The prompt mark: two dots and a caret, in the brand colors. -->
<svg
	viewBox="0 0 111.42 68.55"
	xmlns="http://www.w3.org/2000/svg"
	aria-label="Nokku"
	{...restProps}
>
	<g transform="translate(-65.274 -92.63)">
		<ellipse class="fill-brand-dot" cx="77.42" cy="126.905" rx="12.145" ry="12.248" />
		<ellipse class="fill-brand-dot" cx="111.759" cy="126.905" rx="12.145" ry="12.248" />
		<path
			class="stroke-brand-caret"
			fill="none"
			stroke-width="16.933"
			stroke-linecap="round"
			stroke-linejoin="round"
			d="m142.419 152.713 25.808-25.808m-25.808-25.808 25.808 25.808"
		/>
	</g>
</svg>
