<script lang="ts">
	import { Button } from '#lib/components/ui/button/index.js';
	import { UseClipboard } from '#lib/hooks/use-clipboard.svelte.js';
	import { cn } from '#lib/utils.js';
	import { Check, Copy } from '@lucide/svelte';

	interface Props {
		code: string;
		/** Shown in the header, e.g. "bash" or "yaml". */
		language?: string;
		/** Breaks long lines instead of scrolling, for keys. */
		wrap?: boolean;
		class?: string;
	}

	let { code, language, wrap = false, class: className }: Props = $props();

	const clipboard = new UseClipboard({ delay: 1500 });
</script>

<div class={cn('overflow-hidden rounded-lg border bg-muted/40', className)}>
	<div class="flex items-center justify-between border-b py-1 pr-1 pl-3">
		<span class="font-mono text-xs text-muted-foreground">{language}</span>
		<Button variant="ghost" size="xs" onclick={() => clipboard.copy(code)}>
			{#if clipboard.copied}
				<Check data-icon="inline-start" />
				Copied
			{:else}
				<Copy data-icon="inline-start" />
				Copy
			{/if}
		</Button>
	</div>
	<pre
		class={[
			'p-3 font-mono text-xs leading-relaxed',
			wrap ? 'break-all whitespace-pre-wrap' : 'overflow-x-auto'
		]}><code>{code}</code></pre>
</div>
