<script lang="ts">
	import type { Snippet } from 'svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { cn } from '$lib/utils';
	import { X } from '@lucide/svelte';
	import CopyText from './CopyText.svelte';

	interface Props {
		label: string;
		/** Links the label, e.g. to the subject's sheet. */
		href?: string;
		/** Click the label to copy this value. */
		copy?: string;
		mono?: boolean;
		/** Inherited or read-only chips look quieter. */
		muted?: boolean;
		title?: string;
		onRemove?: () => void;
		removeLabel?: string;
		leading?: Snippet;
		trailing?: Snippet;
		class?: string;
	}

	let {
		label,
		href,
		copy,
		mono = false,
		muted = false,
		title,
		onRemove,
		removeLabel = `Remove ${label}`,
		leading,
		trailing,
		class: className
	}: Props = $props();
</script>

<Badge
	variant="outline"
	{title}
	class={cn(
		'group/chip h-7 max-w-64 gap-1.5 rounded-full bg-background pr-2.5 pl-2.5 text-xs font-normal transition-colors hover:border-foreground/20',
		leading && 'pl-0.5',
		onRemove && 'pr-0.5',
		muted && 'border-dashed bg-transparent text-muted-foreground',
		mono && 'font-mono',
		className
	)}
>
	{@render leading?.()}
	{#if copy}
		<CopyText value={copy}>{label}</CopyText>
	{:else if href}
		<a {href} class="truncate hover:underline">{label}</a>
	{:else}
		<span class="truncate">{label}</span>
	{/if}
	{@render trailing?.()}
	{#if onRemove}
		<button
			type="button"
			class="rounded-full p-1 text-muted-foreground transition-colors hover:bg-destructive/10 hover:text-destructive focus-visible:outline-none pointer-fine:opacity-50 pointer-fine:group-hover/chip:opacity-100 pointer-fine:focus-visible:opacity-100"
			aria-label={removeLabel}
			onclick={onRemove}
		>
			<X class="size-3" />
		</button>
	{/if}
</Badge>
