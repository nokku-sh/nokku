<script lang="ts">
	import { Button } from '#lib/components/ui/button/index.js';
	import { cn } from '#lib/utils.js';
	import {
		Bot,
		ChevronRight,
		CircleUser,
		Ellipsis,
		Server,
		Tag,
		Terminal,
		Users
	} from '@lucide/svelte';
	import { Handle, Position, type Node, type NodeProps } from '@xyflow/svelte';
	import type { RowData } from './graph.js';

	let { data }: NodeProps<Node<RowData>> = $props();

	const icons = {
		user: CircleUser,
		team: Users,
		'service-account': Bot,
		account: Terminal,
		tag: Tag,
		target: Server,
		more: Ellipsis
	};
	const Icon = $derived(icons[data.kind]);
</script>

<div
	class={cn(
		'flex size-full items-center overflow-hidden rounded-lg border bg-card transition-[opacity,border-color,background-color] duration-200',
		data.kind === 'more' && 'border-dashed bg-transparent',
		data.tone === 'dim' && 'opacity-40',
		data.tone === 'lit' && 'border-primary/50 bg-accent text-accent-foreground',
		data.selected && 'border-primary ring-2 ring-primary/30'
	)}
>
	<Button
		variant="ghost"
		class="h-full min-w-0 flex-1 justify-start rounded-none"
		aria-pressed={data.kind === 'more' ? undefined : !!data.selected}
		onclick={data.onselect}
	>
		<Icon data-icon="inline-start" class="text-muted-foreground" />
		<span class={cn('truncate', data.kind === 'account' && 'font-mono')}>{data.label}</span>
		{#if data.detail}
			<span class="min-w-0 flex-1 truncate text-left text-xs font-normal text-muted-foreground">
				{data.detail}
			</span>
		{/if}
		{#if data.count}
			<span class="ml-auto font-mono text-xs font-normal text-muted-foreground tabular-nums">
				{data.count}
			</span>
		{/if}
	</Button>
	{#if data.ontoggle}
		<Button
			variant="ghost"
			size="icon-sm"
			class="mr-1 shrink-0"
			aria-expanded={!!data.expanded}
			aria-label={`${data.expanded ? 'Collapse' : 'Expand'} ${data.label}`}
			onclick={data.ontoggle}
		>
			<ChevronRight class={cn('transition-transform', data.expanded && 'rotate-90')} />
		</Button>
	{/if}
</div>

{#if data.lane !== 'who'}
	<Handle type="target" position={Position.Left} class="invisible" />
{/if}
{#if data.lane !== 'where'}
	<Handle type="source" position={Position.Right} class="invisible" />
{/if}
