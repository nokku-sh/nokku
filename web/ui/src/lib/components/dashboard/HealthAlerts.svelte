<script lang="ts">
	import * as Alert from '$lib/components/ui/alert';
	import { Button } from '$lib/components/ui/button';
	import { cn } from '$lib/utils';
	import type { HealthIssue } from './types';

	interface Props {
		items: HealthIssue[];
		class?: string;
	}

	let { items, class: className }: Props = $props();

	const tones: Record<string, { root: string; media: string; button: string }> = {
		info: {
			root: 'flex items-center gap-3 border-blue-500/25 bg-blue-500/5',
			media: 'bg-blue-500/10 text-blue-500',
			button:
				'border-blue-500/30 bg-blue-500/5 text-blue-600 hover:bg-blue-500/10 dark:text-blue-400'
		},
		warn: {
			root: 'flex items-center gap-3 border-amber-500/25 bg-amber-500/5',
			media: 'bg-amber-500/10 text-amber-500',
			button:
				'border-amber-500/30 bg-amber-500/5 text-amber-600 hover:bg-amber-500/10 dark:text-amber-400'
		},
		danger: {
			root: 'flex items-center gap-3 border-destructive/25 bg-destructive/5',
			media: 'bg-destructive/10 text-destructive',
			button: 'border-destructive/30 bg-destructive/5 text-destructive hover:bg-destructive/10'
		}
	};
</script>

{#if items.length > 0}
	<div class={cn('space-y-3', className)}>
		{#each items as issue (issue.id)}
			{@const t = tones[issue.tone]}
			{@const IssueIcon = issue.icon}
			<Alert.Root class={t.root}>
				<div class={cn('shrink-0 rounded-md p-1.5', t.media)}>
					<IssueIcon class="size-4" />
				</div>
				<div class="min-w-0 flex-1 space-y-0.5">
					<Alert.Title class="text-sm">{issue.title}</Alert.Title>
					<Alert.Description class="text-xs">{issue.description}</Alert.Description>
				</div>
				<Button size="sm" variant="outline" class={cn('shrink-0', t.button)} href={issue.href}>
					{issue.ctaLabel}
				</Button>
			</Alert.Root>
		{/each}
	</div>
{/if}
