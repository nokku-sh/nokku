<script lang="ts">
	import * as Alert from '$lib/components/ui/alert';
	import type { AlertVariant } from '$lib/components/ui/alert/alert.svelte';
	import { Button } from '$lib/components/ui/button';
	import { cn } from '$lib/utils';
	import type { HealthIssue } from './types';

	interface Props {
		items: HealthIssue[];
		class?: string;
	}

	let { items, class: className }: Props = $props();

	const variants: Record<HealthIssue['tone'], AlertVariant> = {
		info: 'info',
		warn: 'warning',
		danger: 'destructive'
	};
</script>

{#if items.length > 0}
	<div class={cn('flex flex-col gap-3', className)}>
		{#each items as issue (issue.id)}
			{@const IssueIcon = issue.icon}
			<Alert.Root variant={variants[issue.tone]}>
				<IssueIcon />
				<Alert.Title>{issue.title}</Alert.Title>
				<Alert.Description class="text-xs">{issue.description}</Alert.Description>
				<Alert.Action>
					<Button size="sm" variant="outline" href={issue.href}>{issue.ctaLabel}</Button>
				</Alert.Action>
			</Alert.Root>
		{/each}
	</div>
{/if}
