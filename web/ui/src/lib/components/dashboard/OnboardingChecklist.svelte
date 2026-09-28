<script lang="ts">
	import { PersistedState } from 'runed';
	import { Check, X } from '@lucide/svelte';
	import { Button } from '$lib/components/ui/button';
	import { Progress } from '$lib/components/ui/progress';
	import { cn } from '$lib/utils';
	import type { SetupStep } from './types';

	interface Props {
		steps: SetupStep[];
		title?: string;
	}

	let { steps, title = 'Finish setup' }: Props = $props();

	const dismissed = new PersistedState<boolean>('nokku:onboarding:dismissed', false);

	const doneCount = $derived(steps.filter((s) => s.done).length);
	const complete = $derived(doneCount === steps.length);
	const visible = $derived(!complete && !dismissed.current);
	const pct = $derived(steps.length > 0 ? Math.round((doneCount / steps.length) * 100) : 100);
</script>

{#if visible}
	<div class="rounded-xl border bg-card p-4">
		<div class="mb-3 flex items-center justify-between gap-2">
			<h3 class="text-sm font-semibold">{title}</h3>
			<div class="flex items-center gap-2">
				<span class="text-xs text-muted-foreground">{doneCount}/{steps.length}</span>
				<Button
					variant="ghost"
					size="icon"
					class="size-6 text-muted-foreground hover:text-foreground"
					onclick={() => (dismissed.current = true)}
					aria-label="Dismiss setup checklist"
				>
					<X class="size-3.5" />
				</Button>
			</div>
		</div>

		<Progress value={pct} class="mb-4 h-1.5" />

		<ul class="space-y-1">
			{#each steps as step (step.id)}
				<li>
					<a
						href={step.href}
						class="flex items-center gap-2.5 rounded-md px-2 py-1.5 transition-colors hover:bg-muted/40"
					>
						<span
							class={cn(
								'flex size-4 shrink-0 items-center justify-center rounded-full border',
								step.done ? 'border-success bg-success text-white' : 'border-muted-foreground/40'
							)}
						>
							{#if step.done}
								<Check class="size-2.5 stroke-3" />
							{/if}
						</span>
						<span
							class={cn(
								'text-xs',
								step.done ? 'text-muted-foreground line-through' : 'font-medium'
							)}
						>
							{step.label}
						</span>
					</a>
				</li>
			{/each}
		</ul>
	</div>
{/if}
