<script lang="ts">
	import { Button, type ButtonSize, type ButtonVariant } from '$lib/components/ui/button';
	import * as Command from '$lib/components/ui/command';
	import SearchPopover from '$lib/components/blocks/SearchPopover.svelte';
	import { Check, UserPlus } from '@lucide/svelte';
	import { Debounced } from 'runed';
	import SubjectAvatar from './SubjectAvatar.svelte';
	import { useSubjectSearch, type Subject } from './subjects.svelte';

	interface Props {
		selected: string[];
		onToggle: (subject: Subject, grant: boolean) => void;
		label?: string;
		variant?: ButtonVariant;
		size?: ButtonSize;
		disabled?: boolean;
	}

	let {
		selected,
		onToggle,
		label = 'Grant access',
		variant = 'outline',
		size = 'sm',
		disabled = false
	}: Props = $props();

	let open = $state(false);
	let query = $state('');
	const debounced = new Debounced(() => query, 250);
	const search = useSubjectSearch(
		() => debounced.current,
		() => open
	);
</script>

<SearchPopover
	bind:open
	bind:query
	placeholder="Search people, teams, service accounts..."
	empty="Nobody matches."
	loading={search.loading}
>
	{#snippet trigger(props)}
		<Button {...props} {variant} {size} {disabled}>
			<UserPlus data-icon="inline-start" />
			{label}
		</Button>
	{/snippet}

	{#each search.groups as group (group.heading)}
		{#if group.items.length}
			<Command.Group heading={group.heading}>
				{#each group.items as subject (subject.id)}
					{@const isSelected = selected.includes(subject.id)}
					<Command.Item value={subject.id} onSelect={() => onToggle(subject, !isSelected)}>
						<SubjectAvatar {subject} class="size-6" />
						<div class="flex min-w-0 flex-1 flex-col">
							<span class="truncate">{subject.name}</span>
							<span class="truncate text-xs text-muted-foreground">{subject.detail}</span>
						</div>
						<Check class={isSelected ? 'text-primary' : 'invisible'} />
					</Command.Item>
				{/each}
			</Command.Group>
		{/if}
	{/each}
</SearchPopover>
