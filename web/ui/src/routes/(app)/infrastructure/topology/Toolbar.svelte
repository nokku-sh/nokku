<script lang="ts">
	import { BotIcon, CircleUserIcon, UserIcon, UsersIcon, XIcon } from '@lucide/svelte';
	import * as Popover from '$lib/components/ui/popover';
	import * as Command from '$lib/components/ui/command';
	import { Button } from '$lib/components/ui/button';
	import { CheckIcon, ChevronsUpDownIcon } from '@lucide/svelte';
	import FilterPill from '$lib/components/blocks/FilterPill.svelte';
	import type { Target } from '$lib/gen/nokku/v1/target_pb';

	type Props = {
		data?: Target[];
		selectedTarget?: Target;
		selectedPrincipals?: string[];
		selectedSubjectTypes?: string[];
		targetPrincipals?: any[];
	};

	let {
		data = $bindable(),
		selectedTarget = $bindable(),
		selectedPrincipals = $bindable([]),
		selectedSubjectTypes = $bindable([]),
		targetPrincipals = []
	}: Props = $props();

	let principalsFilter = $derived(
		(targetPrincipals || []).map((p) => ({
			label: p.username,
			value: p.username,
			icon: UserIcon
		}))
	);

	const subjectTypeFilter = [
		{ label: 'User', value: 'user', icon: CircleUserIcon },
		{ label: 'Team', value: 'team', icon: UsersIcon },
		{ label: 'Service account', value: 'service-account', icon: BotIcon }
	];
</script>

<div class="flex flex-col items-center justify-between gap-2 sm:flex-row">
	<div class="flex flex-col items-center gap-2 sm:flex-row">
		<Popover.Root>
			<Popover.Trigger>
				{#snippet child({ props })}
					<Button {...props} variant="outline" class="justify-between sm:min-w-sm" role="combobox">
						{selectedTarget ? selectedTarget.name : 'Pick a target'}
						<ChevronsUpDownIcon class="opacity-50" />
					</Button>
				{/snippet}
			</Popover.Trigger>
			<Popover.Content class="p-0">
				<Command.Root>
					<Command.Input placeholder="Search targets..." />
					<Command.List>
						<Command.Empty>No targets found</Command.Empty>
						<Command.Group value="users">
							{#each data || [] as target (target.id)}
								<Command.Item
									value={target.name}
									onSelect={() => {
										selectedTarget = target;
										selectedPrincipals = [];
									}}
									class="flex items-center justify-between gap-2"
								>
									{target.name}
									<CheckIcon class={target.id === selectedTarget?.id ? '' : 'hidden'} />
								</Command.Item>
							{/each}
						</Command.Group>
					</Command.List>
				</Command.Root>
			</Popover.Content>
		</Popover.Root>

		<div class="flex items-center gap-2">
			{#if selectedTarget}
				<FilterPill
					title="Principals"
					options={principalsFilter}
					selected={selectedPrincipals}
					onChange={(next) => (selectedPrincipals = next)}
				/>
			{/if}
			<FilterPill
				title="Subject"
				options={subjectTypeFilter}
				selected={selectedSubjectTypes}
				onChange={(next) => (selectedSubjectTypes = next)}
			/>
		</div>

		<Button
			variant="ghost"
			class="h-8 px-2 lg:px-3"
			onclick={() => {
				selectedTarget = undefined;
				selectedPrincipals = [];
			}}
		>
			Reset
			<XIcon />
		</Button>
	</div>
</div>
