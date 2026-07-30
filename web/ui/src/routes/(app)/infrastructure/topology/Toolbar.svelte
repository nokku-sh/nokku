<script lang="ts">
	import { BotIcon, CircleUserIcon, UserIcon, UsersIcon, XIcon } from '@lucide/svelte';
	import * as Popover from '$lib/components/ui/popover';
	import * as Command from '$lib/components/ui/command';
	import { Button } from '$lib/components/ui/button';
	import { CheckIcon, ChevronsUpDownIcon } from '@lucide/svelte';
	import { SvelteSet } from 'svelte/reactivity';
	import FilterPill from '$lib/components/utils/FilterPill.svelte';
	import type { Target } from '$lib/gen/nokku/v1/target_pb';

	type Props = {
		data?: Target[];
		selectedTarget?: Target;
		selectedPrincipals?: SvelteSet<string>;
		selectedSubjectTypes?: SvelteSet<string>;
		targetPrincipals?: any[];
	};

	let {
		data = $bindable(),
		selectedTarget = $bindable(),
		selectedPrincipals = $bindable(new SvelteSet<string>()),
		selectedSubjectTypes = $bindable(new SvelteSet<string>()),
		targetPrincipals = []
	}: Props = $props();

	// Filters derived from selected target's principals
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
		{ label: 'Service Account', value: 'service-account', icon: BotIcon }
	];
</script>

{#if data}
	<div class="my-4 flex flex-col items-center justify-between gap-2 sm:flex-row">
		<div class="flex flex-col items-center space-x-2 sm:flex-row">
			<!-- Search -->
			<Popover.Root>
				<Popover.Trigger>
					{#snippet child({ props })}
						<Button
							{...props}
							variant="outline"
							class="justify-between sm:min-w-sm"
							role="combobox"
						>
							{selectedTarget ? selectedTarget.name : 'Choose a target to visualize...'}
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
											selectedPrincipals.clear();
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
						bind:values={selectedPrincipals}
						options={principalsFilter}
						title="Principals"
					/>
				{/if}
				<FilterPill
					bind:values={selectedSubjectTypes}
					options={subjectTypeFilter}
					title="Subject"
				/>
			</div>

			<Button
				variant="ghost"
				class="h-8 px-2 lg:px-3"
				onclick={() => {
					selectedTarget = undefined;
					selectedPrincipals.clear();
				}}
			>
				Reset
				<XIcon />
			</Button>
		</div>
	</div>
{/if}
