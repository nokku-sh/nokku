<script lang="ts">
	import { team } from '$lib/api/team.svelte';
	import TeamMembersField from './TeamMembersField.svelte';
	import FormModal from '$lib/components/modals/FormModal.svelte';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import * as Item from '$lib/components/ui/item';
	import * as Tabs from '$lib/components/ui/tabs';
	import Textarea from '$lib/components/ui/textarea/textarea.svelte';
	import type { Team } from '$lib/gen/nokku/v1/team_pb';
	import { formatTs } from '$lib/utils';
	import { CalendarIcon, ClockIcon, Settings2, Users } from '@lucide/svelte';

	interface Props {
		data: Team;
		open?: boolean;
	}
	let { data = $bindable({} as Team), open = $bindable(false) }: Props = $props();

	const createMutation = team.create();
	const updateMutation = team.update();
	const isLoading = $derived(createMutation.isPending || updateMutation.isPending);

	async function onSubmit() {
		if (data.id) {
			updateMutation.mutate({ ...data });
		} else {
			createMutation.mutate({ ...data });
		}
		open = false;
	}
</script>

<FormModal
	bind:open
	title="{data.id ? 'Edit' : 'Create'} Team"
	description="Configure your team settings"
	submitLabel={data.id ? 'Update' : 'Create'}
	{onSubmit}
	{isLoading}
>
	<Tabs.Root class="w-full">
		<Tabs.List class="mb-4 grid w-full grid-cols-2">
			<Tabs.Trigger value="general">
				<Settings2 />
				General
			</Tabs.Trigger>
			<Tabs.Trigger value="members">
				<Users />
				Members
			</Tabs.Trigger>
		</Tabs.List>

		<Tabs.Content value="general" class="space-y-4">
			<Field.Field>
				<Field.Label for="team-name">Name</Field.Label>
				<Field.Content>
					<Input id="team-name" bind:value={data.name} placeholder="My Team" required />
				</Field.Content>
			</Field.Field>

			<Field.Field>
				<Field.Label for="team-description">Description</Field.Label>
				<Field.Content>
					<Textarea
						id="team-description"
						bind:value={data.description}
						placeholder="My team description"
					/>
				</Field.Content>
			</Field.Field>

			{#if data.id}
				<Item.Group class="grid grid-cols-2 gap-2">
					<Item.Root variant="muted">
						<Item.Media variant="icon">
							<CalendarIcon />
						</Item.Media>
						<Item.Content>
							<Item.Title>Created</Item.Title>
							<Item.Description class="font-mono text-xs">
								{formatTs(data.createdAt)}
							</Item.Description>
						</Item.Content>
					</Item.Root>
					<Item.Root variant="muted">
						<Item.Media variant="icon">
							<ClockIcon />
						</Item.Media>
						<Item.Content>
							<Item.Title>Last Updated</Item.Title>
							<Item.Description class="font-mono text-xs">
								{formatTs(data.updatedAt, 'relative')}
							</Item.Description>
						</Item.Content>
					</Item.Root>
				</Item.Group>
			{/if}
		</Tabs.Content>

		<Tabs.Content value="members" class="space-y-4">
			<TeamMembersField bind:data />
		</Tabs.Content>
	</Tabs.Root>
</FormModal>
