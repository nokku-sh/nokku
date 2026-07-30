<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { PlusIcon, XIcon } from '@lucide/svelte';
	import * as Command from '$lib/components/ui/command';
	import * as Popover from '$lib/components/ui/popover';
	import * as Field from '$lib/components/ui/field';
	import { team } from '$lib/api/team.svelte';
	import type { Team } from '$lib/gen/nokku/v1/team_pb';
	import { workspace } from '$lib/api/workspaces.svelte';
	import type { WorkspaceMember } from '$lib/gen/nokku/v1/workspace_pb';
	import UserAvatar from '$lib/components/utils/UserAvatar.svelte';

	interface Props {
		data: Team;
	}
	let { data = $bindable() }: Props = $props();

	const members = $derived(workspace.listMembers());
	const addMemberMutation = team.addMember();
	const removeMemberMutation = team.removeMember();

	const isUserInTeam = (userID: string) => data?.members?.find((m) => m.id === userID);

	const availableMembers = $derived(
		members.data?.members?.filter((m) => !isUserInTeam(m.id)) || []
	);

	async function addMember(member: WorkspaceMember) {
		await addMemberMutation.mutateAsync({ teamId: data.id, userId: member.id });
		data.members.push(member);
	}

	async function removeMember(member: WorkspaceMember) {
		await removeMemberMutation.mutateAsync({ teamId: data.id, userId: member.id });
		data.members = data.members.filter((m) => m.id !== member.id);
	}
</script>

<Field.Set class="flex flex-col gap-3">
	{#if data.members?.length > 0}
		<div class="flex flex-col gap-1">
			{#each data.members as member (member.id)}
				<div class="flex items-center justify-between gap-3 rounded-lg border p-3">
					<div class="flex items-center gap-3 truncate">
						<UserAvatar user={member} class="size-9" />
						<div class="flex flex-col truncate">
							<span class="truncate text-sm font-medium">{member.name || member.username}</span>
							<span class="truncate text-xs text-muted-foreground">{member.email}</span>
						</div>
					</div>
					<Button
						size="icon"
						variant="ghost"
						class="size-8 shrink-0"
						onclick={() => removeMember(member)}
					>
						<XIcon />
					</Button>
				</div>
			{/each}
		</div>
	{/if}

	<Popover.Root>
		<Popover.Trigger>
			{#snippet child({ props })}
				<Button
					{...props}
					variant="outline"
					class="w-full"
					disabled={availableMembers.length === 0}
				>
					<PlusIcon />
					Add member
				</Button>
			{/snippet}
		</Popover.Trigger>
		<Popover.Content class="p-0" align="center">
			<Command.Root>
				<Command.Input placeholder="Search users..." />
				<Command.List>
					<Command.Empty>No user found.</Command.Empty>
					<Command.Group>
						{#each availableMembers as member (member.id)}
							<Command.Item value={member.username} onSelect={() => addMember(member)}>
								<div class="flex items-center gap-2">
									<UserAvatar user={member} class="size-7" />
									<div class="flex flex-col">
										<span class="text-sm">{member.name || member.username}</span>
										<span class="text-xs text-muted-foreground">{member.email}</span>
									</div>
								</div>
							</Command.Item>
						{/each}
					</Command.Group>
				</Command.List>
			</Command.Root>
		</Popover.Content>
	</Popover.Root>
</Field.Set>
