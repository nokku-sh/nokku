<script lang="ts">
	import { team } from '$lib/api/team.svelte';
	import { roles as rolesApi } from '$lib/api/roles.svelte';
	import { assignableRoles, roleIcon, roleLabel } from '$lib/roles';
	import { Badge } from '$lib/components/ui/badge';
	import * as Item from '$lib/components/ui/item';
	import * as Select from '$lib/components/ui/select';
	import * as Dialog from '$lib/components/ui/dialog';
	import { Separator } from '$lib/components/ui/separator';
	import UserAvatar from '$lib/components/utils/UserAvatar.svelte';
	import { type WorkspaceMember } from '$lib/gen/nokku/v1/workspace_pb';
	import { workspace } from '$lib/api/workspaces.svelte';
	import { BadgeCheck, BadgeX, Crown } from '@lucide/svelte';
	import { CopyButton } from '../ui/copy-button';

	interface Props {
		data: WorkspaceMember;
		open?: boolean;
	}
	let { data = $bindable({} as WorkspaceMember), open = $bindable(false) }: Props = $props();

	const rolesQuery = $derived(rolesApi.list());
	const roleOptions = $derived(
		assignableRoles(rolesQuery.data ?? [], 'users').map((r) => ({
			value: r.name,
			label: roleLabel(r.name),
			description: r.description,
			icon: roleIcon(r.name)
		}))
	);

	const teams = $derived(team.list());
	const userTeams = $derived(
		teams.data?.teams.filter((t) => t.members.find((m) => m.id === data?.id)) ?? []
	);

	const updateMember = workspace.updateMember();
	function handleRoleChange(val: string) {
		if (!data) return;
		if (val === data.roleName) return;
		updateMember.mutateAsync({ userId: data.id, roleName: val });
		data.roleName = val;
	}
</script>

{#if data?.id}
	<Dialog.Root bind:open>
		<Dialog.Content class="no-scrollbar max-h-[95vh] w-125 overflow-y-auto">
			<Dialog.Header>
				<Dialog.Title>User Profile</Dialog.Title>
				<Dialog.Description>View user details and permissions</Dialog.Description>
			</Dialog.Header>

			<!-- User Header -->
			<Item.Root variant="muted">
				<Item.Media>
					<UserAvatar user={data} />
				</Item.Media>
				<Item.Content>
					<Item.Title class="text-lg">{data.name}</Item.Title>
					<Item.Description>@{data.username}</Item.Description>
				</Item.Content>
				<Item.Actions>
					<CopyButton text={data.id}>Copy ID</CopyButton>
				</Item.Actions>
			</Item.Root>

			<Separator />

			<!-- Information -->
			<Item.Group>
				<Item.Root variant="muted" size="sm">
					<Item.Content>
						<Item.Title>Email</Item.Title>
						<Item.Description>{data.email}</Item.Description>
					</Item.Content>
					<Item.Actions>
						{#if data.emailVerified}
							<Badge variant="secondary" class="bg-success">
								<BadgeCheck size={12} />
								Verified
							</Badge>
						{:else}
							<Badge variant="secondary" class="bg-destructive">
								<BadgeX size={12} />
								Unverified
							</Badge>
						{/if}
					</Item.Actions>
				</Item.Root>

				<Item.Root variant="muted" size="sm">
					<Item.Content>
						<Item.Title>Permission</Item.Title>
					</Item.Content>
					<Item.Actions class="py-1">
						{#if data.roleName === 'owner'}
							<Badge variant="destructive" class="h-6 gap-1 text-xs">
								<Crown size={12} />
								{roleLabel(data.roleName)}
							</Badge>
						{:else}
							<Select.Root type="single" value={data.roleName} onValueChange={handleRoleChange}>
								<Select.Trigger
									class="h-auto! w-fit justify-center gap-1 rounded-full border border-input bg-transparent px-2 py-0.5 text-xs font-medium text-foreground shadow-none transition-all hover:bg-muted/50 focus:ring-0 [&>svg:last-child]:hidden"
								>
									{roleOptions.find((r) => r.value === data?.roleName)?.label ??
										roleLabel(data.roleName)}
								</Select.Trigger>
								<Select.Content>
									{#each roleOptions as role (role.value)}
										<Select.Item
											value={role.value}
											label={role.label}
											class="cursor-pointer items-center gap-3 py-2.5"
										>
											<role.icon size={16} class="mt-0.5 text-foreground/70" />
											<div class="flex flex-col gap-1 text-left">
												<span class="text-[12px] leading-none font-medium">{role.label}</span>
												<span class="text-[10px] leading-none text-muted-foreground"
													>{role.description}</span
												>
											</div>
										</Select.Item>
									{/each}
								</Select.Content>
							</Select.Root>
						{/if}
					</Item.Actions>
				</Item.Root>

				<Item.Root variant="muted" size="sm">
					<Item.Content>
						<Item.Title>Teams</Item.Title>
						{#if userTeams.length > 0}
							<div class="flex flex-wrap gap-2">
								{#each userTeams as t (t.id)}
									<Badge variant="default">{t.name}</Badge>
								{/each}
							</div>
						{:else}
							<p class="text-sm text-muted-foreground">Not a member of any teams</p>
						{/if}
					</Item.Content>
				</Item.Root>
			</Item.Group>
		</Dialog.Content>
	</Dialog.Root>
{/if}
