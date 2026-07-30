<script lang="ts">
	import { workspace } from '$lib/api/workspaces.svelte';
	import * as Dialog from '$lib/components/ui/dialog';
	import * as Alert from '$lib/components/ui/alert';
	import * as Empty from '$lib/components/ui/empty';
	import { Button } from '$lib/components/ui/button';
	import { Checkbox } from '$lib/components/ui/checkbox';
	import { Label } from '$lib/components/ui/label';
	import { Separator } from '$lib/components/ui/separator';
	import type { WorkspaceMember } from '$lib/gen/nokku/v1/workspace_pb';
	import { TriangleAlert, Crown, ArrowRight, LoaderCircle } from '@lucide/svelte';
	import UserAvatar from '$lib/components/utils/UserAvatar.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { user } from '$lib/api/user.svelte';

	interface Props {
		open?: boolean;
		targetMember?: WorkspaceMember | null;
	}

	let { open = $bindable(false), targetMember = null }: Props = $props();

	const updateOwner = workspace.updateOwner();
	const currentUserQuery = $derived(user.self());
	const currentUser = $derived(currentUserQuery.data);

	let confirmTransfer = $state(false);

	function handleTransferOwnership() {
		if (!targetMember || !confirmTransfer) return;

		updateOwner.mutate(
			{ newOwner: targetMember.id },
			{
				onSuccess: () => {
					open = false;
					confirmTransfer = false;
				}
			}
		);
	}

	// Reset confirmation when modal toggles
	$effect(() => {
		if (open) confirmTransfer = false;
	});
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-xl">
		{#if targetMember?.roleName === 'owner'}
			<Empty.Root class="rounded-xl border bg-card text-card-foreground shadow-sm">
				<Empty.Header>
					<Empty.Media variant="icon">
						<Crown />
					</Empty.Media>
					<Empty.Title>You are already the workspace owner</Empty.Title>
				</Empty.Header>
			</Empty.Root>
		{:else}
			<Dialog.Header>
				<div class="flex items-center gap-3">
					<div class="rounded-xl bg-destructive/10 p-2.5 ring-2 ring-destructive/20">
						<TriangleAlert class="h-6 w-6 text-destructive" />
					</div>
					<div>
						<Dialog.Title class="text-xl">Transfer Workspace Ownership</Dialog.Title>
						<Dialog.Description>This action cannot be undone</Dialog.Description>
					</div>
				</div>
			</Dialog.Header>

			<Separator />

			<div class="space-y-6">
				<Alert.Root variant="destructive">
					<TriangleAlert class="h-5 w-5" />
					<Alert.Title>Critical Warning</Alert.Title>
					<Alert.Description>
						<ul class="mt-2 space-y-1 text-sm">
							<li>• You will lose all owner privileges immediately</li>
							<li>
								• Billing responsibility transfers to the new owner, however <b
									>billing information will NOT change!</b
								> The new owner must ensure their subscription card works.
							</li>
							<li>• You will become a regular member</li>
						</ul>
					</Alert.Description>
				</Alert.Root>

				{#if targetMember && currentUser}
					<div class="rounded-xl border-2 border-dashed bg-muted/30 p-4">
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-3">
								<UserAvatar user={currentUser as any} />
								<div>
									<p class="text-sm font-medium">{currentUser.email}</p>
									<Badge variant="destructive" class="mt-0.5 h-5 gap-1 text-xs">
										<Crown size={10} />
										Owner
									</Badge>
								</div>
							</div>

							<ArrowRight class="h-6 w-6 text-muted-foreground" />

							<div class="flex items-center gap-3">
								<UserAvatar user={targetMember as any} />
								<div>
									<p class="text-sm font-medium">{targetMember.email}</p>
									<Badge variant="outline" class="mt-0.5 h-5 gap-1 text-xs">
										{targetMember.roleName}
									</Badge>
								</div>
							</div>
						</div>
					</div>
				{/if}

				<div
					class="flex items-start gap-3 rounded-lg border-2 border-destructive/20 bg-muted/10 p-4 shadow-sm transition-colors data-[state=checked]:border-destructive/50"
				>
					<Checkbox id="confirm-transfer" bind:checked={confirmTransfer} class="mt-0.5" />

					<Label
						for="confirm-transfer"
						class="cursor-pointer text-sm leading-relaxed font-medium text-muted-foreground"
					>
						<span>
							I understand that I am permanently transferring ownership to
							<strong class="text-foreground">@{targetMember?.username}</strong>, and they will be
							responsible for ensuring the billing subscription stays active.
						</span>
					</Label>
				</div>
			</div>

			<Dialog.Footer>
				<Button
					variant="destructive"
					disabled={!targetMember || !confirmTransfer || updateOwner.isPending}
					onclick={handleTransferOwnership}
				>
					{#if updateOwner.isPending}
						<LoaderCircle class="size-4 animate-spin" />
					{:else}
						<TriangleAlert size={16} />
					{/if}
					Transfer Ownership
				</Button>
			</Dialog.Footer>
		{/if}
	</Dialog.Content>
</Dialog.Root>
