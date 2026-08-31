<script lang="ts">
	import * as Dialog from '$lib/components/ui/dialog/';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import * as Field from '$lib/components/ui/field';
	import * as Alert from '$lib/components/ui/alert';
	import { CircleAlert, Clock, LinkIcon, Users } from '@lucide/svelte';
	import { invite, workspace } from '$lib/api/workspaces.svelte';
	import { formatTs, toDate } from '$lib/utils';
	import Separator from '../ui/separator/separator.svelte';
	import CopyButton from '../ui/copy-button/copy-button.svelte';

	let { open = $bindable(false) }: { open: boolean } = $props();

	const ws = $derived(workspace.get());
	const invitation = invite.refresh();
	const revoke = invite.revoke();

	$effect(() => {
		if (!open) invitation.reset();
	});
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="no-scrollbar max-h-[95vh] overflow-y-auto">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<Users size={20} />
				Invite Members
			</Dialog.Title>
			<Dialog.Description>
				Share an invitation link to add new members to your workspace.
			</Dialog.Description>
		</Dialog.Header>

		<div class="flex items-center gap-2">
			<Button variant="secondary" class="flex-1" onclick={invitation.mutate}>
				Generate New Link
			</Button>

			{#if ws.data?.inviteExpiresAt && toDate(ws.data.inviteExpiresAt) > new Date()}
				<Button
					variant="destructive"
					class="flex-1"
					onclick={() => {
						revoke.mutate({});
						invitation.reset();
					}}
				>
					Revoke Invite Link
				</Button>
			{/if}
		</div>

		<div class="space-y-4">
			{#if invitation.isSuccess}
				<Separator />
				<Field.Field>
					<div class="flex items-center justify-between">
						<Field.Label class="flex items-center gap-2">
							<LinkIcon size={14} />
							Invitation Link
						</Field.Label>
						<Badge variant="secondary" class="flex items-center gap-1.5">
							<Clock size={12} />
							Expires {formatTs(invitation.data.expiresAt, 'withTime')}
						</Badge>
					</div>
					<Field.Content>
						<CopyButton
							text={invitation.data.link}
							class="relative h-9 w-full p-0 hover:bg-transparent"
						>
							<div class="absolute inset-0 right-8 flex items-center pl-2">
								<span class="block w-full truncate text-left font-mono text-xs font-light">
									{invitation.data.link}
								</span>
							</div>
						</CopyButton>
					</Field.Content>
				</Field.Field>
			{/if}

			<Alert.Root>
				<CircleAlert size={16} />
				<Alert.Title>Important</Alert.Title>
				<Alert.Description>
					<ul class="mt-1 space-y-1 text-xs">
						<li>Links expire automatically after 24 hours</li>
						<li>Anyone with the link can join your workspace</li>
					</ul>
				</Alert.Description>
			</Alert.Root>
		</div>
	</Dialog.Content>
</Dialog.Root>
