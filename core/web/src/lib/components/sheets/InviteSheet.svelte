<script lang="ts">
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import type { Invitation } from '#lib/gen/nokku/v1/invitation_pb.js';
	import { auth } from '#lib/api/auth.svelte.js';
	import { invite, workspace } from '#lib/api/workspaces.svelte.js';
	import RolePicker from '#lib/components/access/RolePicker.svelte';
	import SecretReveal from '#lib/components/blocks/SecretReveal.svelte';
	import { Badge } from '#lib/components/ext/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { Skeleton } from '#lib/components/ui/skeleton/index.js';
	import { Spinner } from '#lib/components/ui/spinner/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import { confirm } from '#lib/hooks/index.js';
	import { roleLabel } from '#lib/roles.js';
	import { formatTs } from '#lib/utils.js';
	import {
		CircleCheck,
		Clock,
		Mail,
		Plus,
		Send,
		ShieldCheck,
		Trash2,
		UserPlus
	} from '@lucide/svelte';
	import { toast } from 'svelte-sonner';
	import EntitySheet from './EntitySheet.svelte';
	import Section from './Section.svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const ws = workspace.get();
	const options = auth.options();
	// Without mail the server hands the link back, and the admin passes it on.
	const mails = $derived(!!options.data?.emailConfigured);
	const pending = invite.list(() => open);
	const create = invite.create();
	const remove = invite.remove();

	let tab = $state('new');
	let email = $state('');
	let role = $state(WorkspaceRole.MEMBER);
	let link = $state('');
	let invited = $state<Invitation>();

	const valid = $derived(email.trim().includes('@'));
	const invites = $derived(pending.data ?? []);

	async function send(to: string, as: WorkspaceRole) {
		const res = await create.mutateAsync({ email: to, role: as });
		invited = res.invitation;
		if (res.link) {
			link = res.link;
			tab = 'new';
		} else {
			toast.success(`Invite sent to ${to}`);
		}
		email = '';
	}

	function another() {
		link = '';
		invited = undefined;
		role = WorkspaceRole.MEMBER;
	}

	function mailto() {
		const name = ws.data?.name ?? 'our workspace';
		const subject = `Join ${name} on Nokku`;
		const body = `You're invited to ${name} on Nokku as ${roleLabel(invited?.role || WorkspaceRole.MEMBER).toLowerCase()}.\n\nJoin here: ${link}`;
		return `mailto:${invited?.email ?? ''}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
	}

	function askRevoke(i: Invitation) {
		void confirm({
			title: `Revoke the invite for ${i.email}?`,
			description: 'The link stops working. You can invite the address again later.',
			confirmText: 'Revoke',
			onConfirm: () => remove.mutateAsync({ email: i.email })
		});
	}
</script>

<EntitySheet
	{open}
	onClose={() => {
		open = false;
		another();
	}}
	title="Invite people"
	tabs={[
		{ value: 'new', label: 'Invite', icon: Plus },
		{ value: 'pending', label: 'Pending', icon: Clock, count: invites.length }
	]}
	{tab}
	onTabChange={(t) => (tab = t)}
>
	{#snippet media()}
		<div class="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
			<UserPlus class="size-5" />
		</div>
	{/snippet}
	{#snippet subtitle()}
		Each invite is for one address. It works once, for 7 days.
	{/snippet}

	<Tabs.Content value="new" class="flex flex-col divide-y">
		{#if link}
			<Section title={`Invite for ${invited?.email ?? 'them'}`} icon={CircleCheck}>
				<SecretReveal
					values={[{ label: 'Invite link', value: link }]}
					note="Copy it now, it is only shown once. Whoever opens it joins as this address, so hand it to that person only."
				/>
				<div class="flex flex-wrap gap-2">
					<Button variant="outline" size="sm" href={mailto()}>
						<Mail data-icon="inline-start" />
						Open in your mail app
					</Button>
					<Button variant="outline" size="sm" onclick={another}>
						<Plus data-icon="inline-start" />
						Invite another
					</Button>
				</div>
			</Section>
		{:else}
			<form
				class="flex flex-col divide-y"
				onsubmit={(e) => {
					e.preventDefault();
					void send(email.trim(), role);
				}}
			>
				<Section title="Who" icon={Mail}>
					<Field.Field>
						<Field.Label for="invite-email">Email</Field.Label>
						<Input
							id="invite-email"
							type="email"
							autocomplete="off"
							bind:value={email}
							placeholder="ada@company.com"
							required
						/>
						<Field.Description>
							{#if mails}
								We email them a link that creates their account.
							{:else}
								This server sends no email. You get a link to hand over, and you vouch for whoever
								opens it.
							{/if}
						</Field.Description>
					</Field.Field>
				</Section>

				<Section title="Role" icon={ShieldCheck}>
					<RolePicker value={role} onChange={(r) => (role = r)} />
				</Section>

				<div class="pt-5">
					<Button type="submit" disabled={!valid || create.isPending} class="w-full sm:w-auto">
						{#if create.isPending}
							<Spinner data-icon="inline-start" />
						{:else}
							<Send data-icon="inline-start" />
						{/if}
						{mails ? 'Send invite' : 'Create invite link'}
					</Button>
				</div>
			</form>
		{/if}
	</Tabs.Content>

	<Tabs.Content value="pending" class="flex flex-col gap-2">
		{#if pending.isLoading}
			<Skeleton class="h-16 w-full rounded-xl" />
			<Skeleton class="h-16 w-full rounded-xl" />
		{:else if !invites.length}
			<Empty.Root class="border border-dashed">
				<Empty.Header>
					<Empty.Media variant="icon"><Clock /></Empty.Media>
					<Empty.Title>No pending invites</Empty.Title>
					<Empty.Description>Invites show up here until they are used or expire.</Empty.Description>
				</Empty.Header>
				<Empty.Content>
					<Button size="sm" variant="outline" onclick={() => (tab = 'new')}>
						<Plus data-icon="inline-start" />
						Invite someone
					</Button>
				</Empty.Content>
			</Empty.Root>
		{:else}
			{#each invites as i (i.email)}
				<div class="flex items-center gap-3 rounded-xl border bg-card p-3">
					<div class="min-w-0 flex-1">
						<p class="flex flex-wrap items-center gap-1.5 text-sm font-medium">
							<span class="truncate">{i.email}</span>
							<Badge variant="secondary">{roleLabel(i.role)}</Badge>
						</p>
						<p class="text-xs text-muted-foreground">
							Sent {formatTs(i.createdAt, 'relative')} · expires {formatTs(i.expiresAt, 'relative')}
						</p>
					</div>
					<Button
						variant="ghost"
						size="sm"
						disabled={create.isPending}
						onclick={() => void send(i.email, i.role)}
					>
						<Send data-icon="inline-start" />
						{mails ? 'Resend' : 'New link'}
					</Button>
					<Button
						variant="ghost"
						size="icon-sm"
						aria-label={`Revoke the invite for ${i.email}`}
						onclick={() => askRevoke(i)}
					>
						<Trash2 />
					</Button>
				</div>
			{/each}
		{/if}
	</Tabs.Content>
</EntitySheet>
