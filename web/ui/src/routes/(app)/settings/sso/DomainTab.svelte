<script lang="ts">
	import { domain } from '$lib/api/sso.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Empty from '$lib/components/ui/empty';
	import * as Collapsible from '$lib/components/ui/collapsible';
	import * as Dialog from '$lib/components/ui/dialog';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import InputGroupVariants from '$lib/components/ui/input-group/input-group-variants.svelte';
	import { Label } from '$lib/components/ui/label';
	import {
		ChevronRight,
		CircleCheckBig,
		Clock,
		Globe,
		Plus,
		RefreshCw,
		Trash2
	} from '@lucide/svelte';
	import { formatTs } from '$lib/utils';
	import DeleteConfirmationModal from '$lib/components/modals/DeleteConfirmationModal.svelte';

	let domains = $derived(domain.list());
	let showAddDialog = $state(false);
	let deleteDomainName = $state('');
	let newDomain = $state('');

	const createDomain = domain.create();
	const verifyDomain = domain.verify();
	const deleteDomain = domain.delete();
	const regenerateToken = domain.regenerate();
	async function handleAddDomain() {
		if (!newDomain.trim()) return;
		createDomain.mutate({ domain: newDomain });
		showAddDialog = false;
		newDomain = '';
	}
</script>

<DeleteConfirmationModal
	open={deleteDomainName !== ''}
	title="Delete Domain"
	description="Are you sure you want to delete this domain?"
	itemName={deleteDomainName}
	onConfirm={() => deleteDomain.mutate({ domain: deleteDomainName })}
/>

<div class="flex flex-col gap-4">
	{#if !domains.data?.length}
		<Empty.Root class="border border-dashed">
			<Empty.Header>
				<Empty.Media variant="icon">
					<Globe />
				</Empty.Media>
				<Empty.Title>No domains configured</Empty.Title>
				<Empty.Description>Add a domain to enable custom email addresses and SSO</Empty.Description>
			</Empty.Header>
			<Empty.Content>
				<Button onclick={() => (showAddDialog = true)}>
					<Plus size={16} />
					Add Your First Domain
				</Button>
			</Empty.Content>
		</Empty.Root>
	{:else}
		<div class="flex items-center justify-end">
			<Button onclick={() => (showAddDialog = true)}>
				<Plus size={16} />
				Add Domain
			</Button>
		</div>

		<div class="grid gap-4">
			{#each domains.data || [] as d (d.domain)}
				<Collapsible.Root class="rounded-xl">
					<Collapsible.Trigger
						class="group relative z-10 flex w-full items-center justify-between gap-2 rounded-xl bg-muted p-3 shadow-md transition-colors"
					>
						<div class="flex items-center gap-2">
							<ChevronRight
								class="transition-transform group-data-[state=open]:rotate-90"
								size={16}
							/>
							<div class="font-medium">{d.domain}</div>
						</div>

						<div class="flex items-center gap-2">
							{#if !d.verifiedAt}
								<Button
									size="sm"
									variant="outline"
									onclick={(e) => {
										e.stopPropagation();
										verifyDomain.mutate({ domain: d.domain });
									}}
								>
									<CircleCheckBig />
									Verify
								</Button>
							{:else}
								<Badge variant="default" class="h-7 gap-2">
									<CircleCheckBig size={16} />
									Verified
								</Badge>
							{/if}
							<Button
								size="sm"
								variant="ghost"
								onclick={(e) => {
									e.stopPropagation();
									regenerateToken.mutate({ domain: d.domain });
								}}
								title="Regenerate Verification Token"
							>
								<RefreshCw />
							</Button>
							<Button
								size="sm"
								variant="ghost"
								class="text-destructive hover:text-destructive"
								onclick={(e) => {
									e.stopPropagation();
									deleteDomainName = d.domain;
								}}
								title="Delete Domain"
							>
								<Trash2 />
							</Button>
						</div>
					</Collapsible.Trigger>

					<Collapsible.Content
						class="relative -mt-6 space-y-4 overflow-hidden rounded-b-xl bg-card px-6 py-4 transition-all duration-300"
					>
						{#if !d.verifiedAt}
							<div class="mt-6 space-y-2">
								<Label>Verification Token</Label>
								<InputGroupVariants
									variant="copy-input"
									value={d.verificationToken}
									readonly
									class="font-mono text-xs"
								/>

								<p class="text-xs text-muted-foreground">
									Add a TXT record to your DNS with name: <code
										class="rounded bg-muted px-1 py-0.5"
									>
										_nokku-verify.{d.domain}
									</code>
									and value set to the verification token above.
								</p>
								<p class="text-xs text-muted-foreground">
									Note: Some DNS providers (like Cloudflare) automatically append your domain to the
									record name, so you may only need to enter <code
										class="rounded bg-muted px-1 py-0.5">_nokku-verify</code
									>
								</p>
							</div>
						{/if}

						<div class="mt-2 grid grid-cols-2 gap-4 text-sm">
							<div>
								<Label class="text-xs">Created</Label>
								<p class="text-muted-foreground">{formatTs(d.createdAt)}</p>
							</div>
							{#if d.verifiedAt}
								<div>
									<Label class="text-xs">Verified</Label>
									<p class="text-muted-foreground">{formatTs(d.verifiedAt)}</p>
								</div>
							{:else}
								<div>
									<Label class="text-xs">Status</Label>
									<p class="flex items-center gap-1 text-muted-foreground">
										<Clock size={14} />
										Pending
									</p>
								</div>
							{/if}
						</div>
					</Collapsible.Content>
				</Collapsible.Root>
			{/each}
		</div>
	{/if}
</div>

<Dialog.Root bind:open={showAddDialog}>
	<Dialog.Content>
		<Dialog.Header>
			<Dialog.Title>Add Domain</Dialog.Title>
			<Dialog.Description>
				Enter the domain name you want to add. After adding, you'll need to verify ownership by
				adding a TXT record to your DNS settings.
			</Dialog.Description>
		</Dialog.Header>
		<Field.Set>
			<Field.Group>
				<Field.Field>
					<Field.Label for="domain">Domain Name</Field.Label>
					<Field.Content>
						<Input
							id="domain"
							bind:value={newDomain}
							placeholder="example.com"
							onkeydown={(e) => {
								if (e.key === 'Enter') {
									e.preventDefault();
									handleAddDomain();
								}
							}}
						/>
					</Field.Content>
				</Field.Field>
			</Field.Group>
		</Field.Set>
		<Dialog.Footer>
			<Button size="sm" onclick={handleAddDomain} disabled={!newDomain.trim()}>Add Domain</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
