<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import CopyText from '#lib/components/blocks/CopyText.svelte';
	import * as HoverCard from '#lib/components/ui/hover-card/index.js';
	import { Separator } from '#lib/components/ui/separator/index.js';
	import {
		AuthorityType,
		CertificateKeyType,
		type CertificateAuthority
	} from '#lib/gen/nokku/v1/certificates_pb.js';
	import { enumLabel, formatD, formatTs } from '#lib/utils.js';
	import { type Timestamp } from '@bufbuild/protobuf/wkt';
	import { ArrowRight, Dot, KeyRound, Shield, Star } from '@lucide/svelte';

	type Props = {
		ca: CertificateAuthority;
	};
	let { ca }: Props = $props();

	const isSsh = $derived(ca.authorityType === AuthorityType.SSH);
	const isX509 = $derived(ca.authorityType === AuthorityType.X509);
	const typeLabel = $derived(isSsh ? 'SSH CA' : 'X.509 CA');
	const TypeIcon = $derived(isSsh ? KeyRound : Shield);

	const keyLabel = $derived.by(() => {
		let label = enumLabel(CertificateKeyType[ca.keyType]);
		if (ca.keyType !== CertificateKeyType.ED25519 && ca.keyBits > 0) {
			label += ` ${ca.keyBits}-bit`;
		}
		return label;
	});

	const extensions = $derived(Object.entries(ca.userExtensions ?? {}));
	const criticalOptions = $derived(Object.entries(ca.userCriticalOptions ?? {}));
	const hasSshPolicies = $derived(isSsh && (extensions.length > 0 || criticalOptions.length > 0));
</script>

{#snippet copyRow(label: string, value: string)}
	<div class="flex items-center gap-2">
		<span class="w-20 shrink-0 text-xs text-muted-foreground">{label}</span>
		<CopyText {value} mono class="flex-1" />
	</div>
{/snippet}

{#snippet textRow(label: string, value: string)}
	<div class="flex items-center gap-2">
		<span class="w-20 shrink-0 text-xs text-muted-foreground">{label}</span>
		<span class="min-w-0 flex-1 truncate text-xs" title={value}>{value}</span>
	</div>
{/snippet}

{#snippet validityRow(from: Timestamp | undefined, to: Timestamp | undefined)}
	<div class="flex items-center gap-2">
		<span class="w-20 shrink-0 text-xs text-muted-foreground">Validity</span>
		<div class="flex items-center gap-2">
			<span class="text-xs" title={formatTs(from, 'full')}>{formatTs(from, 'short')}</span>
			<ArrowRight size={12} />
			<span class="text-xs" title={formatTs(to, 'full')}>{formatTs(to, 'short')}</span>
		</div>
	</div>
{/snippet}

{#snippet ttlRow(label: string, def: string, max: string)}
	<div class="flex items-center gap-2">
		<span class="w-20 shrink-0 text-xs text-muted-foreground">{label}</span>
		<div class="flex items-center gap-2">
			<span class="text-xs" title={def}>{def}</span>
			<Dot size={12} />
			<span class="text-xs" title={max}>{max}</span>
		</div>
	</div>
{/snippet}

<HoverCard.Root openDelay={200}>
	<HoverCard.Trigger>
		<div class="flex max-w-48 min-w-0 flex-col overflow-hidden">
			<div class="flex items-center gap-1.5">
				<span
					class="truncate text-sm font-medium underline decoration-muted-foreground/40 decoration-dotted underline-offset-4"
				>
					{ca.name}
				</span>
				{#if ca.isDefault}
					<Star size={12} class="shrink-0 fill-warning text-warning" />
				{/if}
			</div>
			{#if ca.description}
				<span class="truncate text-xs text-muted-foreground" title={ca.description}>
					{ca.description}
				</span>
			{/if}
		</div>
	</HoverCard.Trigger>
	<HoverCard.Content class="max-h-120 w-96 overflow-y-auto p-4">
		<div class="flex flex-col gap-4">
			<div class="flex items-center gap-3">
				<div class="rounded-md bg-muted p-2">
					<TypeIcon size={16} class="text-muted-foreground" />
				</div>
				<div class="min-w-0 flex-1">
					<div class="truncate text-sm font-semibold">{ca.name}</div>
					<div class="flex items-center gap-1.5 text-xs text-muted-foreground">
						<span>{typeLabel}</span>
						<span>·</span>
						{#if ca.isActive}
							<span class="text-success">Active</span>
						{:else}
							<span class="text-destructive">Inactive</span>
						{/if}
						{#if ca.isDefault}
							<span>·</span>
							<Star size={12} class="fill-warning text-warning" />
							<span>Default</span>
						{/if}
					</div>
				</div>
			</div>

			<Separator />

			<div class="flex flex-col gap-2">
				<span class="text-2xs font-medium tracking-wider text-muted-foreground uppercase">
					Identity
				</span>
				{#if ca.publicKey}
					{@render copyRow('Public key', ca.publicKey)}
				{/if}
				{#if ca.serialNumber}
					{@render copyRow('Serial', ca.serialNumber)}
				{/if}
				{#if isX509}
					{#if ca.subject}
						{@render copyRow('Subject', ca.subject)}
					{/if}
					{#if ca.certificate}
						{@render copyRow('Certificate', ca.certificate)}
					{/if}
				{/if}
			</div>

			<Separator />

			<div class="flex flex-col gap-2">
				<span class="text-2xs font-medium tracking-wider text-muted-foreground uppercase">
					Policy
				</span>
				{@render textRow('Key type', keyLabel)}
				{#if ca.allowedKeyTypes.length > 0}
					<div class="flex items-center gap-2">
						<span class="w-20 shrink-0 text-xs text-muted-foreground">Allowed</span>
						<div class="flex min-w-0 flex-1 flex-wrap gap-1">
							{#each ca.allowedKeyTypes as t (t)}
								<Badge variant="outline" class="px-1.5 py-0.5 text-2xs leading-none font-normal">
									{enumLabel(CertificateKeyType[t]).toUpperCase()}
								</Badge>
							{/each}
						</div>
					</div>
				{/if}
				{@render validityRow(ca.notBefore, ca.notAfter)}
				{@render ttlRow(
					`${isX509 ? 'Client' : 'User'} TTL`,
					`${formatD(ca.userDefaultTtl, 'long')} (default)`,
					`${formatD(ca.userMaxTtl, 'long')} (max)`
				)}
				{@render ttlRow(
					`${isX509 ? 'Server' : 'Host'} TTL`,
					`${formatD(ca.hostDefaultTtl, 'long')} (default)`,
					`${formatD(ca.hostMaxTtl, 'long')} (max)`
				)}
			</div>

			{#if hasSshPolicies}
				<Separator />

				<div class="flex flex-col gap-2">
					<span class="text-2xs font-medium tracking-wider text-muted-foreground uppercase">
						User SSH Policies
					</span>
					{#if extensions.length > 0}
						<div class="flex items-center gap-2">
							<span class="w-20 shrink-0 text-xs text-muted-foreground">Extensions</span>
							<div class="flex min-w-0 flex-1 flex-wrap gap-1">
								{#each extensions as [k, v] (k)}
									<Badge
										variant="secondary"
										class="px-1.5 py-0.5 font-mono text-2xs leading-none font-normal"
									>
										{v ? `${k}=${v}` : k}
									</Badge>
								{/each}
							</div>
						</div>
					{/if}
					{#each criticalOptions as [k, v] (k)}
						{@render copyRow(k, v ? `${k}=${v}` : k)}
					{/each}
				</div>
			{/if}
		</div>
	</HoverCard.Content>
</HoverCard.Root>
