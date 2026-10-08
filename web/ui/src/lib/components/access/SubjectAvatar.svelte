<script lang="ts">
	import * as Avatar from '#lib/components/ui/avatar/index.js';
	import UserAvatar from '#lib/components/blocks/UserAvatar.svelte';
	import { SubjectKind } from '#lib/gen/nokku/v1/target_account_pb.js';
	import { cn } from '#lib/utils.js';
	import { Bot, Users } from '@lucide/svelte';
	import type { Subject } from './subjects.svelte';

	let { subject, class: className }: { subject: Subject; class?: string } = $props();
</script>

{#if subject.kind === SubjectKind.USER}
	<UserAvatar user={subject.user} class={cn('size-7', className)} />
{:else}
	<Avatar.Root class={cn('size-7', className)}>
		<Avatar.Fallback
			class={subject.kind === SubjectKind.TEAM
				? 'bg-chart-2/15 text-chart-2'
				: 'bg-chart-5/15 text-chart-5'}
		>
			{#if subject.kind === SubjectKind.TEAM}
				<Users class="size-3.5" />
			{:else}
				<Bot class="size-3.5" />
			{/if}
		</Avatar.Fallback>
	</Avatar.Root>
{/if}
