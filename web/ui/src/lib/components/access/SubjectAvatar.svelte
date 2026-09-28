<script lang="ts">
	import * as Avatar from '$lib/components/ui/avatar';
	import UserAvatar from '$lib/components/utils/UserAvatar.svelte';
	import { SubjectKind } from '$lib/gen/nokku/v1/principal_pb';
	import { cn } from '$lib/utils';
	import { Bot, Users } from '@lucide/svelte';
	import type { Subject } from './subjects.svelte';

	let { subject, class: className }: { subject: Subject; class?: string } = $props();
</script>

{#if subject.kind === SubjectKind.USER}
	<UserAvatar user={subject.member} class={cn('size-7', className)} />
{:else}
	<Avatar.Root class={cn('size-7', className)}>
		<Avatar.Fallback
			class={subject.kind === SubjectKind.TEAM
				? 'bg-chart-3/15 text-chart-3'
				: 'bg-chart-4/15 text-chart-4'}
		>
			{#if subject.kind === SubjectKind.TEAM}
				<Users class="size-3.5" />
			{:else}
				<Bot class="size-3.5" />
			{/if}
		</Avatar.Fallback>
	</Avatar.Root>
{/if}
