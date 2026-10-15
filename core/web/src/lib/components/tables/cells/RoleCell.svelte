<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { WorkspaceRole } from '#lib/gen/nokku/v1/access_pb.js';
	import { roleColor, roleIcon, roleLabel } from '#lib/roles.js';

	let { role = WorkspaceRole.UNSPECIFIED }: { role?: WorkspaceRole } = $props();

	const Icon = $derived(roleIcon(role));
</script>

<!-- Read-only by design. Roles change in the entity sheet, never by a stray click in a list. -->
<Badge variant="outline" class="font-normal">
	<Icon class={roleColor(role)} aria-hidden="true" />
	{roleLabel(role)}
</Badge>
