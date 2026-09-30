<script lang="ts">
	import { PrivacyURL, ToSURL } from '$lib/config';

	/** Everything before "you agree", e.g. "By signing up,". */
	let { lead }: { lead: string } = $props();
</script>

<p class="text-center text-xs text-balance text-muted-foreground">
	{lead} you agree to the
	<a
		href={ToSURL}
		target="_blank"
		rel="noopener"
		class="underline underline-offset-2 hover:text-foreground">Terms</a
	>
	and the
	<a
		href={PrivacyURL}
		target="_blank"
		rel="noopener"
		class="underline underline-offset-2 hover:text-foreground">Privacy Policy</a
	>.
</p>
