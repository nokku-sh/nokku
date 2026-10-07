<script lang="ts">
	import PageHeader from '#lib/components/layout/PageHeader.svelte';
	import Checkup from './Checkup.svelte';
	import RecentSignIns from './RecentSignIns.svelte';
	import Sessions from './Sessions.svelte';
	import SignInMethods from './SignInMethods.svelte';
</script>

<PageHeader title="Security" description="How you sign in and where you are signed in" />

<Checkup />
<SignInMethods />
<Sessions />
<RecentSignIns />
