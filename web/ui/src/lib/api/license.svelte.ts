import { LicenseService } from '$lib/gen/nokku/v1/license_pb';
import { useQuery } from '$lib/query';

export const license = {
	// The instance license is set via the NOKKU_LICENSE_KEY env var and
	// validated by the server, so there is no activation mutation.
	get: () => useQuery(LicenseService.method.getLicense)
};
