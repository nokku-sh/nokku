import { CertificateService } from '#lib/gen/nokku/v1/certificates_pb.js';
import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { usePatch } from './mask';

// A workspace has one CA, so nothing here takes an id.
export const ca = {
	get: () =>
		useQuery(CertificateService.method.getCertificateAuthority, {}, () => ({
			select: (res) => res.certificateAuthority
		})),
	update: () => usePatch(CertificateService.method.updateCertificateAuthority),
	rollover: () =>
		useMutation(CertificateService.method.rolloverCertificateAuthority, {
			onSuccess: () => toast.success('New keys are in place')
		})
};
