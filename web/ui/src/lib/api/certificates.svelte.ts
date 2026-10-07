import { CertificateService } from '#lib/gen/nokku/v1/certificates_pb.js';
import { toast } from 'svelte-sonner';
import { plural, useBulkMutation } from './bulk';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '#lib/query/index.js';

export const sign = {
	user: () =>
		useMutation(CertificateService.method.signSSHCertificate, {
			onSuccess: () => toast.success('Certificate signed')
		}),
	x509: () =>
		useMutation(CertificateService.method.signX509Certificate, {
			onSuccess: () => toast.success('Certificate signed')
		})
};

export const ca = {
	get: (id: MaybeGetter<string | undefined>) =>
		useQuery(
			CertificateService.method.getCertificateAuthority,
			() => ({ id: extract(id) }),
			() => ({
				enabled: !!extract(id),
				select: (res) => res.certificateAuthority
			})
		),
	list: () =>
		useQuery(CertificateService.method.listCertificateAuthorities, {}, () => ({
			select: (res) => res.certificateAuthorities
		})),

	create: () =>
		useMutation(CertificateService.method.createCertificateAuthority, {
			onSuccess: () => toast.success('Certificate authority created')
		}),
	update: () => useMutation(CertificateService.method.updateCertificateAuthority),
	delete: () => useMutation(CertificateService.method.deleteCertificateAuthority),
	deleteMany: () =>
		useBulkMutation(
			CertificateService.method.deleteCertificateAuthority,
			(n) => `${plural(n, 'certificate authority', 'certificate authorities')} deleted`
		),
	rollover: () =>
		useMutation(CertificateService.method.rolloverCertificateAuthority, {
			onSuccess: (data) => {
				if (!data.certificateAuthority) {
					toast.success('Rollover skipped');
					return;
				}
				toast.success('Certificate authority rolled over');
			}
		})
};
