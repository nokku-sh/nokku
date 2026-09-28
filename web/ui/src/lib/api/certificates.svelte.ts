import {
	CertificateService,
	SignSSHCertificateRequest_CertificateType
} from '$lib/gen/nokku/v1/certificates_pb';
import { toast } from 'svelte-sonner';
import { plural, useBulkMutation } from './bulk';
import { extract, type MaybeGetter } from 'runed';
import { useMutation, useQuery } from '$lib/query';
import { workspaceID } from '$lib/store.svelte';

export const sign = {
	user: () =>
		useMutation(CertificateService.method.signSSHCertificate, {
			onSuccess: () => toast.success('Certificate signed'),
			transform: (variables) => ({
				...variables,
				type: SignSSHCertificateRequest_CertificateType.USER
			})
		}),
	host: () =>
		useMutation(CertificateService.method.signSSHCertificate, {
			onSuccess: () => toast.success('Host certificate signed'),
			transform: (variables) => ({
				...variables,
				type: SignSSHCertificateRequest_CertificateType.HOST
			})
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
			() => ({ workspaceId: workspaceID.current, id: extract(id) }),
			() => ({
				enabled: !!workspaceID.current && !!extract(id),
				select: (res) => res.certificateAuthority
			})
		),
	list: () =>
		useQuery(
			CertificateService.method.listCertificateAuthorities,
			() => ({ workspaceId: workspaceID.current }),
			() => ({ enabled: !!workspaceID.current, select: (res) => res.certificateAuthorities })
		),

	create: () =>
		useMutation(CertificateService.method.createCertificateAuthority, {
			onSuccess: () => toast.success('Certificate Authority created!')
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
				toast.success('Certificate Authority rolled over');
			}
		})
};
