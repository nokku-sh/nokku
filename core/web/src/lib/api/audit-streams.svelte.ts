import { toast } from 'svelte-sonner';
import { useMutation, useQuery } from '#lib/query/index.js';
import { AuditStreamService } from '#lib/gen/nokku/v1/audit_stream_pb.js';

export const auditStreams = {
	list: () =>
		useQuery(AuditStreamService.method.listAuditStreams, {}, { select: (res) => res.streams }),

	create: () =>
		useMutation(AuditStreamService.method.createAuditStream, {
			onSuccess: () => toast.success('Stream added, new events go out within seconds')
		}),
	update: () => useMutation(AuditStreamService.method.updateAuditStream),
	remove: () =>
		useMutation(AuditStreamService.method.deleteAuditStream, {
			onSuccess: () => toast.success('Stream removed')
		}),
	test: () =>
		useMutation(AuditStreamService.method.testAuditStream, {
			onSuccess: () => toast.success('The destination took the test event')
		})
};
