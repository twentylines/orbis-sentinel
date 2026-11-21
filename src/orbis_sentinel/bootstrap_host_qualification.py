"""First-write qualification from the retained Host's actual held observations."""

from . import bootstrap_publication as publication
from . import bootstrap_source as source
from .bootstrap_host_transition import _file
from .bootstrap_source import decode, digest, encoded, fail


def ensure_qualification(writer, resources, directory, namespace, recovery, review, packet, completion,
                         approval, setup_sha, client, verify, guard, product, admission):
    """Persist observations before Ready; existing durable evidence is replay-only."""
    saved = _file(namespace, publication.QUALIFICATION_FILE, 16384, optional=True)
    if saved is None:
        # This producer has no authority after Ready or either retirement starts.
        # In particular it cannot recreate missing evidence after a lost reply.
        evidence = publication._Evidence(resources)
        evidence.absent(namespace, 'credential-bootstrap-ready.json', 'credential-bootstrap-publication-hold.json',
            '.credential-bootstrap-ready.json.pending', '.credential-bootstrap-publication-hold.json.pending',
            publication.RELEASE_FILE, publication.RETIRED_FENCE, publication.RETIRED_INTENT,
            '.' + publication.RELEASE_FILE + '.pending', '.' + publication.RETIRED_FENCE + '.pending',
            '.' + publication.RETIRED_INTENT + '.pending', '.' + publication.FENCE + '.pending',
            '.' + publication.INTENT + '.pending')
        if evidence.file(namespace, publication.FENCE, 4096) != publication._fence(packet):
            fail()
        publication._intent(packet, completion, approval, evidence.document(namespace, publication.INTENT))
        pair = evidence.document(recovery, publication.PAIRED_TRANSPORT_FILE, 32768)
        pair_sha = pair.get('pairSha256')
        binding = {'setupSha256': setup_sha, 'pairSha256': pair_sha}
        if not source.hash_value(pair_sha):
            fail()
        setup_receipts = publication._setup_evidence(evidence, recovery, review, binding)
        history = evidence.file(directory, 'activation-history.json', 65536)
        config = evidence.file(directory, 'activation-config.json', 16384)
        terminal = evidence.file(directory, 'held-activation-terminal.json', 16384)

        def check():
            verify()
            evidence.recheck()
            guard.check(packet['operationId'], packet['reviewSha256'])

        check()
        arguments = {'operationId': packet['operationId'], 'planSha256': packet['planSha256'],
                     'packetSha256': completion['packetSha256']}
        receipt = client.call('bootstrap-held-activation-reconcile', arguments)
        if writer.activation._completion(directory, packet, completion['packetSha256'],
                                         completion['intentSha256'], receipt) != completion:
            fail()
        check()
        value = publication.qualification_evidence(
            review, packet, completion, setup_sha, pair_sha, receipt, history, config, terminal, setup_receipts)
        qualification = publication.qualification_record(value, completion, review, setup_sha, pair_sha)
        writer._put(product, admission, namespace, publication.QUALIFICATION_EVIDENCE_FILE, encoded(value))
        check()
        writer._put(product, admission, namespace, publication.QUALIFICATION_FILE, encoded(qualification))
        check()
    else:
        qualification = decode(saved)
        if encoded(qualification) != saved:
            fail()
        publication._qualification(qualification, completion, review, setup_sha)

    pinned = publication._Evidence(resources)
    if pinned.document(namespace, publication.QUALIFICATION_FILE) != qualification:
        fail()
    publication._qualification_evidence(pinned, namespace, recovery, review, packet, completion, qualification)
    pinned.absent(namespace, '.' + publication.QUALIFICATION_FILE + '.pending')
    pinned.recheck()
    verify()
    # Visible exact files can survive a failed post-rename directory sync.
    # Finish both durability obligations before Ready is allowed to observe them.
    writer._put(product, admission, namespace, publication.QUALIFICATION_EVIDENCE_FILE,
                encoded(pinned.document(namespace, publication.QUALIFICATION_EVIDENCE_FILE, 32768)))
    writer._put(product, admission, namespace, publication.QUALIFICATION_FILE, encoded(qualification))
    pinned.recheck()
    verify()
    return qualification, pinned.recheck
