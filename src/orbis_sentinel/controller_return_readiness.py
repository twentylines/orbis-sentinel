"""Join the installed Gateway, status and return transport without granting authority."""

import math
import re
import threading
import time

from .controller_return import ControllerReturnApprovals, return_scope
from .controller_return_transport import ControllerReturnTransport
from .observer import HANDOFF_MAX_AGE_MS, validate_handoff_envelope


READINESS = 'controller-return-readiness'
APPROVAL = 'controller-return-approval'
RETURN = 'controller-return'
ARM = 'controller-return-readiness-arm'
PROBE_SECONDS = 8
_HASH = re.compile(r'[a-f0-9]{64}')
_INVOCATION = re.compile(r'[a-f0-9]{32}')


def readiness_request(value):
    if (type(value) is not dict or set(value) != {'challenge', 'installationId', 'invocationId', 'markerSha256'}
            or any(type(value[key]) is not str or not _HASH.fullmatch(value[key])
                   for key in ('challenge', 'installationId', 'markerSha256'))
            or type(value['invocationId']) is not str or not _INVOCATION.fullmatch(value['invocationId'])):
        raise ValueError('Invalid controller return readiness challenge.')
    return dict(value)


def readiness_reply(request):
    return {'schema': 'orbis.controller-return-readiness.v1', **request}


class ControllerReturnGateway:
    """Share one Sessions authority across the Gateway and the pinned Root control."""

    def __init__(self, sessions, *, origin, setup, invocation_id, handoff_status):
        self.approvals = ControllerReturnApprovals(sessions, origin=origin)
        self.transport = ControllerReturnTransport(origin=origin)
        self.setup, self.invocation_id, self.handoff_status = setup, invocation_id, handoff_status
        self._lock = threading.Lock()
        self._armed = None

    def _binding(self, request):
        self.setup.verify()
        value = readiness_request(request)
        if (value['installationId'], value['invocationId'], value['markerSha256']) != (
                self.setup.installation, self.invocation_id, self.setup.sha256):
            raise ValueError('The paired listener changed.')
        return value

    def arm(self, request):
        value = self._binding(request)
        with self._lock:
            self._armed = value, time.monotonic() + PROBE_SECONDS
        return value

    def _observation(self):
        started = time.monotonic()
        value = validate_handoff_envelope(self.handoff_status())
        if (value['status'] is None
                or value['ageMs'] + math.ceil((time.monotonic() - started) * 1000) > HANDOFF_MAX_AGE_MS):
            raise RuntimeError('Observed handoff status is unavailable.')
        return value

    def route_probe(self, request, method, path):
        value = readiness_request(request)
        with self._lock:
            if self._armed is None or self._armed[0] != value or time.monotonic() >= self._armed[1]:
                raise ValueError('Controller return readiness challenge expired.')
        self._binding(value)
        return {**readiness_reply(value), 'method': method, 'path': path}

    def readiness(self, request):
        value = readiness_request(request)
        with self._lock:
            armed = self._armed
            if armed is None or armed[0] != value or time.monotonic() >= armed[1]:
                raise ValueError('Controller return readiness challenge expired.')
            self._armed = None
        self._binding(value)
        self.approvals.readiness()
        handoff = self._observation()['status']['handoff']
        if handoff is not None and handoff['state'] == 'held' and handoff['returnScope']['installationId'] != value['installationId']:
            raise RuntimeError('The observed handoff installation changed.')
        reply = self.transport.readiness(value)
        if reply != readiness_reply(value) or time.monotonic() >= armed[1]:
            raise RuntimeError('Controller return readiness could not be verified.')
        self.setup.verify()
        return reply

    def _held_scope(self, requested):
        expected = return_scope(requested)
        self.setup.verify()
        started = time.monotonic()
        observation = self._observation()
        deadline = started + (HANDOFF_MAX_AGE_MS - observation['ageMs']) / 1000
        handoff = observation['status']['handoff']
        if (handoff is None or handoff['state'] != 'held' or handoff['returnScope'] != expected
                or expected['installationId'] != self.setup.installation):
            raise RuntimeError('The controller return scope changed.')
        def check():
            if time.monotonic() >= deadline:
                raise RuntimeError('The observed controller return scope expired.')
        check()
        return expected, check

    def approve(self, request, *, token, csrf, origin):
        if set(request) != {'scope'}:
            raise ValueError('One observed controller return scope is required.')
        scope, check = self._held_scope(request['scope'])
        return self.approvals.approve(token=token, csrf=csrf, origin=origin, scope=scope, check=check)

    def apply(self, request, *, token, csrf, origin):
        if set(request) != {'scope', 'approvalId'}:
            raise ValueError('One approved controller return scope is required.')
        scope, check = self._held_scope(request['scope'])
        self.approvals.authorize(token=token, csrf=csrf, origin=origin, scope=scope,
                                 approval_id=request['approvalId'], check=check)
        self.setup.verify()
        check()
        result = self.transport.apply(plan_id=scope['planId'], approval_id=request['approvalId'])
        if result['phase'] not in ('return-accepted', 'returning', 'complete') or result['state'] != result['phase']:
            raise RuntimeError('Controller return could not be confirmed.')
        return {key: result[key] for key in ('planId', 'state', 'phase')}
