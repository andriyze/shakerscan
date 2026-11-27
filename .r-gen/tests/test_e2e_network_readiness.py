"""Exercise startup transitions and deadlines without sleeping or network traffic."""
from tests.e2e.network_readiness import wait_network_readiness


class Clock:
    now = 0

    def read(self):
        return self.now

    def pause(self, duration):
        self.now += duration


def test_starting_waits_for_a_real_ready_worker():
    clock = Clock()
    starting = {'status':'starting', 'worker_count':0}
    ready = {'status':'ready', 'worker_count':1, 'capable_worker_count':1}
    responses = iter([starting, starting, ready])
    assert wait_network_readiness(lambda:next(responses), clock=clock.read, pause=clock.pause) == ready
    assert clock.now == 4


def test_starting_at_deadline_remains_a_failure_not_ready():
    clock = Clock()
    result = wait_network_readiness(lambda:{'status':'starting'}, timeout=5,
                                   clock=clock.read, pause=clock.pause)
    assert result['status'] == 'starting'
    assert clock.now == 5


def test_explicit_opt_out_and_worker_failure_are_not_hidden_by_polling():
    for state in ('disabled', 'not_ready', 'unknown'):
        clock = Clock()
        assert wait_network_readiness(lambda:{'status':state}, clock=clock.read,
                                      pause=clock.pause)['status'] == state
        assert clock.now == 0
