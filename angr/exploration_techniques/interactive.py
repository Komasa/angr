from . import ExplorationTechnique

import logging
l = logging.getLogger("angr.exploration_techniques.interactive")

class Interactive(ExplorationTechnique):
    """
    Interactively explore a state
    """
    def __init__(self):
        super(Interactive, self).__init__()
        self._complete = False

    def step(self, simgr, stash=None, **kwargs):
        if len(simgr.active) != 1:
            if not type(kwargs.get("pick")) is int:
                if type(kwargs.get("p")) is int:
                    simgr.active[kwargs.get("p")].context_view.pprint()
                l.warn("Multiple active states, pick one")
                self._complete = True
            else:
                ip = simgr.active[kwargs.get('pick')].regs.ip
                print("Picking state with ip: " + (str(ip)))
                simgr.move(from_stash='active',
                           to_stash="stashed",
                           filter_func=lambda x: x.solver.eval(ip != x.regs.ip))
                simgr.step(stash=stash, extra_stop_points=None)
                if type(kwargs.get("p")) is int:
                    simgr.active[kwargs.get("p")].context_view.pprint()

        else:
            simgr.step(stash=stash, extra_stop_points=None)
            if type(kwargs.get("p"))is int:
                simgr.one_active.context_view.pprint()
            if len(simgr.active) != 1:
                return simgr.active[0].context_view.pprint()


    def complete(self, simgr):
        return self._complete
