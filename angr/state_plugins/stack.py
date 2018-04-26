
import logging

from .plugin import SimStatePlugin

l = logging.getLogger('angr.state_plugins.stack')


class Stack():
    def __init__(self):
        return

    def __getitem__(self, offset):
        """Returns a tuple of a stack element as (addr, content)"""
        addr = self.state.regs.sp + offset * self.state.arch.bytes
        if self.state.solver.eval(addr >= self.state.arch.initial_sp):
            raise IndexError
        return addr, self.state.memory.load(addr, size=self.state.arch.bytes, endness=self.state.arch.memory_endness)