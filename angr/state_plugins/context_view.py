
import logging

from .plugin import SimStatePlugin

l = logging.getLogger('angr.state_plugins.context_view')


class ContextView(SimStatePlugin):
    def __init__(self):
        super(ContextView, self).__init__()

    @SimStatePlugin.memo
    def copy(self, memo):
        return ContextView()

    def pprint(self):
        """Pretty context view similiar to the context view of gdb plugins (peda and pwndbg)"""
        raise NotImplementedError

    def registers(self):
        """
        Visualise the register state
        state.arch.default_symbolic_registers is supposed to give a sensible definition of general purpose registers
        Ordering is decided by the VEX register number
        """
        for regnum,reg in sorted(
                [(k,v) for k,v in self.state.context_view.state.arch.register_names.iteritems()
                 if v in self.state.arch.default_symbolic_registers], key=lambda x: x[0]):
            self.__pprint_register(reg, self.state.registers.load(regnum))

    def __pprint_register(self, reg, value):
        print reg.upper() + ":\t"+ str(value)
