
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
        self.state.context_view.registers()
        self.state.context_view.code()
        self.state.context_view.stack()

    def code(self):
        print("[-------------------------------------code-------------------------------------]")
        try:
            self.__pprint_codeblock(self.state.history.bbl_addrs[-1])
            print("|\t" + "" + "\nv")
        except IndexError:
            pass
        self.__pprint_codeblock(self.state.solver.eval(self.state.regs.ip))


    def __pprint_codeblock(self, ip):
        if "functions" in dir(self.state.project.kb):
            f = self.state.project.kb.functions.floor_func(ip)
            print(f.name + "+" + hex(ip - f.addr))
        self.state.project.factory.block(ip).pp()

    def stack(self):
        stackdepth = 8
        print("[------------------------------------stack-------------------------------------]")
        #Not sure if that can happen, but if it does things will break
        if not self.state.regs.sp.concrete:
            print "STACK POINTER IS SYMBOLIC: " + str(self.state.regs.sp)
            return
        for o in range(stackdepth):
            self.__pprint_stack_element(o)


    def __pprint_stack_element(self, offset):
        """Print stack element in the form OFFSET| ADDRESS --> CONTENT"""
        print("%s| %x --> %s" % (
            "{0:#04x}".format(offset * self.state.arch.bytes),
            self.state.solver.eval(self.state.regs.sp + offset * self.state.arch.bits),
            self.__pstr_ast(self.state.stack_read(offset * self.state.arch.bits, self.state.arch.bytes))))


    def registers(self):
        """
        Visualise the register state
        """
        print("[----------------------------------registers-----------------------------------]")
        for reg in self.default_registers():
            register_number = self.state.arch.registers[reg][0]
            self.__pprint_register(reg, self.state.registers.load(register_number))

    def __pprint_register(self, reg, value):

        print reg.upper() + ":\t" + self.__pstr_ast(value)

    def __describe_addr(self, addr, depth=0):
        o = self.state.project.loader.find_object_containing(addr)
        if o:
            return " <%s>" % self.state.project.loader.describe_addr(addr)
        else:
            deref = self.state.mem[addr].uintptr_t.resolved
            if deref.concrete or not deref.uninitialized:
                return " --> %s" % self.__pstr_ast(deref)

    def __pstr_ast(self, ast):
        if ast.concrete:
            value = self.state.solver.eval(ast)
            if self.__describe_addr(value):
                return hex(value) + self.__describe_addr(value)
            else:
                return hex(value)
        else:
            return str(ast)

    def default_registers(self):
        custom ={
            'X86': ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip'],
            'AMD64': ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip', 'r8', 'r9', 'r10', 'r11', 'r12',
                      'r13', 'r14', 'r15']
        }
        if self.state.arch.name in custom:
            return custom[self.state.arch.name]
        else:
            l.warn("No custom register list implemented, using fallback")
            return self.state.arch.default_symbolic_registers\
                   + [self.state.arch.register_names[self.state.arch.ip_offset]]\
                   + [self.state.arch.register_names[self.state.arch.sp_offset]]\
                   + [self.state.arch.register_names[self.state.arch.bp_offset]]
