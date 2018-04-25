
import logging

from .plugin import SimStatePlugin

l = logging.getLogger('angr.state_plugins.context_view')


class ContextView(SimStatePlugin):
    def __init__(self):
        super(ContextView, self).__init__()

    @SimStatePlugin.memo
    def copy(self, memo):
        return ContextView()

    def red(self, text):
        return "\x1b[6;31;40m"+text+"\x1b[0m"

    def blue(self, text):
        return "\x1b[6;34;40m"+text+"\x1b[0m"

    def green(self, text):
        return "\x1b[6;32;40m"+text+"\x1b[0m"

    def yellow(self, text):
        return "\x1b[6;33;40m"+text+"\x1b[0m"

    def magenta(self, text):
        return "\x1b[6;35;40m"+text+"\x1b[0m"

    def underline(self, text):
        return "\x1b[4m"+text+"\x1b[0m"

    def grey(self, text):
        return "\x1b[6;90;1;40m"+text+"\x1b[0m"

    def BVtoREG(self, bv):
        if type(bv) == str:
            return bv
        if "reg" in str(bv):
            args = list()
            for v in self.state.se.describe_variables(bv):
                if "reg" in v:
                    ridx = v[1]
                    regname =  self.state.arch.register_names[ridx]
            replname = str(bv).replace("reg_"+hex(ridx)[2:], regname)
            return replname
        return str(bv)

    def print_legend(self):
        s = "LEGEND: "
        s += self.green("SYMBOLIC")
        s += " | "+ self.grey("UNINITIALIZED")
        s += " | "+ self.yellow("STACK")
        s += " | "+ self.blue("HEAP")
        s += " | "+ self.red("CODE")
        s += " | "+ self.magenta("DATA")
        s += " | "+ self.underline("RWX")
        s += " | RODATA"
        print(s)

    def cc(self, bv): # return color coded version of BV 
        x = self.BVtoREG(bv)
        if bv.symbolic:
            if bv.uninitialized:
                return self.grey(self.BVtoREG(bv))
            return self.green(self.BVtoREG(self.__pstr_ast(bv))) 
        # its concrete
        value = self.state.se.eval(bv)
        if self.state.project.loader.find_object_containing(value):
            descr = " <%s>" % self.state.project.loader.describe_addr(value)
            return self.red(hex(value) + descr)
        if value >= self.state.se.eval(self.state.regs.sp) and value <= self.state.arch.initial_sp:
            return self.yellow(hex(value))
        try:
            return self.__pstr_ast(bv)
        except Exception as e:
            return str(bv)
        

    def pprint(self):
        """Pretty context view similiar to the context view of gdb plugins (peda and pwndbg)"""
        self.print_legend()
        self.state.context_view.registers()
        self.state.context_view.code()
        self.state.context_view.stack()

    def code(self):
        print(self.blue("[-------------------------------------code-------------------------------------]"))
        try:
            self.__pprint_codeblock(self.state.history.bbl_addrs[-1])
            print("|\t" + self.cc(self.state.history.jump_guard) + "\nv")
        except IndexError:
            pass
        self.__pprint_codeblock(self.state.solver.eval(self.state.regs.ip))

    def __pprint_codeblock(self, ip):
        if "functions" in dir(self.state.project.kb):
            f = self.state.project.kb.functions.floor_func(ip)
            print(f.name + "+" + hex(ip - f.addr))
        self.state.project.factory.block(ip).pp()

    def stack(self):
        stackdepth = 24
        print(self.blue("[------------------------------------stack-------------------------------------]"))
        #Not sure if that can happen, but if it does things will break
        if not self.state.regs.sp.concrete:
            print "STACK POINTER IS SYMBOLIC: " + str(self.state.regs.sp)
            return
        for o in range(stackdepth):
            self.__pprint_stack_element(o)


    def __pprint_stack_element(self, offset):
        """Print stack element in the form OFFSET| ADDRESS --> CONTENT"""
        print("%s| %s --> %s" % (
            "{0:#04x}".format(offset * self.state.arch.bytes),
            self.cc(self.state.regs.sp + offset * self.state.arch.byte_width),
            self.cc(self.state.stack_read(offset * self.state.arch.byte_width, self.state.arch.bytes))))


    def registers(self):
        """
        Visualise the register state
        """
        print(self.blue("[----------------------------------registers-----------------------------------]"))
        for reg in self.default_registers():
            register_number = self.state.arch.registers[reg][0]
            self.__pprint_register(reg, self.state.registers.load(register_number))

    def __pprint_register(self, reg, value):
        repr = reg.upper() + ":\t"
        repr += self.cc(value)
        print(repr)

    def __describe_addr(self, addr, depth=0):
        o = self.state.project.loader.find_object_containing(addr)
        if o:
            return " <%s>" % self.state.project.loader.describe_addr(addr)
        else:
            deref = self.state.mem[addr].uintptr_t.resolved
            if deref.concrete or not deref.uninitialized:
                value = self.state.solver.eval(deref)
                if not value == addr:
                    return " --> %s" % self.__pstr_ast(deref)

    def __pstr_ast(self, ast):
        """Return a pretty string for an AST including a description of the derefed value if it makes sense (i.e. if
        the ast is concrete and the derefed value is not uninitialized"""
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

