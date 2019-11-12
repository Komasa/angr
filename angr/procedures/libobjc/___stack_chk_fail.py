import angr

######################################
# exit
######################################

class ___stack_chk_fail(angr.SimProcedure): #pylint:disable=redefined-builtin
    #pylint:disable=arguments-differ

    NO_RET = True
    def run(self):
        pass