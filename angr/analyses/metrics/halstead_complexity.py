import pyvex
import math


class HalsteadComplexity():
    """Represents the various Halstead metrics"""
    def __init__(self, function):

        self.n1, self.n2, self.N1, self.N2 = self.function_to_basemetrics(function)


    def function_to_basemetrics(self, function):
        """Calculates the basic metrics of Halstead out of a Function"""
        #TODO This implementation does not count calls to other functions and should only be regarded as an inital PoC !!!

        # the number of distinct operators
        n1 = len(set(function.operations))

        # the total number of operators
        N1 = len(function.operations)

        def getOperands(smt):
            """
            Get all Operands of a statement
            Operands are either constants or reads from a temporary register
            """
            unhandled = ["Ist_Dirty", 'Ist_CAS', 'Ist_AbiHint']
            if smt.tag in unhandled:
                #TODO: Figure out if they need to be handled somehow, ignoring for now
                return []
            if smt.tag == 'Ist_LoadG':
                return [getOperands(e) for e in smt.expressions]
            elif smt.tag[:3] == "Ist":
                exp = smt.data
            else:
                exp = smt
            if exp.child_expressions:
                return exp.child_expressions
            else:
                return [exp]

        def flattenList(l):
            return [item for sublist in l for item in sublist]

        # the number of distinct operands
        n2 = sum(
            [len(
                {smt for smt in block.vex.statements if isinstance(smt, pyvex.stmt.WrTmp)})
            for block in function.blocks])


        # the total number of operands
        N2 = len(
            flattenList(
                [getOperands(smt)
                for block in function.blocks
                    for smt in block.vex.statements if not smt.tag == 'Ist_IMark' and not smt.tag == "Ist_Exit"
                ]
                )
            )

        return (n1, n2, N1, N2)

    @property
    def program_vocabulary(self):
        return self.n1 + self.n2

    @property
    def program_length(self):
        return self.N1 + self.N2

    @property
    def calculated_program_length(self):
        return self.n1 * math.log(self.n1, 2) + self.n2 * math.log(self.n2, 2)

    @property
    def volume(self):
        return self.program_length * math.log(self.program_vocabulary, 2)

    @property
    def difficulty(self):
        return self.n1/2.0 * self.N2/self.n2

    @property
    def effort(self):
        return self.difficulty * self.volume

    def pp(self):
        raise NotImplementedError

    def getLatex(self):
        from IPython.display import Math
        return Math(r'\eta _{1} = %d \space \eta _{2} = %d \space  \,N_{1} = %d \space  \,N_{2} = %d \\ \
                      \hat {N}=%d \space V =%d \space D =%d \space E =%d \\ \
                      ' % (self.n1, self.n2, self.N1, self.N2,
                           self.calculated_program_length, self.volume, self.difficulty, self.effort))