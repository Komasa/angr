
import logging

from .. import SIM_PROCEDURES
from . import SimLibrary

_l = logging.getLogger(name=__name__)


libobjc = SimLibrary()

libobjc.set_library_names('libobjc.A.dylib')
libobjc.add_all_from_dict(SIM_PROCEDURES['libobjc'])


libSystem = SimLibrary()

libSystem.set_library_names('libSystem.B.dylib')

libSystem.add("___stack_chk_fail", SIM_PROCEDURES['libobjc']["___stack_chk_fail"])