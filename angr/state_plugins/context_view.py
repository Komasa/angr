
import logging

from .plugin import SimStatePlugin

l = logging.getLogger('angr.state_plugins.context_view')


class ContextView(SimStatePlugin):
    def __init__(self):
        pass
