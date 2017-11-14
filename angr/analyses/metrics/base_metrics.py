

class BaseMetrics():
    def __init__(self, function):
        self.function = function
        self._name = "Base Metrics"

    @property
    def loads(self):
        """All loads that are done by this functions."""
        return len({exp for block in self.blocks for exp in block.vex.expressions if exp.tag == "Iex_Load" })

    @property
    def stores(self):
        """All stores that are done by this function"""
        return len({exp for block in self.blocks for exp in block.vex.statements if exp.tag == "Ist_Store"})


