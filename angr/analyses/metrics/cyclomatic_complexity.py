

class CyclomaticComplexity():
    def __init__(self, function):
        self.function = function
        self._name = "Cyclomatic Complexity"
        self.value = len(self.function.graph.edges()) - len(self.function.graph.nodes()) + 2

