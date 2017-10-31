
import logging
from angr.analyses import Analysis, register_analysis
from angr.analyses.metrics import *

l = logging.getLogger("angr.analyses.complexity_analysis")

"""
Structure:

ComplexityAnalysis Class that will be accessable via a property of a function
This class has various metrics as properties, either as simple functions
for something like cyclomatic complexity or classes for something like Halstead

"""


class ComplexityAnalysis(Analysis):
    """Class that provides all the analysis methods"""
    def __init__(self, function):
        self.function = function
        self.metric_cache = {}


    @property
    def cyclomatic_complexity(self):
        """Calculate the cyclomatic complexity of a given cfg"""
        if "Cyclomatic" not in self.metric_cache:
            with self._resilience():
                self.metric_cache['Cyclomatic'] = CyclomaticComplexity(self.function)
            return self.metric_cache['Cyclomatic']

    @property
    def halstead_complexity(self):
        if "Halstead" not in self.metric_cache:
            with self._resilience():
                self.metric_cache['Halstead'] = HalsteadComplexity(self.function)
            if "Halstead" not in self.metric_cache:
                # TODO find better way to deal with failed analysis
                return None

        return self.metric_cache['Halstead']


register_analysis(ComplexityAnalysis, 'Complexity')
