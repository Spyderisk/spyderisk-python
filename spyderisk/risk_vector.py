#!/usr/bin/python3.9

# Copyright 2024 University of Southampton IT Innovation Centre

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# <!-- SPDX-License-Identifier: Apache 2.0 -->
# <!-- SPDX-FileCopyrightText: 2024 The University of Southampton IT Innovation Centre -->
# <!-- SPDX-ArtifactOfProjectName: Spyderisk -->
# <!-- SPDX-FileType: Source code -->
# <!-- SPDX-FileComment: Original by Panos Melas, August 2024 -->

import logging
from functools import cache
from collections import defaultdict

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

class RiskVector:
    def __init__(self, risk_dict=None, risk_levels=None):
        # Initialize to empty dictionaries if None is provided
        risk_dict = risk_dict if risk_dict is not None else {}
        risk_levels = risk_levels if risk_levels is not None else {}

        self.risk_dict = self._normalise_dict(risk_dict)
        self.risk_levels = self._normalise_dict(risk_levels)

        self.sorted_levels = self._sort_dict(self.risk_levels)

    def _normalise_dict(self, a_dict):
        return {str(key): value for key, value in a_dict.items()}

    def _sort_dict(self, a_dict):
        # get a list of the form [('Medium', 2), ('Low', 1), ('Very Low', 0)]
        return sorted(a_dict.items(), key=lambda item: item[1], reverse=True)

    @property
    def risk_vector(self):
        return self._normalise_dict(self.risk_dict)

    @property
    def overall_level(self):
        if not self.risk_levels:
            return None
        return self.sorted_levels[0][0]

    def __str__(self):
        return "\n".join([f"{str(level[0])}: {self.risk_dict[level[0]]}" for level in self.sorted_levels])

    def __eq__(self, other):
        if not isinstance(other, RiskVector):
            print("here")
            return NotImplemented
        return (self.risk_dict == other.risk_dict) and (self.risk_levels == other.risk_levels)

    def __gt__(self, other):
        return self._compare(other, operator='gt')

    def __lt__(self, other):
        return self._compare(other, operator='lt')

    def _compare(self, other, operator):
        if not isinstance(other, RiskVector):
            return NotImplemented

        merged_levels = {**self.risk_levels, **other.risk_levels}
        sorted_levels = sorted(merged_levels.items(), key=lambda item: item[1])

        for level in sorted_levels:
            key = level[0]
            self_value = self.risk_dict.get(key, 0)
            other_value = other.risk_dict.get(key, 0)
            if operator == 'gt' and self_value > other_value:
                return True
            elif operator == 'lt' and self_value < other_value:
                return True

        return False

