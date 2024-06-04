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
# <!-- SPDX-FileComment: Original by Stephen Phillips, June 2024 -->

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import system_model as sm

system_model = sm.SystemModel("steel.nq.gz", "domain-network-6a5-1-1.zip")

for asset in system_model.assets:
    print(asset.description)
    print()

for control_set in system_model.control_sets:
    print(control_set.description)
    print()

for misbehaviour_set in system_model.misbehaviour_sets:
    print(misbehaviour_set.description)
    print()

for twas in system_model.trustworthiness_attribute_sets:
    print(twas.description)
    print()

for threat in system_model.threats:
    print(threat)
    print()

for control_strategy in system_model.control_strategies:
    print(control_strategy.description)
    print()
