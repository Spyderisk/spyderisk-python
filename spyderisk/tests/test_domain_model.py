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

import domain_model as dm

# Download a domain model zip from e.g. https://github.com/Spyderisk/domain-network/packages/1826148
domain_model = dm.DomainModel("domain-network-6a5-1-1.zip")

for threat in sorted(domain_model.threats):
    print(threat.short_description)
    print("  ", threat.long_description)
    print()

for asset in sorted(domain_model.assets):
    props = []
    if asset.is_visible: props.append("visible")
    if asset.is_assertable: props.append("assertable")
    parents = sorted([parent.label for parent in asset.parents])
    if parents: props.append(f"subclass of {', '.join(parents)}")

    print(f"{asset.label} ({', '.join(props)})")
    print(f"  {asset.comment}")

    lines = []
    for twa in asset.trustworthiness_attributes:
        if not twa.is_visible:
            continue
        lines.append(f"  - {twa.label}: {twa.comment}")
    if lines:
        print("  Visible trustworthiness attributes:")
        print("\n".join(sorted(lines)))

    lines = []
    for twa in asset.trustworthiness_attributes:
        if twa.is_visible:
            continue
        lines.append(f"  - {twa.label}: {twa.comment}")
    if lines:
        print("  Hidden trustworthiness attributes:")
        print("\n".join(sorted(lines)))

    print()

for rel in domain_model.relations:
    print(rel.description)
    print()