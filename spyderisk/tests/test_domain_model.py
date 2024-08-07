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

import unittest
from spyderisk.domain_model import DomainModel

#@unittest.skip("temporarily skipping domain model test")
class TestDomainModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.domain_model_path = os.path.join(os.path.dirname(__file__),
                'data', "domain-network-6a6-1-2.zip")
        cls.domain_model = DomainModel(cls.domain_model_path)

    @classmethod
    def tearDownClass(cls):
        cls.domain_model = None
        cls.domain_model_path = None


    def test_version(self):
        version = self.domain_model.version_info
        self.assertIsNotNone(version)

    def test_label(self):
        label = self.domain_model.label
        self.assertIsNotNone(label)

    def test_comment(self):
        comment = self.domain_model.comment
        self.assertIsNotNone(comment)

    def test_threat(self):
        for threat in sorted(self.domain_model.threats):
            print(threat.short_description)
            print("  ", threat.long_description)
            print()

    def test_asset(self):
        for asset in sorted(self.domain_model.assets):
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

    def test_rel(self):
        for rel in self.domain_model.relations:
            print(rel.description)
            print()

    def test_twa(self):
        twas = self.domain_model.trustworthiness_attributes
        self.assertIsNotNone(twas)

    #@unittest.skip("temporarily skipping twa_set domain test")
    def test_twa_set(self):
        twass = self.domain_model.trustworthiness_attributes_set
        self.assertIsNotNone(twass)


if __name__ == "__main__":
    unittest.main()
