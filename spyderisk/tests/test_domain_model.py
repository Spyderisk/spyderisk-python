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
from spyderisk.domain_model import TrustworthinessAttribute, TrustworthinessAttributeSet
from spyderisk.domain_model import Asset, Relation, Threat

#@unittest.skip("temporarily skipping domain model test")
class TestDomainModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.domain_model_path = os.path.join(os.path.dirname(__file__),
            'data', "domain-network-6a7-1-1-Beta-unfiltered.zip")
            #'data', "domain-network-6a6-1-2.zip")
        cls.domain_model = DomainModel(cls.domain_model_path)

    @classmethod
    def tearDownClass(cls):
        cls.domain_model = None
        cls.domain_model_path = None

    def test_version(self):
        version = self.domain_model.version_info
        print(f"Domain model version {version}")
        self.assertIsNotNone(version)

    def test_label(self):
        label = self.domain_model.label
        print(f"Domain model label {label}")
        self.assertIsNotNone(label)

    def test_comment(self):
        comment = self.domain_model.comment
        self.assertIsNotNone(comment)

    def test_assets(self):
        # Ensure that assetss are found
        assets = self.domain_model.assets
        self.assertGreater(len(assets), 0, "No assets found in the domain model.")

        # Check that each asset is an instance of Asset
        for asset in assets:
            self.assertIsInstance(asset, Asset)

    def test_relations(self):
        # Ensure that relations are found
        relations = self.domain_model.relations
        self.assertGreater(len(relations), 0, "No relations found in the domain model.")

        # Check that each relation is an instance of Relation
        for relation in relations:
            self.assertIsInstance(relation, Relation)

    def test_threats(self):
        # Ensure that threats are found
        threats = self.domain_model.threats
        self.assertGreater(len(threats), 0, "No threats found in the domain model.")

        # Check that each threat is an instance of Threat
        for threat in threats:
            self.assertIsInstance(threat, Threat)

    def test_trustworthiness_attributes(self):
        # Ensure that trustworthiness_attributes are found
        twas = self.domain_model.trustworthiness_attributes
        self.assertGreater(len(twas), 0, "No trustworthiness_attributes found in the domain model.")

        # Check that each trustworthiness_attribute is an instance of
        # TrustworthinessAttribute
        for twa in twas:
            self.assertIsInstance(twa, TrustworthinessAttribute)

    def test_trustworthiness_attributes_set(self):
        # Ensure that trustworthiness_attribute_sets are found
        twass = self.domain_model.trustworthiness_attributes_set
        self.assertGreater(len(twass), 0, "No trustworthiness_attribute_sets found in the domain model.")

        # Check that each trustworthiness_attribute_set is an instance of
        # TrustworthinessAttributeSet
        for twas in twass:
            self.assertIsInstance(twas, TrustworthinessAttributeSet)

    @unittest.skip("temporarily skipping domain model test")
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
