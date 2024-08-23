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

import unittest
from rdflib import Literal

from spyderisk.config.test_config import TEST_DOMAIN_FILE

from spyderisk.domain_model import DomainModel
from spyderisk.domain_model import TrustworthinessAttribute, TrustworthinessAttributeSet
from spyderisk.domain_model import Asset, Relation, Threat, ThreatCategory, Likelihood
from spyderisk.domain_model import RootPattern, MatchingPattern, ConstructionPattern
from spyderisk.domain_model import ControlStrategy, PerformanceImpactLevel


# @unittest.skip("temporarily skipping domain model test")
class TestDomainModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.domain_model = DomainModel(TEST_DOMAIN_FILE)

    @classmethod
    def tearDownClass(cls):
        cls.domain_model = None
        cls.domain_model_path = None

    def test_inferred_link(self):
        pass

    def test_node(self):
        pass

    def test_role_link(self):
        pass

    def test_control_strategies(self):
        csgs = self.domain_model.control_strategies
        for csg in csgs:
            self.assertIsInstance(csg, ControlStrategy, "not a control strategy")

    def test_construction_patterns(self):
        cps = self.domain_model.construction_patterns
        for cp in cps:
            self.assertIsInstance(cp, ConstructionPattern, "not a construction pattern")

    def test_matching_patterns(self):
        mps = self.domain_model.matching_patterns
        for mp in mps:
            self.assertIsInstance(mp, MatchingPattern, "not a matching pattern")
            print(mp.summary())

    def test_root_patterns(self):
        rps = self.domain_model.root_patterns
        for rp in rps:
            self.assertIsInstance(rp, RootPattern, "not a matching pattern")

    def test_version(self):
        version = self.domain_model.version_info
        self.assertIsInstance(version, Literal, "cost label should be an RDF Literal")
        self.assertIsNotNone(version)

    def test_cost_level_range(self):
        cost_range = self.domain_model.cost_level_range()
        for rl in cost_range:
            value = self.domain_model.level_value(rl)
            self.assertIsInstance(value, int, "cost level value should be an int")
            label = self.domain_model.label_uri(rl)
            self.assertIsInstance(label, Literal, "cost label should be an RDF Literal")

    def test_impact_level_range(self):
        impact_range = self.domain_model.impact_level_range()
        for rl in impact_range:
            value = self.domain_model.level_value(rl)
            self.assertIsInstance(value, int, "impact level value should be an int")
            label = self.domain_model.label_uri(rl)
            self.assertIsInstance(label, Literal, "impact label should be an RDF Literal")

    def test_performance_impact_level_range(self):
        performance_impact_range = self.domain_model.performance_impact_level_range()
        for rl in performance_impact_range:
            pil = PerformanceImpactLevel(rl, self.domain_model)
            value = self.domain_model.level_value(rl)
            self.assertIsInstance(value, int, "performance_impact level value should be an int")
            self.assertIsInstance(pil.level_value, int, "performance_impact level value should be an int")
            self.assertEqual(value, pil.level_value)
            label = self.domain_model.label_uri(rl)
            self.assertIsInstance(label, Literal, "performance_impact label should be an RDF Literal")

    def test_population_level_range(self):
        population_range = self.domain_model.population_level_range()
        for rl in population_range:
            value = self.domain_model.level_value(rl)
            self.assertIsInstance(value, int, "population level value should be an int")
            label = self.domain_model.label_uri(rl)
            self.assertIsInstance(label, Literal, "population label should be an RDF Literal")

    def test_risk_level_range(self):
        risk_range = self.domain_model.risk_level_range()
        allowed_values = {"Very Low", "Low", "Medium", "High", "Very High"}
        for rl in risk_range:
            value = self.domain_model.level_value(rl)
            self.assertIsInstance(value, int, "risk level value should be an int")
            label = self.domain_model.label_uri(rl)
            self.assertIsInstance(label, Literal, "risk label should be an RDF Literal")
            self.assertIn(str(label), allowed_values, f"label value '{str(label)}' is not in the allowed set")

    def test_tw_level_range(self):
        tw_range = self.domain_model.tw_level_range()
        for rl in tw_range:
            value = self.domain_model.level_value(rl)
            self.assertIsInstance(value, int, "tw level value should be an int")
            label = self.domain_model.label_uri(rl)
            self.assertIsInstance(label, Literal, "tw label should be an RDF Literal")

    def test_label(self):
        label = self.domain_model.label
        self.assertIsInstance(label, Literal, "label should be an RDF Literal")

    def test_comment(self):
        comment = self.domain_model.comment
        self.assertIsInstance(comment, Literal, "comment should be an RDF Literal")
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

    def test_asset(self):
        for asset in sorted(self.domain_model.assets):
            props = []
            if asset.is_visible:
                props.append("visible")
            if asset.is_assertable:
                props.append("assertable")
            parents = sorted([parent.label for parent in asset.parents])
            if parents:
                props.append(f"subclass of {', '.join(parents)}")

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

    def test_twa(self):
        twas = self.domain_model.trustworthiness_attributes
        self.assertIsNotNone(twas)

    # @unittest.skip("temporarily skipping twa_set domain test")
    def test_twa_set(self):
        twass = self.domain_model.trustworthiness_attributes_set
        self.assertIsNotNone(twass)


if __name__ == "__main__":
    unittest.main()
