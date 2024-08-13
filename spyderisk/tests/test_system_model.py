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

import unittest
from spyderisk.system_model import SystemModel
from spyderisk.system_model import Relation, TrustworthinessAttributeSet
from spyderisk.system_model import Asset, ControlSet, MisbehaviourSet, Threat
from spyderisk.system_model import ControlStrategy
from spyderisk.risk_vector import RiskVector

#@unittest.skip("temporarily skipping system model test")
class TestSystemModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.domain_model_path = os.path.join(os.path.dirname(__file__),
                'data', "domain-network-6a7-1-1-Beta-unfiltered.zip")
                #'data', "domain-network-6a6-1-2.zip")
        cls.system_model_path = os.path.join(os.path.dirname(__file__),
                'data', "router_v1-b.nq.gz")
                #'data', "router.nq.gz")
        cls.system_model = SystemModel(cls.system_model_path, cls.domain_model_path)

    @classmethod
    def tearDownClass(cls):
        cls.system_model = None
        cls.domain_model_path = None
        cls.system_model_path = None

    def test_version(self):
        version = self.system_model.domain_version
        self.assertIsNotNone(version)

    def test_risks_valid(self):
        result = self.system_model.risks_valid
        self.assertTrue(result, bool)

    def test_is_valid(self):
        result = self.system_model.is_valid
        self.assertTrue(result, bool)

    def test_is_validating(self):
        result = self.system_model.is_validating
        self.assertFalse(result, bool)

    def test_is_calculating_risk(self):
        result = self.system_model.is_calculating_risk
        self.assertFalse(result, bool)

    def test_created(self):
        created = self.system_model.created
        self.assertIsNotNone(created)

    def test_modified(self):
        modified = self.system_model.modified
        self.assertIsNotNone(modified)

    @unittest.skip("temporarily skipping test")
    def test_me(self):
        print("test me")
        info = self.system_model.info
        breakpoint()

    #@unittest.skip("temporarily skipping test")
    def test_threatens(self):
        threats = self.system_model.threats
        for thr in threats:
            a_uri = thr.threatens
            threatens_asset = self.system_model.get_entity(a_uri)
            self.assertIsInstance(threatens_asset, Asset)

    #@unittest.skip("temporarily skipping test")
    def test_assets(self):
        # Ensure that assets are found
        assets = self.system_model.assets
        self.assertGreater(len(assets), 0, "No assets found in the system model.")

        # Check that each asset is an instance of Asset
        for asset in assets:
            self.assertIsInstance(asset, Asset)

    def test_control_sets(self):
        # Ensure that control sets are found
        control_sets = self.system_model.control_sets
        self.assertGreater(len(control_sets), 0, "No control_sets found in the system model.")

        # Check that each control set is an instance of ControlSet
        for control_set in control_sets:
            self.assertIsInstance(control_set, ControlSet)

    def test_misbehaviour_sets(self):
        # Ensure that misbehaviour sets are found
        misbehaviour_sets = self.system_model.misbehaviour_sets
        self.assertGreater(len(misbehaviour_sets), 0, "No misbehaviour_sets found in the system model.")

        # Check that each misbehaviour set is an instance of MisbehaviourSet
        for misbehaviour_set in misbehaviour_sets:
            self.assertIsInstance(misbehaviour_set, MisbehaviourSet)

    def test_threats(self):
        # Ensure that threats are found
        threats = self.system_model.threats
        self.assertGreater(len(threats), 0, "No threats found in the system model.")

        # Check that each threat is an instance of Threat
        for threat in threats:
            self.assertIsInstance(threat, Threat)

    def test_relations(self):
        # Ensure that relations are found
        relations = self.system_model.relations
        self.assertGreater(len(relations), 0, "No relations found in the system model.")

        # Check that each relation is an instance of Relation
        for relation in relations:
            self.assertIsInstance(relation, Relation)

    def test_trustworthiness_attribute_sets(self):
        # Ensure that twas are found
        trustworthiness_attribute_sets = self.system_model.trustworthiness_attribute_sets
        self.assertGreater(len(trustworthiness_attribute_sets), 0, "No trustworthiness_attribute_sets found in the system model.")

        # Check that each twas is an instance of TrustworthinessAttributeSet 
        for trustworthiness_attribute_set in trustworthiness_attribute_sets:
            self.assertIsInstance(trustworthiness_attribute_set, TrustworthinessAttributeSet)

    def test_control_strategies(self):
        # Ensure that control strategies are found
        control_strategies = self.system_model.control_strategies
        self.assertGreater(len(control_strategies), 0, "No control_strategies found in the system model.")

        # Check that each control_strategy is an instance of ControlStrategy
        for control_strategy in control_strategies:
            self.assertIsInstance(control_strategy, ControlStrategy)


    @unittest.skip("temporarily skipping test")
    def test_control_set(self):
        for control_set in self.system_model.control_sets:
            print(control_set.description)
            print()

    @unittest.skip("temporarily skipping test")
    def test_misbehaviour_set(self):
        for misbehaviour_set in self.system_model.misbehaviour_sets:
            print(misbehaviour_set.description)
            print()

    @unittest.skip("temporarily skipping test")
    def test_twas(self):
        for twas in self.system_model.trustworthiness_attribute_sets:
            print(twas.description)
            print()

    @unittest.skip("temporarily skipping test")
    def test_threat(self):
        for threat in self.system_model.threats:
            print(threat)
            print()

    @unittest.skip("temporarily skipping test")
    def test_control_strategy(self):
        for control_strategy in self.system_model.control_strategies:
            print(control_strategy.description)
            print()

    @unittest.skip("temporarily skipping test")
    def test_relation(self):
        for relation in self.system_model.relations:
            print(relation.description)
            print()

if __name__ == "__main__":
    unittest.main()
