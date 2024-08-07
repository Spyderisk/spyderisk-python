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

#@unittest.skip("temporarily skipping system model test")
class TestSystemModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.domain_model_path = os.path.join(os.path.dirname(__file__),
                'data', "domain-network-6a6-1-2.zip")
        cls.system_model_path = os.path.join(os.path.dirname(__file__),
                'data', "router.nq.gz")
        cls.system_model = SystemModel(cls.system_model_path, cls.domain_model_path)

    @classmethod
    def tearDownClass(cls):
        cls.system_model = None
        cls.domain_model_path = None
        cls.system_model_path = None

    def test_version(self):
        version = self.system_model.domain_version
        self.assertIsNotNone(version)

    @unittest.skip("temporarily skipping test")
    def test_me(self):
        threats = self.system_model.threats
        breakpoint()

    @unittest.skip("temporarily skipping test")
    def test_me_asset(self):
        threats = self.system_model.threats
        for thr in threats:
            a_uri = thr.threatens
            print("asset?", self.system_model.get_entity(a_uri))
        breakpoint()


    #@unittest.skip("temporarily skipping test")
    def test_asset(self):
        for asset in self.system_model.assets:
            print(asset.description)
            print()

    #@unittest.skip("temporarily skipping test")
    def test_control_set(self):
        for control_set in self.system_model.control_sets:
            print(control_set.description)
            print()

    #@unittest.skip("temporarily skipping test")
    def test_misbehaviour_set(self):
        for misbehaviour_set in self.system_model.misbehaviour_sets:
            print(misbehaviour_set.description)
            print()

    #@unittest.skip("temporarily skipping test")
    def test_twas(self):
        for twas in self.system_model.trustworthiness_attribute_sets:
            print(twas.description)
            print()

    #@unittest.skip("temporarily skipping test")
    def test_threat(self):
        for threat in self.system_model.threats:
            print(threat)
            print()

    #@unittest.skip("temporarily skipping test")
    def test_control_strategy(self):
        for control_strategy in self.system_model.control_strategies:
            print(control_strategy.description)
            print()

    #@unittest.skip("temporarily skipping test")
    def test_relation(self):
        for relation in self.system_model.relations:
            print(relation.description)
            print()

if __name__ == "__main__":
    unittest.main()
