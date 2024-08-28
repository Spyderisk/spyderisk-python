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
from collections import defaultdict
from rdflib.term import Literal
from spyderisk.risk_vector import RiskVector


# @unittest.skip("temporarily skipping domain model test")
class TestRiskVector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rdf_levels = defaultdict(int, {
            Literal('Very Low'): 0,
            Literal('Low'): 1,
            Literal('Medium'): 2
            })
        cls.risk_levels = defaultdict(int, {
            Literal('Very Low'): 800,
            Literal('Low'): 50,
            Literal('Medium'): 20
            })

    def test_risk_vector_str(self):
        try:
            rv = RiskVector(self.risk_levels, self.rdf_levels)
        except ValueError:
            self.fail("RiskVector raised ValueError unexpectedly with matching keys.")

        expected_str = (
            "Medium: 20, "
            "Low: 50, "
            "Very Low: 800"
        )
        self.assertEqual(str(rv), expected_str)

    def test_risk_vector_comparison2(self):
        r_levels1 = defaultdict(int, {
            Literal('Very Low'): 800,
            Literal('Low'): 50,
            Literal('Medium'): 25,
            Literal('Very High'): 5
        })
        rdf_levels = defaultdict(int, {
            Literal('Very Low'): 0,
            Literal('Low'): 1,
            Literal('Medium'): 2,
            Literal('Very High'): 4
            })
        rv1 = RiskVector(r_levels1, rdf_levels)
        rv2 = RiskVector(self.risk_levels, self.rdf_levels)

        self.assertTrue(rv1 > rv2)
        self.assertFalse(rv2 > rv1)
        self.assertFalse(rv1 == rv2)
        self.assertTrue(rv2 < rv1)

    def test_risk_vector_comparison(self):
        r_levels1 = defaultdict(int, {
            Literal('Very Low'): 800,
            Literal('Low'): 50,
            Literal('Medium'): 25
        })
        rv1 = RiskVector(r_levels1, self.rdf_levels)
        rv2 = RiskVector(self.risk_levels, self.rdf_levels)

        self.assertTrue(rv1 > rv2)
        self.assertFalse(rv2 > rv1)
        self.assertFalse(rv1 == rv2)
        self.assertTrue(rv2 < rv1)

    def test_risk_vector_equality(self):
        r_levels1 = defaultdict(int, {
            Literal('Very Low'): 800,
            Literal('Low'): 50,
            Literal('Medium'): 20
        })
        rv1 = RiskVector(r_levels1, self.rdf_levels)
        rv2 = RiskVector(self.risk_levels, self.rdf_levels)

        self.assertEqual(rv1, rv2)

    def test_mismatched_keys(self):
        # Create risk_dict and risk_levels with mismatched keys
        r_levels1 = defaultdict(int, {
            Literal('Very Low'): 800,
            Literal('Low'): 50,
            Literal('Medium'): 25,
            Literal('Very High'): 5
        })
        rdf_levels = defaultdict(int, {
            Literal('Very Low'): 0,
            Literal('Low'): 1,
            Literal('Medium'): 2
            })

        # Check that initializing RiskVector with mismatched keys raises ValueError
        with self.assertRaises(ValueError) as context:
            rv = RiskVector(r_levels1, rdf_levels)
            self.assertIsNotNone(rv)

        self.assertEqual(str(context.exception), "Keys in risk_dict and risk_levels must match.")


if __name__ == "__main__":
    unittest.main()
