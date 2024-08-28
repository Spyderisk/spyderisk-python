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

# config/test_config.py

import os

# Base directory for the package
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# Path to the test data directory
TEST_DATA_DIR = os.path.join(BASE_DIR, 'tests', 'data')

TEST_DOMAIN_FILE = os.path.join(TEST_DATA_DIR, "domain-network-6a7-1-1-Beta-unfiltered.zip")
TEST_SYSTEM_FILE = os.path.join(TEST_DATA_DIR, "router_v1-b.nq.gz")
