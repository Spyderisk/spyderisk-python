#!/usr/bin/python3.9

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import system_model as sm

system_model = sm.SystemModel("steel.nq.gz", "domain-network-6a5-1-1.zip")

for threat in system_model.threats:
    print(threat)
    print()

for asset in system_model.assets:
    print(asset.description)
    print()

for control_strategy in system_model.control_strategies:
    print(control_strategy)
    print()

for twas in system_model.trustworthiness_attribute_sets:
    print(twas.description)
    print()
