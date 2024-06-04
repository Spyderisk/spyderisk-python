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

from rdflib import URIRef

GRAPH = {
    "core": URIRef("http://it-innovation.soton.ac.uk/ontologies/trustworthiness/core"),
    "domain": URIRef("http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain"),
    "system": URIRef("http://it-innovation.soton.ac.uk/ontologies/trustworthiness/system")
}

PREDICATE = {
    "type": URIRef("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
    "comment": URIRef("http://www.w3.org/2000/01/rdf-schema#comment"),
    "label": URIRef("http://www.w3.org/2000/01/rdf-schema#label"),
    "sub_class_of": URIRef("http://www.w3.org/2000/01/rdf-schema#subClassOf"),

    "affected_by": URIRef(GRAPH['core'] + "#affectedBy"),
    "affects": URIRef(GRAPH['core'] + "#affects"),
    "applies_to": URIRef(GRAPH['core'] + "#appliesTo"),
    "blocks": URIRef(GRAPH['core'] + "#blocks"),
    "causes_direct_misbehaviour": URIRef(GRAPH['core'] + "#causesDirectMisbehaviour"),
    "causes_indirect_misbehaviour": URIRef(GRAPH['core'] + "#causesIndirectMisbehaviour"),
    "causes_misbehaviour": URIRef(GRAPH['core'] + "#causesMisbehaviour"),
    "causes_threat": URIRef(GRAPH['core'] + "#causesThreat"),
    "has_asserted_level": URIRef(GRAPH['core'] + "#hasAssertedLevel"),
    "has_asset": URIRef(GRAPH['core'] + "#hasAsset"),
    "has_blocking_effect": URIRef(GRAPH['core'] + "#hasBlockingEffect"),
    "has_control": URIRef(GRAPH['core'] + "#hasControl"),
    "has_control_set": URIRef(GRAPH['core'] + "#hasControlSet"),
    "has_entry_point": URIRef(GRAPH['core'] + "#hasEntryPoint"),
    "has_id": URIRef(GRAPH['core'] + "#hasID"),
    "has_impact_level": URIRef(GRAPH['core'] + "#hasImpactLevel"),
    "has_inferred_level": URIRef(GRAPH['core'] + "#hasInferredLevel"),
    "has_mandatory_control_set": URIRef(GRAPH['core'] + "#hasMandatoryCS"),
    "has_misbehaviour": URIRef(GRAPH['core'] + "#hasMisbehaviour"),
    "has_node": URIRef(GRAPH['core'] + "#hasNode"),
    "has_prior": URIRef(GRAPH['core'] + "#hasPrior"),
    "has_risk": URIRef(GRAPH['core'] + "#hasRisk"),
    "has_secondary_effect_condition": URIRef(GRAPH['core'] + "#hasSecondaryEffectCondition"),
    "has_twa": URIRef(GRAPH['core'] + "#hasTrustworthinessAttribute"),
    "is_assertable": URIRef(GRAPH['core'] + "#isAssertable"),
    "is_current_risk": URIRef(GRAPH['core'] + "#isCurrentRisk"),
    "is_external_cause": URIRef(GRAPH['core'] + "#isExternalCause"),
    "is_future_risk": URIRef(GRAPH['core'] + "#isFutureRisk"),
    "is_initial_cause": URIRef(GRAPH['core'] + "#isInitialCause"),
    "is_normal_op": URIRef(GRAPH['core'] + "#isNormalOp"),
    "is_normal_op_effect": URIRef(GRAPH['core'] + "#isNormalOpEffect"),
    "is_proposed": URIRef(GRAPH['core'] + "#isProposed"),
    "is_root_cause": URIRef(GRAPH['core'] + "#isRootCause"),
    "is_visible": URIRef(GRAPH['core'] + "#isVisible"),
    "level_value": URIRef(GRAPH['core'] + "#levelValue"),
    "located_at": URIRef(GRAPH['core'] + "#locatedAt"),
    "meta_located_at": URIRef(GRAPH['core'] + "#metaLocatedAt"),
    "mitigates": URIRef(GRAPH['core'] + "#mitigates"),
    "parent": URIRef(GRAPH['core'] + "#parent"),
}

OBJECT = {
    "asset": URIRef("http://www.w3.org/2002/07/owl#Class"),
    "control_set": URIRef(GRAPH['core'] + "#ControlSet"),
    "control_strategy": URIRef(GRAPH['core'] + "#ControlStrategy"),
    "misbehaviour_set": URIRef(GRAPH['core'] + "#MisbehaviourSet"),
    "threat": URIRef(GRAPH['core'] + "#Threat"),
    "trustworthiness_attribute_set": URIRef(GRAPH['core'] + "#TrustworthinessAttributeSet"),
    "trustworthiness_level": URIRef(GRAPH['core'] + "#TrustworthinessLevel"),
    "twaa_default_setting": URIRef(GRAPH['core'] + "#TWAADefaultSetting"),
}
