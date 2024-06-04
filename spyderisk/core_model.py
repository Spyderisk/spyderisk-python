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

from rdflib import Namespace, RDF, RDFS, OWL

GRAPH = {
    "core": Namespace("http://it-innovation.soton.ac.uk/ontologies/trustworthiness/core#"),
    "domain": Namespace("http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#"),
    "system": Namespace("http://it-innovation.soton.ac.uk/ontologies/trustworthiness/system#")
}

PREDICATE = {
    "type": RDF.type,
    "comment": RDFS.comment,
    "label": RDFS.label,
    "sub_class_of": RDFS.subClassOf,

    "affected_by": GRAPH['core'].affectedBy,
    "affects": GRAPH['core'].affects,
    "applies_to": GRAPH['core'].appliesTo,
    "blocks": GRAPH['core'].blocks,
    "causes_direct_misbehaviour": GRAPH['core'].causesDirectMisbehaviour,
    "causes_indirect_misbehaviour": GRAPH['core'].causesIndirectMisbehaviour,
    "causes_misbehaviour": GRAPH['core'].causesMisbehaviour,
    "causes_threat": GRAPH['core'].causesThreat,
    "has_asserted_level": GRAPH['core'].hasAssertedLevel,
    "has_asset": GRAPH['core'].hasAsset,
    "has_blocking_effect": GRAPH['core'].hasBlockingEffect,
    "has_control": GRAPH['core'].hasControl,
    "has_control_set": GRAPH['core'].hasControlSet,
    "has_coverage_level": GRAPH['core'].hasCoverageLevel,
    "has_entry_point": GRAPH['core'].hasEntryPoint,
    "has_id": GRAPH['core'].hasID,
    "has_impact_level": GRAPH['core'].hasImpactLevel,
    "has_inferred_level": GRAPH['core'].hasInferredLevel,
    "has_mandatory_control_set": GRAPH['core'].hasMandatoryCS,
    "has_misbehaviour": GRAPH['core'].hasMisbehaviour,
    "has_node": GRAPH['core'].hasNode,
    "has_prior": GRAPH['core'].hasPrior,
    "has_risk": GRAPH['core'].hasRisk,
    "has_secondary_effect_condition": GRAPH['core'].hasSecondaryEffectCondition,
    "has_twa": GRAPH['core'].hasTrustworthinessAttribute,
    "is_assertable": GRAPH['core'].isAssertable,
    "is_current_risk": GRAPH['core'].isCurrentRisk,
    "is_external_cause": GRAPH['core'].isExternalCause,
    "is_future_risk": GRAPH['core'].isFutureRisk,
    "is_initial_cause": GRAPH['core'].isInitialCause,
    "is_normal_op": GRAPH['core'].isNormalOp,
    "is_normal_op_effect": GRAPH['core'].isNormalOpEffect,
    "is_proposed": GRAPH['core'].isProposed,
    "is_root_cause": GRAPH['core'].isRootCause,
    "is_visible": GRAPH['core'].isVisible,
    "is_work_in_progress": GRAPH['core'].isWorkInProgress,
    "level_value": GRAPH['core'].levelValue,
    "located_at": GRAPH['core'].locatedAt,
    "meta_located_at": GRAPH['core'].metaLocatedAt,
    "mitigates": GRAPH['core'].mitigates,
    "parent": GRAPH['core'].parent,
    "population": GRAPH['core'].population,
    "triggers": GRAPH['core'].triggers,
}

OBJECT = {
    "asset": OWL.Class,
    "control_set": GRAPH['core'].ControlSet,
    "control_strategy": GRAPH['core'].ControlStrategy,
    "misbehaviour_set": GRAPH['core'].MisbehaviourSet,
    "threat": GRAPH['core'].Threat,
    "trustworthiness_attribute_set": GRAPH['core'].TrustworthinessAttributeSet,
    "trustworthiness_level": GRAPH['core'].TrustworthinessLevel,
    "twaa_default_setting": GRAPH['core'].TWAADefaultSetting,
}
