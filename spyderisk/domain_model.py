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

import zipfile
import logging
from functools import cache, cached_property

from rdflib import ConjunctiveGraph, Literal, URIRef

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

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
    "is_external_cause": URIRef(GRAPH['core'] + "#isExternalCause"),
    "is_initial_cause": URIRef(GRAPH['core'] + "#isInitialCause"),
    "is_normal_op": URIRef(GRAPH['core'] + "#isNormalOp"),
    "is_normal_op_effect": URIRef(GRAPH['core'] + "#isNormalOpEffect"),
    "is_proposed": URIRef(GRAPH['core'] + "#isProposed"),
    "is_root_cause": URIRef(GRAPH['core'] + "#isRootCause"),
    "is_visible": URIRef(GRAPH['core'] + "#isVisible"),
    "located_at": URIRef(GRAPH['core'] + "#locatedAt"),
    "meta_located_at": URIRef(GRAPH['core'] + "#metaLocatedAt"),
    "mitigates": URIRef(GRAPH['core'] + "#mitigates"),
    "parent": URIRef(GRAPH['core'] + "#parent"),
}

TYPE = {
    "asset": URIRef("http://www.w3.org/2002/07/owl#Class"),
    "control_set": URIRef(GRAPH['core'] + "#ControlSet"),
    "control_strategy": URIRef(GRAPH['core'] + "#ControlStrategy"),
    "misbehaviour_set": URIRef(GRAPH['core'] + "#MisbehaviourSet"),
    "threat": URIRef(GRAPH['core'] + "#Threat"),
    "trustworthiness_attribute_set": URIRef(GRAPH['core'] + "#TrustworthinessAttributeSet"),
    "twaa_default_setting": URIRef(GRAPH['core'] + "#TWAADefaultSetting"),
}

class DomainModel(ConjunctiveGraph):
    def __init__(self, nq_filename):
        super().__init__()
        if nq_filename.endswith(".zip"):
            with zipfile.ZipFile(nq_filename, "r") as archive:
                for file in archive.namelist():
                    if file.endswith(".nq"):
                        logging.info(f"Loading {file} from {nq_filename}")
                        with archive.open(file) as f:
                            self.parse(f, format="nquads")
                        break
        else:
            self.parse(nq_filename, format="nquads")

    @cache
    def asset(self, uriref):
        return Asset(uriref, self)

    @cache
    def threat(self, uriref):
        return Threat(uriref, self)

    @cache
    def trustworthiness_attribute(self, uriref):
        return TrustworthinessAttribute(uriref, self)
    
    @property
    def assets(self):
        return [self.asset(uriref) for uriref in self.subjects(PREDICATE['type'], TYPE['asset'])]

    @property
    def threats(self):
        return [self.threat(uriref) for uriref in self.subjects(PREDICATE['type'], TYPE['threat'])]

    @property
    def trustworthiness_attributes(self):
        return [self.trustworthiness_attribute(uriref) for uriref in self.subjects(PREDICATE['type'], TYPE['trustworthiness_attribute_set'])]

class Entity():
    """Superclass of Threat, Misbehaviour, Trustworthiness Attribute, Control Strategy, etc."""
    def __init__(self, uriref, domain_model):
        self.uriref = uriref
        self.domain_model = domain_model

class Asset(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __lt__(self, other):
        return self.label < other.label

    @property
    def label(self):
        label = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['label'])
        if label is None:
            label = self.uriref.split("/")[-1]
        return label
    
    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])
    
    @property
    def is_assertable(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_assertable'])

    @property
    def is_visible(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])

    @property
    def parents(self):
        return [self.domain_model.asset(asset_uriref) for asset_uriref in self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['sub_class_of'])]

    @property
    def trustworthiness_attributes(self):
        twaads_urirefs = self.domain_model.subjects(predicate=PREDICATE['meta_located_at'], object=self.uriref)
        twa_urirefs = []
        for twaads in twaads_urirefs:
            twa_urirefs += self.domain_model.objects(subject=twaads, predicate=PREDICATE['has_twa'])
        return [self.domain_model.trustworthiness_attribute(uriref) for uriref in twa_urirefs]

class Threat(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __lt__(self, other):
        return self.label < other.label

    @property
    def label(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['label'])

    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])

    @property
    def short_description(self):
        """Return the first part of the threat description (up to the colon)"""
        comment = self.comment.split(':', 1)[0].strip()
        return comment

    @property
    def long_description(self):
        """Return the longer description of a threat (after the colon)"""
        comment = self.comment.split(':', 1)[-1].strip()
        return comment[0].upper() + comment[1:]

class TrustworthinessAttribute(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    @property
    def label(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['label'])
    
    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])

    @property
    def is_visible(self):
        b = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])
        return b

if __name__ == "__main__":
    # This is test code really, but it's useful to have it here while developing.
    # Download a domain model zip from e.g. https://github.com/Spyderisk/domain-network/packages/1826148
    dm = DomainModel("domain-network-6a5-1-1.zip")

    for threat in sorted(dm.threats):
        print(threat.short_description)
        print("  ", threat.long_description)
        print()

    for asset in sorted(dm.assets):
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