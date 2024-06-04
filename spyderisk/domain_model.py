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

from rdflib import ConjunctiveGraph, Literal, Namespace, RDF, RDFS, OWL

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

CORE   = Namespace("http://it-innovation.soton.ac.uk/ontologies/trustworthiness/core#")
DOMAIN = Namespace("http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#")
SYSTEM = Namespace("http://it-innovation.soton.ac.uk/ontologies/trustworthiness/system#")

TYPE         = RDF.type
COMMENT      = RDFS.comment
LABEL        = RDFS.label
CLASS        = OWL.Class
SUB_CLASS_OF = RDFS.subClassOf

AFFECTED_BY                    = CORE.affectedBy
AFFECTS                        = CORE.affects
APPLIES_TO                     = CORE.appliesTo
BLOCKS                         = CORE.blocks
ASSET                          = OWL.Class ## XXX surely incorrect
CAUSES_DIRECT_MISBEHAVIOUR     = CORE.causesDirectMisbehaviour
CAUSES_INDIRECT_MISBEHAVIOUR   = CORE.causesIndirectMisbehaviour
CAUSES_MISBEHAVIOUR            = CORE.causesMisbehaviour
CAUSES_THREAT                  = CORE.causesThreat
CONTROL_SET                    = CORE.ControlSet
CONTROL_STRATEGY               = CORE.ControlStrategy
HAS_ASSERTED_LEVEL             = CORE.hasAssertedLevel
HAS_ASSET                      = CORE.hasAsset
HAS_CONTROL                    = CORE.hasControl
HAS_CONTROL_SET                = CORE.hasControlSet
HAS_ENTRY_POINT                = CORE.hasEntryPoint
HAS_ID                         = CORE.hasID
HAS_IMPACT_LEVEL               = CORE.hasImpactLevel
HAS_INFERRED_LEVEL             = CORE.hasInferredLevel
HAS_MANDATORY_CONTROL_SET      = CORE.hasMandatoryCS
HAS_MISBEHAVIOUR               = CORE.hasMisbehaviour
HAS_NODE                       = CORE.hasNode
HAS_PRIOR                      = CORE.hasPrior
HAS_RISK                       = CORE.hasRisk
HAS_SECONDARY_EFFECT_CONDITION = CORE.hasSecondaryEffectCondition
HAS_TWA                        = CORE.hasTrustworthinessAttribute
IS_ASSERTABLE                  = CORE.isAssertable
IS_EXTERNAL_CAUSE              = CORE.isExternalCause
IS_INITIAL_CAUSE               = CORE.isInitialCause
IS_NORMAL_OP                   = CORE.isNormalOp
IS_NORMAL_OP_EFFECT            = CORE.isNormalOpEffect
IS_PROPOSED                    = CORE.isProposed
IS_ROOT_CAUSE                  = CORE.isRootCause
IS_VISIBLE                     = CORE.isVisible
LOCATED_AT                     = CORE.locatedAt
META_LOCATED_AT                = CORE.metaLocatedAt
MISBEHAVIOUR_SET               = CORE.MisbehaviourSet
MITIGATES                      = CORE.mitigates
PARENT                         = CORE.parent
THREAT                         = CORE.Threat
TRUSTWORTHINESS_ATTRIBUTE_SET  = CORE.TrustworthinessAttributeSet
TWAA_DEFAULT_SETTING           = CORE.TWAADefaultSetting

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
        return [self.asset(uriref) for uriref in self.subjects(TYPE, ASSET)]

    @property
    def threats(self):
        return [self.threat(uriref) for uriref in self.subjects(TYPE, THREAT)]

    @property
    def trustworthiness_attributes(self):
        return [self.trustworthiness_attribute(uriref) for uriref in self.subjects(TYPE, TRUSTWORTHINESS_ATTRIBUTE_SET)]

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
        label = self.domain_model.value(subject=self.uriref, predicate=LABEL)
        if label is None:
            label = self.uriref.split("/")[-1]
        return label
    
    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=COMMENT)
    
    @property
    def is_assertable(self):
        return self.domain_model.value(subject=self.uriref, predicate=IS_ASSERTABLE)

    @property
    def is_visible(self):
        return self.domain_model.value(subject=self.uriref, predicate=IS_VISIBLE)

    @property
    def parents(self):
        return [self.domain_model.asset(asset_uriref) for asset_uriref in self.domain_model.objects(subject=self.uriref, predicate=SUB_CLASS_OF)]

    @property
    def trustworthiness_attributes(self):
        twaads_urirefs = self.domain_model.subjects(predicate=META_LOCATED_AT, object=self.uriref)
        twa_urirefs = []
        for twaads in twaads_urirefs:
            twa_urirefs += self.domain_model.objects(subject=twaads, predicate=HAS_TWA)
        return [self.domain_model.trustworthiness_attribute(uriref) for uriref in twa_urirefs]

class Threat(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __lt__(self, other):
        return self.label < other.label

    @property
    def label(self):
        return self.domain_model.value(subject=self.uriref, predicate=LABEL)

    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=COMMENT)

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
        return self.domain_model.value(subject=self.uriref, predicate=LABEL)
    
    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=COMMENT)

    @property
    def is_visible(self):
        b = self.domain_model.value(subject=self.uriref, predicate=IS_VISIBLE)
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
