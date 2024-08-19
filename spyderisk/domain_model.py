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
from functools import cache

from rdflib import ConjunctiveGraph, RDF, OWL

from .core_model import PREDICATE, OBJECT

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)


class DomainModel(ConjunctiveGraph):
    def __init__(self, domain_model_filename):
        super().__init__()

        logging.info(f"Loading domain model {domain_model_filename}")

        if domain_model_filename.endswith(".zip"):
            with zipfile.ZipFile(domain_model_filename, "r") as archive:
                for file in archive.namelist():
                    if file.endswith(".nq"):
                        with archive.open(file) as f:
                            self.parse(f, format="nquads")
                        break
        else:
            self.parse(domain_model_filename, format="nquads")

    @cache
    def asset(self, uriref):
        return Asset(uriref, self)

    @cache
    def control(self, uriref):
        return Control(uriref, self)

    @cache
    def construction_pattern(self, uriref):
        return ConstructionPattern(uriref, self)

    @cache
    def control_strategy(self, uriref):
        return ControlStrategy(uriref, self)

    @cache
    def matching_pattern(self, uriref):
        return MatchingPattern(uriref, self)

    @cache
    def misbehaviour(self, uriref):
        return Misbehaviour(uriref, self)

    @cache
    def relation(self, uriref):
        return Relation(uriref, self)

    @cache
    def root_pattern(self, uriref):
        return RootPattern(uriref, self)

    @cache
    def threat(self, uriref):
        return Threat(uriref, self)

    @cache
    def trustworthiness_attribute(self, uriref):
        return TrustworthinessAttribute(uriref, self)

    @cache
    def trustworthiness_attribute_set(self, uriref):
        return TrustworthinessAttributeSet(uriref, self)

    @property
    @cache
    def ontology_uri(self):
        return next(self.subjects(RDF.type, OWL.Ontology), None)

    @property
    @cache
    def version_info(self):
        return self.value(self.ontology_uri, PREDICATE['version_info'])

    @property
    def label(self):
        return self.value(self.ontology_uri, PREDICATE['label'])

    @property
    def comment(self):
        return self.value(self.ontology_uri, PREDICATE['comment'])

    def is_asset(self, uriref):
        return (uriref, PREDICATE['type'], OBJECT['asset']) in self

    @property
    def assets(self):
        return [self.asset(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['asset'])]

    @property
    def controls(self):
        return [self.control(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['control'])]

    @property
    def construction_patterns(self):
        return [self.construction_pattern(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['construction_pattern'])]

    @property
    def control_strategies(self):
        return [self.control_strategy(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['control_strategy'])]

    @property
    def matching_patterns(self):
        return [self.matching_pattern(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['matching_pattern'])]

    @property
    def misbehaviours(self):
        return [self.misbehaviour(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['misbehaviour'])]

    @property
    def relations(self):
        return [Relation(uriref, self) for uriref in self.subjects(PREDICATE['type'], OBJECT['relation'])]

    @property
    def root_patterns(self):
        return [RootPattern(uriref, self) for uriref in self.subjects(PREDICATE['type'], OBJECT['root_pattern'])]

    @property
    def threats(self):
        return [self.threat(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['threat'])]

    @property
    def trustworthiness_attributes_set(self):
        return [self.trustworthiness_attribute_set(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['trustworthiness_attribute_set'])]

    @property
    def trustworthiness_attributes(self):
        return [self.trustworthiness_attribute(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['trustworthiness_attribute'])]

    def level_value(self, uriref):
        return int(self.value(subject=uriref, predicate=PREDICATE['level_value']))

    def label_uri(self, uriref):
        return self.value(subject=uriref, predicate=PREDICATE['label'])

    def comment_uri(self, uriref):
        return self.value(subject=uriref, predicate=PREDICATE['comment'])

    def level_number_inverse(self, number):
        # TODO: capture the max TW/likelihood level when domain model is loaded
        return 5 - number

    def cost_level_range(self):
        return [uriref for uriref in self.subjects(PREDICATE['type'], OBJECT['cost_level'])]

    def impact_level_range(self):
        return [uriref for uriref in self.subjects(PREDICATE['type'], OBJECT['impact_level'])]

    def performance_impact_level_range(self):
        return [uriref for uriref in self.subjects(PREDICATE['type'], OBJECT['performance_impact_level'])]

    def population_level_range(self):
        return [uriref for uriref in self.subjects(PREDICATE['type'], OBJECT['population_level'])]

    def risk_level_range(self):
        return [uriref for uriref in self.subjects(PREDICATE['type'], OBJECT['risk_level'])]

    def tw_level_range(self):
        return [uriref for uriref in self.subjects(PREDICATE['type'], OBJECT['trustworthiness_level'])]


class Entity():
    """
    Superclass of Threat, Misbehaviour, Trustworthiness Attribute, Control Strategy, etc.

    Attributes:
        uriref (str): The unique reference URI for the entity.
        domain_model (object): The domain model associated with the entity.
    """
    def __init__(self, uriref, domain_model):
        self.uriref = uriref
        self.domain_model = domain_model

    def __str__(self):
        return f"Domain entity: {self.label} ({self.uriref})"

    @property
    def label(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['label'])


class Asset(Entity):
    """ Represents a domain model Asset """

    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __lt__(self, other):
        return self.label < other.label

    def __str__(self):
        return "Domain Asset: {} ({})".format(self.label, str(self.uriref))

    @property
    def label(self):
        label = super().label
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


class Control(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Control: {} ({})".format(self.label, str(self.uriref))

    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])

    @property
    def is_visible(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])


class ControlStrategy(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Control: {} ({})".format(self.label, str(self.uriref))

    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])

    def _effectiveness_uriref(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_blocking_effect'])

    @property
    def effectiveness_number(self):
        return self.domain_model.level_number(self._effectiveness_uriref())

    @property
    def effectiveness_label(self):
        return self.domain_model.level_label(self._effectiveness_uriref())

    @property
    def is_current_risk(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_current_risk']) and ("-Runtime" in str(self.uriref) or "-Implementation" in str(self.uriref))

    @property
    def is_future_risk(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_future_risk'])

    @property
    def maximum_likelihood_number(self):
        return self.domain_model.level_number_inverse(self.effectiveness_number)


class Relation(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Relation: {} ({})".format(self.label, str(self.uriref))

    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])

    @property
    def description(self):
        return "{}\n  Comment: {}\n  Range:\n    {}\n  Domain:\n    {}".format(
            self.label, self.comment,
            "\n    ".join([str(asset.label) for asset in self.range]),
            "\n    ".join([str(asset.label) for asset in self.domain])
        )

    @property
    def range(self):
        return [self.domain_model.asset(asset_uriref) for asset_uriref in self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['range'])]

    @property
    def domain(self):
        return [self.domain_model.asset(asset_uriref) for asset_uriref in self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['domain'])]


class Misbehaviour(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Misbehaviour: {} ({})".format(self.label, str(self.uriref))

    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])

    @property
    def is_visible(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])


class Threat(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __lt__(self, other):
        return self.label < other.label

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

    def __str__(self):
        return "Trustworthiness Attribute: {} ({})".format(self.label, str(self.uriref))

    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])

    @property
    def is_visible(self):
        b = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])
        return b


class TrustworthinessAttributeSet(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Trustworthiness Attribute Set: {} ({})".format(self.label, str(self.uriref))

    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])

    @property
    def is_visible(self):
        b = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])
        return b


class AssetGroup:
    pass


class CASetting:
	pass


class CardinalityConstraint:
	pass


class ComplianceSet:
	pass


class CompositeThing:
	pass


class ConstructionPattern(Entity):
    """ Represents a domain model ConstructionPattern """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "ConstructionPattern: {} ({})".format(self.label, str(self.uriref))

    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])

    @property
    def matching_pattern(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_matching_pattern'])

    @property
    def priority(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_priority'])

    @property
    def iterate(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['iterate'])

    @property
    def max_iterations(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['max_iterations'])

    @property
    def inferred_link(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_inferred_link'])


class ControlSet:
	pass


class DefaultSetting:
	pass


class DistinctNodeGroup:
	pass


class DomainPatternUISetting:
	pass


class ImpactLevel:
	pass


class InferredLink(Entity):
    """ Represents a domain model InferredLink """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "MatchingPattern: {} ({})".format(self.label, str(self.uriref))

    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])

    @property
    def matching_pattern(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_matching_pattern'])

    @property
    def priority(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_priority'])

    @property
    def iterate(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['iterate'])

    @property
    def max_iterations(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['max_iterations'])

    @property
    def inferred_link(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_inferred_link'])

    @property
    def inferred_node(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_inferred_node'])

    @property
    def inferred_node_setting(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_inferred_node_setting'])



class InferredNodeSetting:
	pass


class Level:
	pass


class Likelihood:
	pass


class Link:
	pass


class MADefaultSetting:
	pass


class MatchingPattern(Entity):
    """ Represents a domain model MatchingPattern """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "MatchingPattern: {} ({})".format(self.label, str(self.uriref))

    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])

    @property
    def root_pattern(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_root_pattern'])


class MetadataPair:
	pass


class MisbehaviourInhibitionSet:
	pass


class MisbehaviourSet:
	pass


class MitigationLevel:
	pass


class MitigationSet:
	pass


class Node:
	pass


class Pattern:
	pass


class PopulationLevel:
	pass


class RiskLevel:
	pass


class Role:
	pass


class RoleLink:
	pass


class RootPattern(Entity):
    """ Represents a domain model MatchingPattern """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "RootPattern: {} ({})".format(self.label, str(self.uriref))

    @property
    def key_nodes(self):
        return [node for node in self.domain_model.objects(self.uriref, PREDICATE['has_key_node'])]

    @property
    def links(self):
        return [link for link in self.domain_model.objects(self.uriref, PREDICATE['has_link'])]

class SetMember:
	pass


class Setting:
	pass


class TWAADefaultSetting:
	pass


class ThreatCategory:
	pass


class TripletMember:
	pass


class TrustworthinessImpactSet:
	pass


class TrustworthinessLevel:
	pass

