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


class BaseEntity():
    """
    Superclass of Entity.

    Attributes:
        uriref (str): The unique reference URI for the entity.
        domain_model (object): The domain model associated with the entity.
    """
    def __init__(self, uriref, domain_model):
        self.uriref = uriref
        self.domain_model = domain_model

    def __str__(self):
        return f"Domain base entity: ({self.uriref})"


class Entity(BaseEntity):
    """
    Superclass of Threat, Misbehaviour, Trustworthiness Attribute, Control Strategy, etc.

    Attributes:
        uriref (str): The unique reference URI for the entity.
        domain_model (object): The domain model associated with the entity.
    """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return f"Domain entity: {self.label} ({self.uriref})"

    @property
    def label(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['label'])

    @property
    def comment(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])


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
        return "Domain Control: {} ({})".format(self.label, str(self.uriref))

    @property
    def is_visible(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])

    @property
    def unit_cost(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['unit_cost'])

    @property
    def min(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_min'])

    @property
    def max(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_max'])

    @property
    def located_at(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['located_at'])

    @property
    def performance_impact(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['performance_impact'])


class ControlStrategy(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain ControlStrategy: {} ({})".format(self.label, str(self.uriref))

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

    @property
    def blocks(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['blocks'])

    @property
    def min(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_min'])

    @property
    def max(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_max'])

    @property
    def mandatory_cs(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_mandatory_control_set'])


class Relation(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain Relation: {} ({})".format(self.label, str(self.uriref))

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
        return "Domain Misbehaviour: {} ({})".format(self.label, str(self.uriref))

    @property
    def is_visible(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])

    @property
    def min(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_min'])

    @property
    def max(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_max'])

    @property
    def located_at(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['located_at'])


class Threat(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __lt__(self, other):
        return self.label < other.label

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

    @property
    def category(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_category'])

    @property
    def frequency(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_frequency'])

    @property
    def current_risk(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_current_risk'])

    @property
    def future_risk(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_future_risk'])

    @property
    def secondary_threat(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_secondary_threat'])

    @property
    def normal_op(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_normal_op'])

    @property
    def min(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_min'])

    @property
    def max(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_max'])

    # TODO it should return a list?
    @property
    def causes_misbehaviour(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['causes_misbehaviour'])

    # TODO it should return a list?
    @property
    def entry_point(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_entry_point'])

    @property
    def applies_to(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['applies_to'])

    @property
    def threatens(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['threatens'])


class TrustworthinessAttribute(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain Trustworthiness Attribute: {} ({})".format(self.label, str(self.uriref))

    @property
    def is_visible(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])

    @property
    def min_of(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['min_of'])

    @property
    def meta_located_at(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['meta_located_at'])


class TrustworthinessAttributeSet(BaseEntity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain Trustworthiness Attribute Set: ({})".format(str(self.uriref))

    #TODO not sure it has this property?
    @property
    def is_visible(self):
        b = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])
        return b

    @property
    def located_at(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['located_at'])

    @property
    def twa(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_twa'])


class CASetting(BaseEntity):
    """ Represents a domain model CASetting """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain CASetting: {} ({})".format(self.label, str(self.uriref))

    @property
    def has_control(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_control'])

    @property
    def meta_located_at(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['meta_located_at'])

    @property
    def is_assertable(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_assertable'])

    @property
    def has_level(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_level'])

    @property
    def independent_levels(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['independent_levels'])


class ComplianceSet(Entity):
    """ Represents a domain model ComplianceSet """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain ComplianceSet: {} ({})".format(self.label, str(self.uriref))

    @property
    def requires_treatment_of(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['requires_treatment_of'])


class ConstructionPattern(Entity):
    """ Represents a domain model ConstructionPattern """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain ConstructionPattern: {} ({})".format(self.label, str(self.uriref))

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


class ControlSet(BaseEntity):
    """ Represents a domain model ControlSet """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain ControlSet: ({})".format(str(self.uriref))

    @property
    def has_control(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_control'])

    @property
    def located_at(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['located_at'])


class DistinctNodeGroup(BaseEntity):
    """ Represents a domain model DistinctNodeGroup """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain DistinctNodeGroup: ({})".format(str(self.uriref))

    @property
    def has_node(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_node'])


class InferredLink(Entity):
    """ Represents a domain model InferredLink """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain InferredLink: {} ({})".format(self.label, str(self.uriref))

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


class InferredNodeSetting(BaseEntity):
    """ Represents a domain model InferredNodeSetting """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain InferredNodeSetting: ({})".format(str(self.uriref))

    @property
    def has_node(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_node'])

    @property
    def displayed_at_node(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['displayed_at_node'])

    @property
    def includes_node_in_uri(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['includes_node_in_uri'])


class MADefaultSetting(BaseEntity):
    """ Represents a domain model MADefaultSetting """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain MADefaultSetting: ({})".format(str(self.uriref))

    @property
    def located_at(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['located_at'])

    @property
    def has_misbehaviour(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_misbehaviour'])

    @property
    def has_level(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_level'])


class MatchingPattern(Entity):
    """ Represents a domain model MatchingPattern """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain MatchingPattern: {} ({})".format(self.label, str(self.uriref))

    @property
    def root_pattern(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_root_pattern'])


class MisbehaviourSet(BaseEntity):
    """ Represents a domain model MisbehaviourSet """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain MisbehaviourSet: ({})".format(str(self.uriref))

    @property
    def has_misbehaviour(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_misbehaviour'])

    @property
    def located_at(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['located_at'])


class Node(BaseEntity):
    """ Represents a domain model Node """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain Node: ({})".format(str(self.uriref))

    @property
    def meta_asset(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['meta_has_asset'])

    @property
    def role(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_role'])


class Role(Entity):
    """ Represents a domain model Role """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain Role: {} ({})".format(self.label, str(self.uriref))

    @property
    def meta_located_at(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['meta_located_at'])


class RoleLink(BaseEntity):
    """ Represents a domain model RoleLink """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain RoleLink: ({})".format(str(self.uriref))

    @property
    def link_type(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['link_type'])

    @property
    def links_from(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['links_from'])

    @property
    def links_to(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['links_to'])


class RootPattern(BaseEntity):
    """ Represents a domain model MatchingPattern """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain RootPattern: ({})".format(str(self.uriref))

    @property
    def key_nodes(self):
        return [node for node in self.domain_model.objects(self.uriref, PREDICATE['has_key_node'])]

    @property
    def links(self):
        return [link for link in self.domain_model.objects(self.uriref, PREDICATE['has_link'])]


class ThreatCategory(Entity):
    """ Represents a domain model ThreatCategory """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain ThreatCategory: {} ({})".format(self.label, str(self.uriref))


class TrustworthinessImpactSet(BaseEntity):
    """ Represents a domain model TrustworthinessImpactSet """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain TrustworthinessImpactSet: ({})".format(str(self.uriref))

    @property
    def affected_by(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['affected_by'])

    @property
    def affects(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['affects'])


class EntityLevel(Entity):
    """ Represents a domain model PopulationLevel """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain EntityLevel: {} ({})".format(self.label, str(self.uriref))

    @property
    def level_value(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['level_value'])


class TrustworthinessLevel(EntityLevel):
    """ Represents a domain model TrustworthinessLevel """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain TrustworthinessLevel: {} ({})".format(self.label, str(self.uriref))


class PopulationLevel(EntityLevel):
    """ Represents a domain model PopulationLevel """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain PopulationLevel: {} ({})".format(self.label, str(self.uriref))


class RiskLevel(EntityLevel):
    """ Represents a domain model RiskLevel """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain RiskLevel: {} ({})".format(self.label, str(self.uriref))


class ImpactLevel(EntityLevel):
    """ Represents a domain model ImpactLevel """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain ImpactLevel: {} ({})".format(self.label, str(self.uriref))


class Likelihood(EntityLevel):
    """ Represents a domain model Likelihood """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain Likelihood: {} ({})".format(self.label, str(self.uriref))

