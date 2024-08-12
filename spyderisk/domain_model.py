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

from rdflib import ConjunctiveGraph, Literal, URIRef, RDF, OWL

from .core_model import GRAPH, PREDICATE, OBJECT

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
    def control_strategy(self, uriref):
        return ControlStrategy(uriref, self)

    @cache
    def misbehaviour(self, uriref):
        return Misbehaviour(uriref, self)

    @cache
    def relation(self, uriref):
        return Relation(uriref, self)

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
        tmp_rui = None
        for s in self.subjects(RDF.type, OWL.Ontology):
            tmp_uri = s
            break
        return tmp_uri

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
    def control_strategies(self):
        return [self.control_strategy(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['control_strategy'])]

    @property
    def misbehaviours(self):
        return [self.misbehaviour(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['misbehaviour'])]

    @property
    def relations(self):
        return [Relation(uriref, self) for uriref in self.subjects(PREDICATE['type'], OBJECT['relation'])]

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

    def level_label(self, uriref):
        return self.value(subject=uriref, predicate=PREDICATE['label'])

    def level_comment(self, uriref):
        return self.value(subject=uriref, predicate=PREDICATE['comment'])

    def level_number_inverse(self, number):
        # TODO: capture the max TW/likelihood level when domain model is loaded
        return 5 - number

class Entity():
    """Superclass of Threat, Misbehaviour, Trustworthiness Attribute, Control Strategy, etc."""
    def __init__(self, uriref, domain_model):
        self.uriref = uriref
        self.domain_model = domain_model

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


class Control(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Control: {} ({})".format(self.label, str(self.uriref))

    @property
    def label(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['label'])

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
    def label(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['label'])

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
    def label(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['label'])

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
    def label(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['label'])

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

    def __str__(self):
        return "Trustworthiness Attribute: {} ({})".format(self.label, str(self.uriref))

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


class TrustworthinessAttributeSet(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Trustworthiness Attribute Set: {} ({})".format(self.label, str(self.uriref))

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


