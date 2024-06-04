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

import gzip
import logging
import re
from functools import cache, cached_property
from itertools import chain

from rdflib import ConjunctiveGraph, Literal, URIRef

import domain_model
from core_model import GRAPH, PREDICATE, OBJECT

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

# TODO: remove these domain-model specific predicates
DEFAULT_TW = URIRef(GRAPH['domain'] + "#DefaultTW")
IN_SERVICE = URIRef(GRAPH['domain'] + "#InService")

class SystemModel(ConjunctiveGraph):
    def __init__(self, system_model_filename, domain_model_filename):
        super().__init__()

        logging.info(f"Loading system model {system_model_filename}")

        if system_model_filename.endswith(".gz"):
            with gzip.open(system_model_filename, "rb") as f:
                self.parse(f, format="nquads")
        else:
            self.parse(system_model_filename, format="nquads")

        if domain_model_filename:
            self.domain_model = domain_model.DomainModel(domain_model_filename)

        # TODO: check that the domain model matches the ysstem model

    def label(self, uriref):
        return self.value(subject=uriref, predicate=PREDICATE['label'])

    def get_entity(self, uriref):
        if (uriref, PREDICATE['type'], OBJECT['misbehaviour_set']) in self:
            return MisbehaviourSet(uriref, self)
        elif (uriref, PREDICATE['type'], OBJECT['threat']) in self:
            return Threat(uriref, self)
        elif (uriref, PREDICATE['type'], OBJECT['control_strategy']) in self:
            return ControlStrategy(uriref, self)
        elif (uriref, PREDICATE['type'], OBJECT['trustworthiness_attribute_set']) in self:
            return TrustworthinessAttributeSet(uriref, self)
        elif (uriref, PREDICATE['type'], OBJECT['asset']) in self:
            return Asset(uriref, self)
        else:
            raise KeyError(uriref)

    @cache
    def asset(self, uriref):
        return Asset(uriref, self)

    @cache
    def control_strategy(self, uriref):
        return ControlStrategy(uriref, self)

    @cache
    def misbehaviour(self, uriref):
        return MisbehaviourSet(uriref, self)

    @cache
    def threat(self, uriref):
        return Threat(uriref, self)

    @cache
    def trustworthiness_attribute_set(self, uriref):
        return TrustworthinessAttributeSet(uriref, self)

    @property
    def assets(self):
        asset_urirefs = []
        for asset_class in [asset.uriref for asset in self.domain_model.assets]:
            asset_urirefs += self.subjects(PREDICATE['type'], asset_class)
        return [self.asset(uriref) for uriref in asset_urirefs]

    @property
    def control_strategies(self):
        return [self.control_strategy(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['control_strategy'])]

    @property
    def misbehaviours(self):
        return [self.misbehaviour(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['misbehaviour_set'])]

    @property
    def threats(self):
        return [self.threat(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['threat'])]

    @property
    def trustworthiness_attribute_sets(self):
        return [self.trustworthiness_attribute_set(uriref) for uriref in self.subjects(PREDICATE['type'], OBJECT['trustworthiness_attribute_set'])]

class Entity():
    """Superclass of Threat, Misbehaviour, Trustwworthiness Attribute or Control Strategy."""
    def __init__(self, uriref, system_model):
        self.uriref = uriref
        self.system_model = system_model

class Asset(Entity):
    """Represents an Asset."""
    def __init__(self, uriref, graph):
        super().__init__(uriref, graph)

    def __str__(self):
        return "Asset: {} ({})".format(self.label, str(self.uriref))

    @property
    def label(self):
        return self.system_model.label(self.uriref)

    @property
    def comment(self):
        return self.type.comment
    
    @property
    def description(self):
        return "{}\n  Class:\n    {}\n  Trustworthiness Attributes:\n    {}".format(
            str(self), str(self.type), "\n    ".join([twas.comment for twas in self.trustworthiness_attribute_sets]))

    @property
    def type(self):
        return self.system_model.domain_model.asset(self.system_model.value(self.uriref, PREDICATE['type']))

    @property
    def trustworthiness_attribute_sets(self):
        return [twas for twas in self.system_model.trustworthiness_attribute_sets if twas.asset == self]

class ControlStrategy(Entity):
    """Represents a Control Strategy."""
    def __init__(self, uriref, graph):
        super().__init__(uriref, graph)

    def __str__(self):
        return "Control Strategy: {} ({})".format(self.label, str(self.uriref))

    @property
    def label(self):
        return self.parent.label

    @property
    def comment(self):
        asset_labels = self.control_set_asset_labels()  # get unique set of asset labels the CSG involves (whether proposed or not)
        asset_labels = [f'"{label}"' for label in asset_labels]
        asset_labels.sort()
        comment = "{} ({})".format(un_camel_case(self.label), ", ".join(asset_labels))
        return comment

    @property
    def parent(self):
        return self.system_model.domain_model.control_strategy(self.system_model.value(self.uriref, PREDICATE['parent']))

    @property
    def effectiveness_number(self):
        return self.parent.effectiveness_number

    @property
    def effectiveness_label(self):
        return self.parent.effectiveness_label

    @property
    def maximum_likelihood_number(self):
        return self.parent.maximum_likelihood_number

    @property
    def is_current_risk(self):
        return self.parent.is_current_risk

    @property
    def is_future_risk(self):
        return self.parent.is_future_risk

    @cached_property
    def blocked_threats(self):
        return [self.system_model.threat(threat_uriref) for threat_uriref in self.system_model.value(self.uriref, PREDICATE['blocks'])]

    # TODO: add ControlSet class and use that
    @property
    def is_active(self):
        # TODO: do we need to check sufficient CS?
        control_sets = self.system_model.objects(self.uriref, PREDICATE['has_mandatory_control_set'])
        all_proposed = True
        for cs in control_sets:
            if (cs, PREDICATE['is_proposed'], Literal(True)) not in self.system_model:
                all_proposed = False
        return all_proposed

    def control_set_urirefs(self):
        return self.system_model.objects(self.uriref, PREDICATE['has_mandatory_control_set'])

    def control_set_asset_urirefs(self):
        cs_urirefs = self.control_set_urirefs()
        asset_urirefs = []
        for cs_uriref in cs_urirefs:
            asset_urirefs += self.system_model.objects(cs_uriref, PREDICATE['located_at'])
        return asset_urirefs

    def control_set_asset_labels(self):
        return sorted([self.system_model.label(asset_uriref) for asset_uriref in self.control_set_asset_urirefs()])

class TrustworthinessAttributeSet(Entity):
    """Represents a Trustworthiness Attribute Set."""
    def __init__(self, uriref, graph):
        super().__init__(uriref, graph)

    def __str__(self):
        return "Trustworthiness Attribute Set: {}\n  Label: {}\n  Description: {}\n".format(
            str(self.uriref), self.label, self.description)

    @property
    def twa(self):
        return self.system_model.domain_model.trustworthiness_attribute(self.system_model.value(self.uriref, PREDICATE['has_twa']))

    @property
    def asset(self):
        return self.system_model.asset(self.system_model.value(self.uriref, PREDICATE['located_at']))

    def _asserted_tw_level_uri(self):
        return self.system_model.value(self.uriref, PREDICATE['has_asserted_level'])

    def _inferred_tw_level_uri(self):
        return self.system_model.value(self.uriref, PREDICATE['has_inferred_level'])

    @property
    def label(self):
        """Return a TWAS label"""
        return self.twa.label

    @property
    def comment(self):
        """Return a short description of a TWAS"""
        tw_level = self.inferred_level_label
        twa = self.label
        asset = self.asset.label
        return '{} of {} is {}'.format(un_camel_case(twa), asset, tw_level)

    @property
    def description(self):
        """Return a long description of a TWAS"""
        tw_level = self.inferred_level_label
        twa = self.comment
        asset = self.asset.label
        return '{} of {} is {}'.format(un_camel_case(twa), asset, tw_level)

    @property
    def inferred_level_number(self):
        return self.system_model.domain_model.level_number(self._inferred_tw_level_uri())

    @property
    def inferred_level_label(self):
        return self.system_model.domain_model.level_label(self._inferred_tw_level_uri())

    @property
    def asserted_level_number(self):
        return self.system_model.domain_model.level_number(self._asserted_tw_level_uri())

    @property
    def inferred_level_label(self):
        return self.system_model.domain_model.level_label(self._inferred_tw_level_uri())

    @property
    def is_external_cause(self):
        return (self.uriref, PREDICATE['is_external_cause'], Literal(True)) in self.system_model

    # TODO: this uses a domain-specific predicate. Don't incorporate it into a general class
    @property
    def is_default_tw(self):
        """Return Boolean describing whether this is a TWAS which has the Default TW attribute"""
        return (self.uriref, PREDICATE['has_twa'], DEFAULT_TW) in self.system_model

class Threat(Entity):
    """Represents a Threat."""
    def __init__(self, uri_ref, graph):
        super().__init__(uri_ref, graph)

    def __str__(self):
        return "Threat: {} ({})".format(self.comment, str(self.uriref))

    def _likelihood_uri(self):
        return self.system_model.value(self.uriref, PREDICATE['has_prior'])

    def _risk_uri(self):
        return self.system_model.value(self.uriref, PREDICATE['has_risk'])

    def _get_threat_comment(self):
        """Return the first part of the threat description (up to the colon)"""
        comment = self.system_model.value(subject=self.uriref, predicate=PREDICATE['comment'])
        quote_counter = 0
        char_index = 0
        # need to deal with the case where there is a colon in a quoted asset label
        while (comment[char_index] != ":" or quote_counter % 2 != 0):
            if comment[char_index] == '"':
                quote_counter += 1
            char_index += 1
        comment = comment[0:char_index]
        return comment

    @property
    def comment(self):
        """Return the first part of the threat description (up to the colon) and add in the likelihood if so configured"""
        comment = self._get_threat_comment()
        # TODO: remove next line when we're sure we don't need it
        comment = comment.replace('re-disabled at "Router"', 're-enabled at "Router"')  # hack that is necessary to correct an error in v6a3-1-4 for the overview paper system model
        return comment

    @property
    def description(self):
        """Return the longer description of a threat (after the colon)"""
        short_comment = self._get_threat_comment()
        comment = self.system_model.value(subject=self.uriref, predicate=PREDICATE['comment'])
        comment = comment[len(short_comment) + 1:]  # remove the short comment from the start
        comment = comment.strip()  # there is conventionally a space after the colon
        return comment[0].upper() + comment[1:]  # uppercase the first word

    @property
    def likelihood_level_number(self):
        if self._likelihood_uri() is None:
            return -1
        return self.system_model.domain_model.level_number(self._likelihood_uri())

    @property
    def likelihood_level_label(self):
        if self._likelihood_uri() is None:
            return "N/A"
        return self.system_model.domain_model.level_label(self._likelihood_uri())

    @property
    def risk_level_number(self):
        if self._risk_uri() is None:
            return -1
        return self.system_model.domain_model.level_number(self._risk_uri())

    @property
    def risk_level_label(self):
        if self._risk_uri() is None:
            return "N/A"
        return self.system_model.domain_model.level_label(self._risk_uri())

    @property
    def is_normal_op(self):
        return (self.uriref, PREDICATE['is_normal_op'], Literal(True)) in self.system_model

    @property
    def is_root_cause(self):
        return (self.uriref, PREDICATE['is_root_cause'], Literal(True)) in self.system_model

    @property
    def is_secondary_threat(self):
        return (self.uriref, PREDICATE['has_secondary_effect_condition'], None) in self.system_model

    @property
    def is_primary_threat(self):
        return (self.uriref, PREDICATE['has_entry_point'], None) in self.system_model

    @property
    def is_initial_cause(self):
        """Return Boolean describing if the Threat is an 'initial cause'"""
        return (self.uriref, PREDICATE['is_initial_cause'], Literal(True)) in self.system_model

    @property
    def trustworthiness_attribute_sets(self):
        return [self.system_model.trustworthiness_attribute_set(uriref) for uriref in self.system_model.objects(self.uriref, PREDICATE['has_entry_point'])]

    @property
    def primary_threat_misbehaviour_parents(self):
        """Get all the Misbehaviours that can cause this Threat (disregarding likelihoods), for primary Threat types"""
        ms_urirefs = []
        entry_points = self.system_model.objects(self.uriref, PREDICATE['has_entry_point'])
        for twas in entry_points:
            twis = self.system_model.value(predicate=PREDICATE['affects'], object=twas)
            ms_urirefs.append(self.system_model.value(twis, PREDICATE['affected_by']))
        return [self.system_model.misbehaviour(ms_uriref) for ms_uriref in ms_urirefs]

    @property
    def secondary_threat_misbehaviour_parents(self):
        """Get all the Misbehaviours that can cause this Threat (disregarding likelihoods), for secondary Threat types"""
        ms_urirefs = self.system_model.objects(self.uriref, PREDICATE['has_secondary_effect_condition'])
        return [self.system_model.misbehaviour(ms_uriref) for ms_uriref in ms_urirefs]

    @property
    def misbehaviour_parents(self):
        """Get all the Misbehaviours that can cause this Threat (disregarding likelihoods), for all Threat types"""
        return self.primary_threat_misbehaviour_parents + self.secondary_threat_misbehaviour_parents

    @property
    def control_strategies(self, future_risk=None):
        """Return list of control strategy objects that block the threat"""
        csgs = []
        # the "blocks" predicate means a CSG appropriate for current or future risk calc
        # the "mitigates" predicate means a CSG appropriate for future risk (often a contingency plan for a current risk CSG); excluded from likelihood calc in current risk
        # The "mitigates" predicate is not used in newer domain models
        if future_risk == True or future_risk == None:
            for csg_uri in chain(self.system_model.subjects(PREDICATE['blocks'], self.uriref), self.system_model.subjects(PREDICATE['mitigates'], self.uriref)):
                csg = self.system_model.control_strategy(csg_uri)
                if csg.is_future_risk_csg:
                    csgs.append(csg)
        elif future_risk == False or future_risk == None:
            for csg_uri in self.system_model.subjects(PREDICATE['blocks'], self.uriref):
                csg = self.system_model.control_strategy(csg_uri)
                if csg.is_current_risk_csg and not csg.has_inactive_contingency_plan:
                    csgs.append(csg)
        return csgs

class MisbehaviourSet(Entity):
    """Represents a Misbehaviour Set, or "Consequence" (a Misbehaviour at an Asset)."""
    def __init__(self, uriref, graph):
        super().__init__(uriref, graph)

    def __str__(self):
        return "Misbehaviour: {} ({})".format(self.comment, str(self.uriref))

    def _likelihood_uri(self):
        return self.system_model.value(self.uriref, PREDICATE['has_prior'])

    def _impact_uri(self):
        return self.system_model.value(self.uriref, PREDICATE['has_impact'])

    def _risk_uri(self):
        return self.system_model.value(self.uriref, PREDICATE['has_risk'])

    @property
    def misbehaviour(self):
        return self.system_model.misbehaviour(self.system_model.value(self.uriref, PREDICATE['has_misbehaviour']))

    @property
    def asset(self):
        return self.system_model.asset(self.system_model.value(self.uriref, PREDICATE['located_at']))
    
    @property
    def label(self):
        """Return a misbehaviour label"""
        return self.misbehaviour.label

    @property
    def comment(self):
        """Return a short description of a misbehaviour"""
        likelihood = self.likelihood_level_label
        consequence = self.label
        asset = self.asset.label
        aspect = None
        if consequence.startswith("LossOf"):
            aspect = un_camel_case(consequence[6:])
            consequence = "loses"
        elif consequence.startswith("Loss Of"):
            aspect = un_camel_case(consequence[7:])
            consequence = "loses"
        elif consequence.startswith("Not"):
            aspect = un_camel_case(consequence[3:])
            consequence = "is not"
        if aspect != None:
            return '{} likelihood that "{}" {} {}'.format(likelihood, un_camel_case(asset), consequence, aspect)
        else:
            return '{} likelihood of: {} at {}'.format(likelihood, un_camel_case(consequence), un_camel_case(asset))

    @property
    def description(self):
        """Return a long description of a misbehaviour"""
        return self.misbehaviour.description

    @property
    def likelihood_level_number(self):
        return self.system_model.domain_model.level_number(self._likelihood_uri())

    @property
    def likelihood_level_label(self):
        return self.system_model.domain_model.level_label(self._likelihood_uri())

    @property
    def impact_number(self):
        return self.system_model.domain_model.level_number(self._impact_uri())

    @property
    def impact_level_label(self):
        return self.system_model.domain_model.level_label(self._impact_uri())

    @property
    def risk_level_number(self):
        return self.system_model.domain_model.level_number(self._risk_uri())

    @property
    def risk_level_label(self):
        return self.system_model.domain_model.level_label(self._risk_uri())

    @property
    def is_normal_op(self):
        return (self.uriref, PREDICATE['is_normal_op_effect'], Literal(True)) in self.system_model

    @property
    def is_external_cause(self):
        # if the domain model doesn't support mixed cause Threats, then some MS may be external causes
        return (self.uriref, PREDICATE['is_external_cause'], Literal(True)) in self.system_model

    @property
    def threat_parents(self):
        """Get all the Threats that can cause this Misbehaviour (disregarding likelihoods and untriggered Threats)"""
        threats = [self.system_model.threat(t) for t in self.system_model.subjects(PREDICATE['causes_misbehaviour'], self.uriref)]
        # TODO: it would be better to test if a threat had is_triggered and then check the threat's triggering CSGs to see if they were active
        # Easiest to just check the threat likelihood, but this relies on the risk calculation already being done
        return [threat for threat in threats if threat.likelihood_level_number >= 0]  # likelihood_number is set to -1 for untriggered threats

def un_camel_case(text):
    if text is None or text.strip() == "":
        logging.error("un_camel_case: empty text, you may have loaded the wrong domain model")
        return "****"
    text = text.strip()
    text = text.replace("TW", "Trustworthiness")
    if text[0] == "[":
        return text
    else:
        text = re.sub('([a-z])([A-Z])', r'\1 \2', text)
        text = text.replace("Auth N", "AuthN")  # re-join "AuthN" into one word
        text = re.sub('(AuthN)([A-Z])', r'\1 \2', text)
        text = text.replace("Io T", "IoT")  # re-join "IoT" into one word
        text = re.sub('(IoT)([A-Z])', r'\1 \2', text)
        text = re.sub('([A-Z]{2,})([A-Z][a-z])', r'\1 \2', text)  # split out e.g. "PIN" or "ID" as a separate word
        text = text.replace('BIO S', 'BIOS ')  # one label is "BIOSatHost"
        return text