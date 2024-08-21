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
from typing import Optional, List
from itertools import chain

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
    def label(self) -> Optional[str]:
        """
        Retrieve the label associated with the current URI reference.

        Returns:
            Optional[str]: The label if found, otherwise None.
        """
        try:
            label_value = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['label'])
            return label_value if label_value else None
        except Exception as e:
            logging.error(f"Error retrieving label for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def comment(self) -> Optional[str]:
        """
        Retrieve the comment associated with the current URI reference.

        Returns:
            Optional[str]: The comment if found, otherwise None.
        """
        try:
            label_value = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['comment'])
            return label_value if label_value else None
        except Exception as e:
            logging.error(f"Error retrieving comment for {self.uriref}: {e}", exc_info=True)
            return None


class EntityLevel(Entity):
    """ Represents a domain model PopulationLevel """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain EntityLevel: {} ({})".format(self.label, str(self.uriref))

    @property
    def level_value(self) -> Optional[int]:
        """
        Retrieve the level value as an integer for the current entity.

        This method queries the domain model to find the 'level_value' associated
        with `self.uriref` and returns it as an integer.

        Returns:
            Optional[int]: The level value as an integer if found, otherwise None.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['level_value'])
            return int(urirdf) if urirdf else None
        except (ValueError, TypeError) as e:
            logging.error(f"Invalid level value for {self.uriref}: {e}")
            return None
        except Exception as e:
            logging.error(f"Error retrieving level value for {uriref}: {e}")
            return None


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


class CostLevel(EntityLevel):
    """ Represents a domain model CostLevel """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain CostLevel: {} ({})".format(self.label, str(self.uriref))


class ImpactLevel(EntityLevel):
    """ Represents a domain model ImpactLevel """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain ImpactLevel: {} ({})".format(self.label, str(self.uriref))


class PerformanceImpactLevel(EntityLevel):
    """ Represents a domain model PerformanceImpactLevel """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain PerformanceImpactLevel: {} ({})".format(self.label, str(self.uriref))


class Likelihood(EntityLevel):
    """ Represents a domain model Likelihood """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain Likelihood: {} ({})".format(self.label, str(self.uriref))


class ThreatCategory(Entity):
    """ Represents a domain model ThreatCategory """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain ThreatCategory: {} ({})".format(self.label, str(self.uriref))


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
    def is_assertable(self) -> Optional[bool]:
        """
        Retrieve the asset assertability status as a boolean.

        Returns:
            Optional[bool]: True if 'is_assertable' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_assertable'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving asset assertability for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def is_visible(self) -> Optional[bool]:
        """
        Retrieve the asset visibility as a boolean.

        Returns:
            Optional[bool]: True if 'is_visible' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving asset visibility for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def parents(self) -> Optional[List['Asset']]:
        """
        Retrieve the parent asset objects for the current asset.

        Returns:
            Asset list: The parent list of the asset.
            None: If no parent assets found for the given URI reference.
        """
        try:
            urirdf_list = list(self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['sub_class_of']))
            if urirdf_list:
                return [Asset(urirdf, self.domain_model) for urirdf in urirdf_list]
            return []
        except Exception as e:
            logging.error(f"Error retrieving asset parents for {urirdf}: {e}")
            return None

    @property
    def trustworthiness_attributes(self) -> List['TrustworthinessAttribute']:
        """
        Retrieve all trustworthiness attributes related to the current asset.

        Returns:
            List: A list of trustworthiness attribute objects.
        """
        twaads_urirefs = self.domain_model.subjects(predicate=PREDICATE['meta_located_at'], object=self.uriref)

        twa_urirefs = list(chain.from_iterable(
            self.domain_model.objects(subject=twaads, predicate=PREDICATE['has_twa'])
            for twaads in twaads_urirefs
        ))

        return [self.domain_model.trustworthiness_attribute(uriref) for uriref in twa_urirefs]


class Role(Entity):
    """ Represents a domain model Role """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain Role: {} ({})".format(self.label, str(self.uriref))

    @property
    def meta_located_at(self) -> Optional[List[Asset]]:
        """
        Retrieve the assets list object for the current TWA.

        Returns:
            List[Asset]: The list of asset objects caused by the threat.
            None: If no caused misbehaviour set is found for the given URI reference.
        """
        try:
            urirdf_list = list(self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['meta_located_at']))
            if urirdf_list:
                return [Asset(urirdf, self.domain_model) for urirdf in urirdf_list]
            return []
        except Exception as e:
            logging.error(f"Error retrieving meta located assets for {urirdf}: {e}")
            return None


class Control(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain Control: {} ({})".format(self.label, str(self.uriref))

    @property
    def is_visible(self) -> Optional[bool]:
        """
        Retrieve the control visibility as a boolean.

        Returns:
            Optional[bool]: True if 'is_visible' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving control visibility for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def unit_cost(self) -> Optional[CostLevel]:
        """
        Retrieve the cost level for the current control.

        Returns:
            CostLevel: The cost level of the control.
            None: If no CostLevel is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['unit_cost'])
            if urirdf:
                return CostLevel(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving CostLevel for {urirdf}: {e}")
            return None

    @property
    def min(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_min'])

    @property
    def max(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_max'])

    @property
    def located_at(self) -> Optional[Asset]:
        """
        Retrieve the asset for the current control.

        Returns:
            Asset: The asset of the control.
            None: If no Asset is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['located_at'])
            if urirdf:
                return Asset(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving Asset for {urirdf}: {e}")
            return None

    @property
    def performance_impact(self) -> Optional[PerformanceImpactLevel]:
        """
        Retrieve the performance impact level for the current control.

        Returns:
            PerformanceImpactLevel: The PerformanceImpactLevel of the control.
            None: If no PerformanceImpactLevel is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['performance_impact'])
            if urirdf:
                return PerformanceImpactLevel(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving PerformanceImpactLevel for {urirdf}: {e}")
            return None


class ControlSet(BaseEntity):
    """ Represents a domain model ControlSet """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain ControlSet: ({})".format(str(self.uriref))

    @property
    def has_control(self) -> Optional[Control]:
        """
        Retrieve the control for the current control set.

        Returns:
            Control: The Control of the control set.
            None: If no control is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_control'])
            if urirdf:
                return Control(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving control for cs {urirdf}: {e}")
            return None


    @property
    def located_at(self) -> Optional[List[Asset]]:
        """
        Retrieve the assets list object for the current control set.

        Returns:
            List[Asset]: The list of asset objects caused by the control set.
            None: If no assets found for the given URI reference.
        """
        try:
            urirdf_list = list(self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['located_at']))
            if urirdf_list:
                return [Asset(urirdf, self.domain_model) for urirdf in urirdf_list]
            return []
        except Exception as e:
            logging.error(f"Error retrieving located assets for CS {urirdf}: {e}")
            return None

    @property
    def coverage_level(self) -> Optional[TrustworthinessLevel]:
        """
        Retrieve the trustworthiness level for the current control set.

        Returns:
            TrustworthinessLevel: The TrustworthinessLevel of the control set.
            None: If no TrustworthinessLevel is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_blocking_effect'])
            if urirdf:
                return TrustworthinessLevel(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving TrustworthinessLevel for {urirdf}: {e}")
            return None


class ControlStrategy(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain ControlStrategy: {} ({})".format(self.label, str(self.uriref))

    @property
    def blocks(self) -> Optional['Threat']:
        """
        Retrieve the blocking threat for the current control strategy.

        Returns:
            Threat: The Threat this control strategy blocks.
            None: If no blocking threat is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['blocks'])
            if urirdf:
                return Threat(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving blocking threat for {urirdf}: {e}")
            return None

    @property
    def blocking_effect(self) -> Optional[TrustworthinessLevel]:
        """
        Retrieve the trustworthiness level for the current control strategy.

        Returns:
            TrustworthinessLevel: The TrustworthinessLevel of the control strategy.
            None: If no TrustworthinessLevel is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_blocking_effect'])
            if urirdf:
                return TrustworthinessLevel(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving TrustworthinessLevel for {urirdf}: {e}")
            return None

    @property
    def current_risk(self) -> Optional[bool]:
        """
        Retrieve the current risk status as a boolean for the current threat.

        Returns:
            Optional[bool]: True if 'is_current_risk' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_current_risk'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving current risk for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def future_risk(self) -> Optional[bool]:
        """
        Retrieve the future risk status as a boolean for the current threat.

        Returns:
            Optional[bool]: True if 'is_future_risk' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_future_risk'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving future risk for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def min(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_min'])

    @property
    def max(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_max'])

    @property
    def mandatory_cs(self) -> Optional[ControlSet]:
        """
        Retrieve the mandatory control set for the current control strategy.

        Returns:
            ControlSet: The control set this control strategy has.
            None: If no control set is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_mandatory_control_set'])
            if urirdf:
                return ControlSet(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving mandatory control set for {urirdf}: {e}")
            return None

    @property
    def optional_cs(self) -> Optional[ControlSet]:
        """
        Retrieve the optional control set for the current control strategy.

        Returns:
            ControlSet: The optional control set this control strategy has.
            None: If no optional control set is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_optional_cs'])
            if urirdf:
                return ControlSet(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving optional control set for {urirdf}: {e}")
            return None

    def _effectiveness_uriref(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_blocking_effect'])

    @property
    def effectiveness_number(self):
        return self.domain_model.level_number(self._effectiveness_uriref())

    @property
    def effectiveness_label(self):
        return self.domain_model.level_label(self._effectiveness_uriref())
    @property
    def maximum_likelihood_number(self):
        return self.domain_model.level_number_inverse(self.effectiveness_number)


#TODO not sure this exists in DM?
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

    """
    is_assertable
    is_visible
    hidden
    ty_of
    """

class Misbehaviour(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain Misbehaviour: {} ({})".format(self.label, str(self.uriref))

    @property
    def is_visible(self) -> Optional[bool]:
        """
        Retrieve the misbehaviour visibility as a boolean.

        Returns:
            Optional[bool]: True if 'is_visible' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving misbehaviour visibility for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def min(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_min'])

    @property
    def max(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_max'])

    @property
    def located_at(self) -> Optional[List[Asset]]:
        """
        Retrieve the assets list for the current misbehavour.

        Returns:
            List[Asset]: The list of asset objects for current misbehaviour.
            None: If no caused misbehaviour set is found for the given URI reference.
        """
        try:
            urirdf_list = list(self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['located_at']))
            if urirdf_list:
                return [Asset(urirdf, self.domain_model) for urirdf in urirdf_list]
            return []
        except Exception as e:
            logging.error(f"Error retrieving located assets for {urirdf}: {e}")
            return None


class MisbehaviourSet(BaseEntity):
    """ Represents a domain model MisbehaviourSet """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain MisbehaviourSet: ({})".format(str(self.uriref))

    @property
    def has_misbehaviour(self) -> Optional[Misbehaviour]:
        """
        Retrieve the misbehaviour for the current misbehavour set.

        Returns:
            Misbehavour: The misbehaviour this set.
            None: If no misbehavour is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_misbehaviour'])
            if urirdf:
                return Misbehaviour(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving misbehaviour for {urirdf}: {e}")
            return None

    @property
    def located_at(self) -> Optional[Role]:
        """
        Retrieve the Role object for the current misbehaviour set.

        Returns:
            Role: The misbehaviour Role object of the set.
            None: If no Role is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['located_at'])
            if urirdf:
                return Role(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving Role for MS {urirdf}: {e}")
            return None


class MatchingPattern(Entity):
    """ Represents a domain model MatchingPattern """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain MatchingPattern: {} ({})".format(self.label, str(self.uriref))

    @property
    def root_pattern(self) -> Optional['RootPattern']:
        """
        Retrieve the root pattern object for the current pattern.

        Returns:
            RootPattern: The root pattern object of the matching pattern.
            None: If no root pattern is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_root_pattern'])
            if urirdf:
                return RootPattern(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving root pattern for node {urirdf}: {e}")
            return None

    @property
    def necessary_node(self) -> Optional['Node']:
        """
        Retrieve the Node object for the current matching pattern.

        Returns:
            Node: The Node object of the pattern.
            None: If no Node is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_necessary_node'])
            if urirdf:
                return Node(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving Node for node {urirdf}: {e}")
            return None

    @property
    def links(self) -> Optional['RoleLink']:
        """
        Retrieve the role link for the current root pattern.

        Returns:
            RoleLink: The RoleLink this root pattern.
            None: If no role link is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_link'])
            if urirdf:
                return RoleLink(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving role link for {urirdf}: {e}")
            return None


class TrustworthinessAttribute(Entity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain Trustworthiness Attribute: {} ({})".format(self.label, str(self.uriref))

    @property
    def is_visible(self) -> Optional[bool]:
        """
        Retrieve the TWA visibility as a boolean.

        Returns:
            Optional[bool]: True if 'is_visible' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving TWA visibility for {self.uriref}: {e}", exc_info=True)
            return None

    # TODO is it part of TWA?
    @property
    def min_of(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['min_of'])

    # TODO is it part of TWA?
    @property
    def max_of(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['max_of'])

    @property
    def meta_located_at(self) -> Optional[List[Asset]]:
        """
        Retrieve the assets list object for the current TWA.

        Returns:
            List[Asset]: The list of asset objects caused by the threat.
            None: If no caused misbehaviour set is found for the given URI reference.
        """
        try:
            urirdf_list = list(self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['meta_located_at']))
            if urirdf_list:
                return [Asset(urirdf, self.domain_model) for urirdf in urirdf_list]
            return []
        except Exception as e:
            logging.error(f"Error retrieving meta located assets for {urirdf}: {e}")
            return None

    #TODO not sure what it returns looks like a uriref to min? but not more
    @property
    def min(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_min'])

    #TODO not sure what it returns looks like a uriref to min? but not more
    @property
    def max(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_max'])


class TrustworthinessAttributeSet(BaseEntity):
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain Trustworthiness Attribute Set: ({})".format(str(self.uriref))

    @property
    def is_visible(self) -> Optional[bool]:
        """
        Retrieve the twa set visibility as a boolean.

        Returns:
            Optional[bool]: True if 'is_visible' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_visible'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving twa set visibility for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def located_at(self) -> Optional[Role]:
        """
        Retrieve the Role object for the current TWA set.

        Returns:
            Role: The TWA Role object of the set.
            None: If no Role is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['located_at'])
            if urirdf:
                return Role(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving Role for {urirdf}: {e}")
            return None

    @property
    def twa(self) -> Optional[TrustworthinessAttribute]:
        """
        Retrieve the TWA object for the current set.

        Returns:
            TWA: The TWA object of the set.
            None: If no TWA is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_twa'])
            if urirdf:
                return TrustworthinessAttribute(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving TWA for {urirdf}: {e}")
            return None


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
    def category(self) -> Optional[ThreatCategory]:
        """
        Retrieve the category object for the current threat.

        Returns:
            ThreatCategory: The ThreatCategory object if category is found.
            None: If no category is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_category'])
            if urirdf:
                return ThreatCategory(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving category for {urirdf}: {e}")
            return None

    @property
    def frequency(self) -> Optional[Likelihood]:
        """
        Retrieve the frequency Likelihood object for the current threat.

        Returns:
            Likelihood: The Likelihood object if frequency is found.
            None: If no frequency is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_frequency'])
            if urirdf:
                return Likelihood(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving frequency for {urirdf}: {e}")
            return None

    @property
    def current_risk(self) -> Optional[bool]:
        """
        Retrieve the current risk status as a boolean for the current threat.

        Returns:
            Optional[bool]: True if 'is_current_risk' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_current_risk'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving current risk for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def future_risk(self) -> Optional[bool]:
        """
        Retrieve the future risk status as a boolean for the current threat.

        Returns:
            Optional[bool]: True if 'is_future_risk' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_future_risk'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving future risk for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def secondary_threat(self) -> Optional[bool]:
        """
        Retrieve the secondary threat flag as a boolean for the current threat.

        Returns:
            Optional[bool]: True if 'is_secondary_threat' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_secondary_threat'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving secondary threat flag for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def normal_op(self) -> Optional[bool]:
        """
        Retrieve the normal op flag as a boolean for the current threat.

        Returns:
            Optional[bool]: True if 'is_normal_op' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_normal_op'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving normal op flag for {self.uriref}: {e}", exc_info=True)
            return None

    #TODO not sure what it returns looks like a uriref to min? but not more
    @property
    def min(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_min'])

    #TODO not sure what it returns looks like a uriref to min? but not more
    @property
    def max(self):
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_max'])

    @property
    def causes_misbehaviour(self) -> Optional[List[MisbehaviourSet]]:
        """
        Retrieve the caused misbehaviour set object for the current threat.

        Returns:
            MisbehaviourSet: The MisbehaviourSet object caused by the threat.
            None: If no caused misbehaviour set is found for the given URI reference.
        """
        try:
            urirdf_list = list(self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['causes_misbehaviour']))
            if urirdf_list:
                return [MisbehaviourSet(urirdf, self.domain_model) for urirdf in urirdf_list]
            return []
        except Exception as e:
            logging.error(f"Error retrieving caused misbehaviour set for {urirdf}: {e}")
            return None

    @property
    def entry_point(self) -> Optional[List[TrustworthinessAttributeSet]]:
        """
        Retrieve the entry point TWA set object for the current threat.

        Returns:
            TrustworthinessAttributeSet: The TWA set object caused by the threat.
            None: If no TWA set is found for the given URI reference.
        """
        try:
            urirdf_list = list(self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['has_entry_point']))
            if urirdf_list:
                return [TrustworthinessAttributeSet(urirdf, self.domain_model) for urirdf in urirdf_list]
            return []
        except Exception as e:
            logging.error(f"Error retrieving entry point TWA set for {self.uriref}: {e}")
            return None

    @property
    def applies_to(self) -> Optional[MatchingPattern]:
        """
        Retrieve the matching pattern object for the current threat.

        Returns:
            MatchingPattern: The matching pattern object caused by the threat.
            None: If no matching pattern is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['applies_to'])
            if urirdf:
                return MatchingPattern(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving matching pattern for {urirdf}: {e}")
            return None

    @property
    def threatens(self) -> Optional[Role]:
        """
        Retrieve the role object for the current threat.

        Returns:
            Role: The Role object caused by the threat.
            None: If no role is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['threatens'])
            if urirdf:
                return Role(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving Role object for {urirdf}: {e}")
            return None


class CASetting(BaseEntity):
    """ Represents a domain model CASetting """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain CASetting: {} ({})".format(self.label, str(self.uriref))

    @property
    def has_control(self) -> Optional[Control]:
        """
        Retrieve the control for the CA setting.

        Returns:
            Control: The Control of the ca setting.
            None: If no control is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_control'])
            if urirdf:
                return Control(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving control for ca setting {urirdf}: {e}")
            return None

    @property
    def meta_located_at(self) -> Optional[Asset]:
        """
        Retrieve the asset for the CA setting.

        Returns:
            Asset: The asset of the CA setting.
            None: If no Asset is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['meta_located_at'])
            if urirdf:
                return Asset(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving Asset for {urirdf}: {e}")
            return None

    @property
    def is_assertable(self) -> Optional[bool]:
        """
        Retrieve the asset assertibility as a boolean.

        Returns:
            Optional[bool]: True if 'is_assertable' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['is_assertible'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving assertable flag for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def has_level(self) -> Optional[TrustworthinessLevel]:
        """
        Retrieve the trustworthiness level for CA setting.

        Returns:
            TrustworthinessLevel: The TrustworthinessLevel of the CA set.
            None: If no TrustworthinessLevel is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_level'])
            if urirdf:
                return TrustworthinessLevel(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving TrustworthinessLevel for {urirdf}: {e}")
            return None

    @property
    def independent_levels(self) -> Optional[bool]:
        """
        Retrieve the CA settings independent levels as a boolean.

        Returns:
            Optional[bool]: True if 'independent_levels' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['independent_levels'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving independent levels flag for {self.uriref}: {e}", exc_info=True)
            return None


class ComplianceSet(Entity):
    """ Represents a domain model ComplianceSet """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain ComplianceSet: {} ({})".format(self.label, str(self.uriref))

    @property
    def requires_treatment_of(self) -> Optional[List[Threat]]:
        """
        Retrieve the list of threat objects for the current compliance set.

        Returns:
            List[Thrat]: The list of threat objects require treatement in this set.
            None: If no Threats are found for the given URI reference.
        """
        try:
            urirdf_list = list(self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['requires_treatment_of']))
            if urirdf_list:
                return [Threat(urirdf, self.domain_model) for urirdf in urirdf_list]
            return []
        except Exception as e:
            logging.error(f"Error retrieving threats for {self.uriref}: {e}")
            return None


class ConstructionPattern(Entity):
    """ Represents a domain model ConstructionPattern """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain ConstructionPattern: {} ({})".format(self.label, str(self.uriref))

    @property
    def matching_pattern(self) -> Optional[MatchingPattern]:
        """
        Retrieve the matching pattern object for the current construction pattern.

        Returns:
            MatchingPattern: The matching pattern object caused by a construction pattern.
            None: If no matching pattern is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_matching_pattern'])
            if urirdf:
                return MatchingPattern(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving matching pattern for {urirdf}: {e}")
            return None

    @property
    def priority(self) -> Optional[int]:
        """
        Retrieve the priority value as an integer for the construction pattern.

        Returns:
            Optional[int]: The priority value as an integer if found, otherwise None.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_priority'])
            return int(urirdf) if urirdf else None
        except (ValueError, TypeError) as e:
            logging.error(f"Invalid level value for {self.uriref}: {e}")
            return None
        except Exception as e:
            logging.error(f"Error retrieving priority value for {uriref}: {e}")
            return None

    @property
    def iterate(self) -> Optional[bool]:
        """
        Retrieve the iterate status as a boolean.

        Returns:
            Optional[bool]: True if 'iterate' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['iterate'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving iterate status for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def max_iterations(self) -> Optional[int]:
        """
        Retrieve max iterationss value as an integer for the construction pattern.

        Returns:
            Optional[int]: The max iterations as an integer if found, otherwise None.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['max_iterations'])
            return int(urirdf) if urirdf else None
        except (ValueError, TypeError) as e:
            logging.error(f"Invalid max iteration value for {self.uriref}: {e}")
            return None
        except Exception as e:
            logging.error(f"Error retrieving max iteration value for {uriref}: {e}")
            return None

    @property
    def inferred_links(self) -> Optional[List['RoleLink']]:
        """
        Retrieve the role link objects for the construction pattern.

        Returns:
            RoleLink list: The role list list of the construction pattern.
            None: If no role links found for the given URI reference.
        """
        try:
            urirdf_list = list(self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['has_inferred_link']))
            if urirdf_list:
                return [RoleLink(urirdf, self.domain_model) for urirdf in urirdf_list]
            return []
        except Exception as e:
            logging.error(f"Error retrieving role links for {urirdf}: {e}")
            return None


class DistinctNodeGroup(BaseEntity):
    """ Represents a domain model DistinctNodeGroup """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain DistinctNodeGroup: ({})".format(str(self.uriref))

    @property
    def nodes(self) -> Optional[List['Node']]:
        """
        Retrieve the node list for the current group.

        Returns:
            List[Node]: The list of node objects for current group.
            None: If no node list is found for the given URI reference.
        """
        try:
            urirdf_list = list(self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['has_node']))
            if urirdf_list:
                return [Node(urirdf, self.domain_model) for urirdf in urirdf_list]
            return []
        except Exception as e:
            logging.error(f"Error retrieving nodes for {urirdf}: {e}")
            return None


class InferredNodeSetting(BaseEntity):
    """ Represents a domain model InferredNodeSetting """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain InferredNodeSetting: ({})".format(str(self.uriref))

    @property
    def node(self) -> Optional[Role]:
        """
        Retrieve the Node object for the setting.

        Returns:
            Node: The Node object of the node.
            None: If no Node is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_node'])
            if urirdf:
                return Node(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving Node for setting {urirdf}: {e}")
            return None

    @property
    def displayed_at_node(self) -> Optional[Role]:
        """
        Retrieve the Node object for the setting.

        Returns:
            Node: The Node object of the node.
            None: If no Node is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['displayed_at_node'])
            if urirdf:
                return Node(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving Node for setting {urirdf}: {e}")
            return None

    @property
    def includes_node_in_uri(self) -> Optional[List['Node']]:
        """
        Retrieve the node list for the current inferred node setting.

        Returns:
            List[Node]: The list of node objects for current setting.
            None: If no node list is found for the given URI reference.
        """
        try:
            urirdf_list = list(self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['includes_node_in_uri']))
            if urirdf_list:
                return [Node(urirdf, self.domain_model) for urirdf in urirdf_list]
            return []
        except Exception as e:
            logging.error(f"Error retrieving nodes for {urirdf}: {e}")
            return None

class TWAADefaultSetting(BaseEntity):
    """ Represents a domain model TWAADefaultSetting """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain TWAADefaultSetting: ({})".format(str(self.uriref))

    @property
    def located_at(self) -> Optional[Asset]:
        """
        Retrieve the asset for the TWADefault setting.

        Returns:
            Asset: The asset of the TWADefault setting.
            None: If no Asset is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['meta_located_at'])
            if urirdf:
                return Asset(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving Asset for {urirdf}: {e}")
            return None

    @property
    def has_level(self) -> Optional[ImpactLevel]:
        """
        Retrieve the impact level for the TWADefaultSetting.

        Returns:
            ImpactLevel: The ImpactLevel of the MADefault setting.
            None: If no ImpactLevel is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_level'])
            if urirdf:
                return ImpactLevel(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving ImpactLevel for {urirdf}: {e}")
            return None

    @property
    def independent_levels(self) -> Optional[bool]:
        """
        Retrieve the TWAA settings independent levels as a boolean.

        Returns:
            Optional[bool]: True if 'independent_levels' is set, False if not set,
                            or None if there was an error retrieving the value.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['independent_levels'])
            return bool(urirdf) if urirdf else None
        except Exception as e:
            logging.error(f"Error retrieving independent levels flag for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def twa(self) -> Optional[TrustworthinessAttribute]:
        """
        Retrieve the TWA for the current trustworthiness impact set.

        Returns:
            TrustworthinessAttribute: The TWA for this trustworthiness impact set.
            None: If no TWA is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_twa'])
            if urirdf:
                return TrustworthinessAttribute(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving TWA for {urirdf}: {e}")
            return None



class MADefaultSetting(BaseEntity):
    """ Represents a domain model MADefaultSetting """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain MADefaultSetting: ({})".format(str(self.uriref))

    @property
    def located_at(self) -> Optional[Asset]:
        """
        Retrieve the asset for the MADefault setting.

        Returns:
            Asset: The asset of the MADefault setting.
            None: If no Asset is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['located_at'])
            if urirdf:
                return Asset(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving Asset for {urirdf}: {e}")
            return None

    @property
    def has_misbehaviour(self) -> Optional[Misbehaviour]:
        """
        Retrieve the misbehaviour for the current MADefaultSetting.

        Returns:
            Misbehavour: The misbehaviour this set.
            None: If no misbehavour is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_misbehaviour'])
            if urirdf:
                return Misbehaviour(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving misbehaviour for {urirdf}: {e}")
            return None

    @property
    def has_level(self) -> Optional[ImpactLevel]:
        """
        Retrieve the impact level for the MADefaultSetting.

        Returns:
            ImpactLevel: The ImpactLevel of the MADefault setting.
            None: If no ImpactLevel is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_level'])
            if urirdf:
                return ImpactLevel(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving ImpactLevel for {urirdf}: {e}")
            return None


class Node(BaseEntity):
    """ Represents a domain model Node """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain Node: ({})".format(str(self.uriref))

    @property
    def meta_asset(self) -> Optional[Asset]:
        return self.domain_model.value(subject=self.uriref, predicate=PREDICATE['meta_has_asset'])
        """
        Retrieve the asset for the current node.

        Returns:
            Asset: The asset of the node.
            None: If no Asset is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['meta_has_asset'])
            if urirdf:
                return Asset(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving Asset for node {urirdf}: {e}")
            return None

    @property
    def role(self) -> Optional[Role]:
        """
        Retrieve the Role object for the current node.

        Returns:
            Role: The Role object of the node.
            None: If no Role is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_role'])
            if urirdf:
                return Role(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving Role for node {urirdf}: {e}")
            return None


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
    def label(self) -> Optional[str]:
        """
        Retrieve the label associated with the current URI reference.

        Returns:
            Optional[str]: The label if found, otherwise None.
        """
        try:
            label_value = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['label'])
            return label_value if label_value else None
        except Exception as e:
            logging.error(f"Error retrieving label for {self.uriref}: {e}", exc_info=True)
            return None

    @property
    def key_nodes(self) -> Optional[List[Node]]:
        """
        Retrieve the node list for the current root pattern.

        Returns:
            List[Node]: The list of node objects for current root pattern.
            None: If no node list is found for the given URI reference.
        """
        try:
            urirdf_list = list(self.domain_model.objects(subject=self.uriref, predicate=PREDICATE['has_key_node']))
            if urirdf_list:
                return [Node(urirdf, self.domain_model) for urirdf in urirdf_list]
            return []
        except Exception as e:
            logging.error(f"Error retrieving nodes for {urirdf}: {e}")
            return None

    @property
    def links(self) -> Optional[RoleLink]:
        """
        Retrieve the role link for the current root pattern.

        Returns:
            RoleLink: The RoleLink this root pattern.
            None: If no role link is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['has_link'])
            if urirdf:
                return RoleLink(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving role link for {urirdf}: {e}")
            return None


class TrustworthinessImpactSet(BaseEntity):
    """ Represents a domain model TrustworthinessImpactSet """
    def __init__(self, uriref, domain_model):
        super().__init__(uriref, domain_model)

    def __str__(self):
        return "Domain TrustworthinessImpactSet: ({})".format(str(self.uriref))

    @property
    def affected_by(self) -> Optional[Misbehaviour]:
        """
        Retrieve the misbehaviour for the current trustworthiness impact set.

        Returns:
            Misbehavour: The misbehaviour this trustworthiness impact set.
            None: If no misbehavour is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['affected_by'])
            if urirdf:
                return Misbehaviour(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving misbehaviour for {urirdf}: {e}")
            return None

    @property
    def affects(self) -> Optional[TrustworthinessAttribute]:
        """
        Retrieve the TWA for the current trustworthiness impact set.

        Returns:
            TrustworthinessAttribute: The TWA for this trustworthiness impact set.
            None: If no TWA is found for the given URI reference.
        """
        try:
            urirdf = self.domain_model.value(subject=self.uriref, predicate=PREDICATE['affects'])
            if urirdf:
                return TrustworthinessAttribute(urirdf, self.domain_model)
            return None
        except Exception as e:
            logging.error(f"Error retrieving TWA for {urirdf}: {e}")
            return None


