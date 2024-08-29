# Must imports
from slips_files.common.imports import *

# Import the fides class (add a layer of abstraction)
from module import SlipsFidesModule

# original module imports
import json
import sys
from dataclasses import asdict
from multiprocessing import Process

from fides.messaging.message_handler import MessageHandler
from fides.messaging.network_bridge import NetworkBridge
from fides.model.configuration import load_configuration
from fides.model.threat_intelligence import SlipsThreatIntelligence
from fides.protocols.alert import AlertProtocol
from fides.protocols.initial_trusl import InitialTrustProtocol
from fides.protocols.opinion import OpinionAggregator
from fides.protocols.peer_list import PeerListUpdateProtocol
from fides.protocols.recommendation import RecommendationProtocol
from fides.protocols.threat_intelligence import ThreatIntelligenceProtocol
from fides.utils.logger import LoggerPrintCallbacks, Logger
from fidesModule.messaging.queue import RedisQueue, RedisSimplexQueue
from fidesModule.originals.abstracts import Module
from fidesModule.originals.database import __database__
from fidesModule.persistance.threat_intelligence import SlipsThreatIntelligenceDatabase
from fidesModule.persistance.trust import SlipsTrustDatabase


class fidesModule(IModule):
    # Name: short name of the module. Do not use spaces
    name = "Fides"
    description = "Trust computation module for P2P interactions."
    authors = ['Lukas Forst', 'Martin Repa', 'David Otta']

    def init(self):
        # Process.__init__(self) done by IModule
        self.__output = self.logger
        # TODO: [S+] add path to trust model configuration yaml to the slips conf
        self.__slips_config = slips_conf # TODO give it path to config file and move the config file to module

        # connect to slips database
        #__database__.start(slips_conf) # __database__ replaced by self.db from IModule, no need ot start it

        # IModule has its own logger, no set-up
        # LoggerPrintCallbacks.clear()
        # LoggerPrintCallbacks.append(self.__format_and_print)

        # load trust model configuration
        self.__trust_model_config = load_configuration(self.__slips_config.trust_model_path) # TODO fix this to make it work under new management

        # prepare variables for global protocols
        self.__bridge: NetworkBridge
        self.__intelligence: ThreatIntelligenceProtocol
        self.__alerts: AlertProtocol
        self.__slips_fides: RedisQueue

    def __setup_trust_model(self):
        r = self.db.rdb

        # TODO: [S] launch network layer binary if necessary

        # create database wrappers for Slips using Redis
        trust_db = SlipsTrustDatabase(self.__trust_model_config, r)
        ti_db = SlipsThreatIntelligenceDatabase(self.__trust_model_config, r)

        # create queues
        # TODO: [S] check if we need to use duplex or simplex queue for communication with network module
        network_fides_queue = RedisSimplexQueue(r, send_channel='fides2network', received_channel='network2fides')
        slips_fides_queue = RedisSimplexQueue(r, send_channel='fides2slips', received_channel='slips2fides')

        bridge = NetworkBridge(network_fides_queue)

        recommendations = RecommendationProtocol(self.__trust_model_config, trust_db, bridge)
        trust = InitialTrustProtocol(trust_db, self.__trust_model_config, recommendations)
        peer_list = PeerListUpdateProtocol(trust_db, bridge, recommendations, trust)
        opinion = OpinionAggregator(self.__trust_model_config, ti_db, self.__trust_model_config.ti_aggregation_strategy)

        intelligence = ThreatIntelligenceProtocol(trust_db, ti_db, bridge, self.__trust_model_config, opinion, trust,
                                                  self.__slips_config.interaction_evaluation_strategy,
                                                  self.__network_opinion_callback)
        alert = AlertProtocol(trust_db, bridge, trust, self.__trust_model_config, opinion,
                              self.__network_opinion_callback)

        # TODO: [S+] add on_unknown and on_error handlers if necessary
        message_handler = MessageHandler(
            on_peer_list_update=peer_list.handle_peer_list_updated,
            on_recommendation_request=recommendations.handle_recommendation_request,
            on_recommendation_response=recommendations.handle_recommendation_response,
            on_alert=alert.handle_alert,
            on_intelligence_request=intelligence.handle_intelligence_request,
            on_intelligence_response=intelligence.handle_intelligence_response,
            on_unknown=None,
            on_error=None
        )

        # bind local vars
        self.__bridge = bridge
        self.__intelligence = intelligence
        self.__alerts = alert
        self.__slips_fides = slips_fides_queue

        # and finally execute listener
        self.__bridge.listen(message_handler, block=False)

    def pre_main(self):
        """
        Initializations that run only once before the main() function runs in a loop
        """
        # utils.drop_root_privs()

    def main(self):
        """Main loop function"""
        if msg := self.get_msg("new_ip"):
            # Example of printing the number of profiles in the
            # Database every second
            data = len(self.db.getProfiles())
            self.print(f"Amount of profiles: {data}", 3, 0)