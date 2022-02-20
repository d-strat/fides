import json
from dataclasses import asdict
from typing import Dict, List, Optional

from dacite import from_dict

from fides.messaging.message_handler import MessageHandler
from fides.messaging.model import NetworkMessage
from fides.messaging.queue import Queue
from fides.model.alert import Alert
from fides.model.aliases import PeerId, Target
from fides.model.recommendation import Recommendation
from fides.model.threat_intelligence import ThreatIntelligence
from fides.utils.logger import Logger

logger = Logger(__name__)


class NetworkBridge:
    """
    Class responsible for communication with the network module.

    In order to connect bridge to the queue and start receiving messages,
    execute "listen" method.
    """
    version = 1

    def __init__(self, queue: Queue):
        self.__queue = queue

    def listen(self, handler: MessageHandler, block: bool = False):
        """Starts messages processing

        If :param: block = False, this method won't block this thread.
        """

        def message_received(message: str):
            logger.debug(f'New message received! Trying to parse..')
            try:
                parsed = json.loads(message)
                network_message = from_dict(data_class=NetworkMessage, data=parsed)
                logger.debug('Message parsed. Executing handler.')
                handler.on_message(network_message)
            except Exception as e:
                logger.error(f'There was an error processing message, Exception: {e}.')
                handler.on_error(message, e)

        logger.info(f'Starts listening...')
        return self.__queue.listen(message_received, block=block)

    def get_message(self, timeout_seconds: float = 0) -> Optional[NetworkMessage]:
        """Starts messages processing

        This method might block, depending on Queue implementation of "listen" method.
        """
        # check if current implementation of queue supports this option
        if not hasattr(self.__queue, 'get_message'):
            raise NotImplemented('Current implementation of Queue does not support this method!')

        # we checked that existence in step before
        # noinspection PyUnresolvedReferences
        message = self.__queue.get_message(timeout=timeout_seconds)
        if message is not None:
            try:
                logger.debug('Message received, trying to parse.')
                parsed = json.loads(message)
                network_message = from_dict(data_class=NetworkMessage, data=parsed)
                logger.debug('Message parsed. Executing handler.')
                return network_message
            except Exception as ex:
                logger.error(f'There was an error processing message, Exception: {ex}.')
        else:
            logger.debug(f'Timeout expired - {timeout_seconds}s - and no message was received.')
        return None

    def send_intelligence_response(self, request_id: str, target: Target, intelligence: ThreatIntelligence):
        """Shares Intelligence with peer that requested it. request_id comes from the first request."""
        envelope = NetworkMessage(
            type='tl2nl_intelligence_response',
            version=self.version,
            data={
                'request_id': request_id,
                'payload': {'target': target, 'intelligence': intelligence}
            }
        )
        return self.__send(envelope)

    def send_intelligence_request(self, target: Target):
        """Requests network intelligence from the network regarding this target."""
        envelope = NetworkMessage(
            type='tl2nl_intelligence_request',
            version=self.version,
            data={'payload': target}
        )
        return self.__send(envelope)

    def send_alert(self, target: Target, intelligence: ThreatIntelligence):
        """Broadcasts alert through the network about the target."""
        envelope = NetworkMessage(
            type='tl2nl_alert',
            version=self.version,
            data={
                'payload': Alert(
                    target=target,
                    score=intelligence.score,
                    confidence=intelligence.confidence
                )
            }
        )
        return self.__send(envelope)

    def send_recommendation_response(self, request_id: str,
                                     recipient: PeerId,
                                     subject: PeerId,
                                     recommendation: Recommendation):
        """Responds to given request_id to recipient with recommendation on target."""
        envelope = NetworkMessage(
            type='tl2nl_recommendation_response',
            version=self.version,
            data={
                'request_id': request_id,
                'recipient_id': recipient,
                'payload': {'subject': subject, 'recommendation': recommendation}
            }
        )
        return self.__send(envelope)

    def send_recommendation_request(self, recipients: List[PeerId], peer: PeerId):
        """Request recommendation from recipients on given peer."""
        envelope = NetworkMessage(
            type='tl2nl_recommendation_request',
            version=self.version,
            data={
                'receiver_ids': recipients,
                'payload': peer
            }
        )
        return self.__send(envelope)

    def send_peers_reliability(self, reliability: Dict[PeerId, float]):
        """Sends peer reliability, this message is only for network layer and is not dispatched to the network."""
        data = [{'peer_id': key, 'reliability': value} for key, value in reliability.items()]
        envelope = NetworkMessage(
            type='tl2nl_peers_reliability',
            version=self.version,
            data=data
        )
        return self.__send(envelope)

    def __send(self, envelope: NetworkMessage):
        logger.debug('Sending', envelope)
        try:
            j = json.dumps(asdict(envelope))
            return self.__queue.send(j)
        except Exception as ex:
            logger.error(f'Exception during sending an envelope: {ex}.', envelope)
