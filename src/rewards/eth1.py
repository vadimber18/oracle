from datetime import timedelta
from typing import Dict

import backoff
from web3.types import BlockNumber

from src.clients import execute_graphql_query, sw_gql_client
from src.graphql_queries import FINALIZED_VALIDATORS_QUERY

from .types import FinalizedValidatorsPublicKeys

SYNC_PERIOD = timedelta(days=1)


@backoff.on_exception(backoff.expo, Exception, max_time=900)
async def get_finalized_validators_public_keys(
    block_number: BlockNumber,
) -> FinalizedValidatorsPublicKeys:
    """Fetches pool validators public keys."""
    last_id = ""
    result: Dict = await execute_graphql_query(
        client=sw_gql_client,
        query=FINALIZED_VALIDATORS_QUERY,
        variables=dict(block_number=block_number, last_id=last_id),
    )
    validators_chunk = result.get("validators", [])
    validators = validators_chunk

    # accumulate chunks of validators
    while len(validators_chunk) >= 1000:
        last_id = validators_chunk[-1]["id"]
        if not last_id:
            break

        result: Dict = await execute_graphql_query(
            client=sw_gql_client,
            query=FINALIZED_VALIDATORS_QUERY,
            variables=dict(block_number=block_number, last_id=last_id),
        )
        validators_chunk = result.get("validators", [])
        validators.extend(validators_chunk)

    return set([val["id"] for val in validators])
