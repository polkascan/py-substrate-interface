#  Python SCALE Codec Library
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

def get_apis():

    return [
        {
            'name': 'Core', 'methods': [
                {'name': 'version', 'inputs': [], 'output': 'RuntimeVersion', 'docs': [' Returns the version of the runtime.']},
                # {'name': 'execute_block', 'inputs': [{'name': 'block', 'type': 864}], 'output': 32,
                #  'docs': [' Execute the given block.']},
                # {'name': 'initialize_block', 'inputs': [{'name': 'header', 'type': 156}], 'output': 32,
                #  'docs': [' Initialize a block with the given header.']}
            ],
            'docs': [' The `Core` runtime api that every Substrate runtime needs to implement.']
        },
        {
            'name': 'AccountNonceApi',
            'methods': [
                {
                    'name': 'account_nonce', 'inputs': [{'name': 'account', 'type': 'AccountId'}], 'output': 'Index',
                    'docs': [' Get current account nonce of given `AccountId`.']
                }
            ],
            'docs': [' The API to query account nonce.']
        },
        {
            'name': 'TransactionPaymentApi',
            'methods': [{'name': 'query_info',
                          'inputs': [{'name': 'uxt',
                                      'type': 'Extrinsic'},
                                     {'name': 'len',
                                      'type': 'u32'}],
                          'output': 'RuntimeDispatchInfo',
                          'docs': []}, {
                             'name': 'query_fee_details',
                             'inputs': [
                                 {'name': 'uxt',
                                  'type': 'Extrinsic'},
                                 {'name': 'len',
                                  'type': 'u32'}],
                             'output': 'FeeDetails',
                             'docs': []}
                        ],
            'docs': []
         }
    ]

    return [
        {
            'name': 'Core', 'methods': [
                {'name': 'version', 'inputs': [], 'output': 465, 'docs': [' Returns the version of the runtime.']},
                {'name': 'execute_block', 'inputs': [{'name': 'block', 'type': 864}], 'output': 32,
                 'docs': [' Execute the given block.']},
                {'name': 'initialize_block', 'inputs': [{'name': 'header', 'type': 156}], 'output': 32,
                 'docs': [' Initialize a block with the given header.']}
            ],
                'docs': [' The `Core` runtime api that every Substrate runtime needs to implement.']
        },
                     {'name': 'Metadata', 'methods': [
                         {'name': 'metadata', 'inputs': [], 'output': 867, 'docs': [' Returns the metadata of a runtime.']},
                         {'name': 'metadata_at_version', 'inputs': [{'name': 'version', 'type': 4}], 'output': 868,
                          'docs': [' Returns the metadata at a given version.', '',
                                   " If the given `version` isn't supported, this will return `None`.",
                                   ' Use [`Self::metadata_versions`] to find out about supported metadata version of the runtime.']},
                         {'name': 'metadata_versions', 'inputs': [], 'output': 114,
                          'docs': [' Returns the supported metadata versions.', '',
                                   ' This can be used to call `metadata_at_version`.']}],
                      'docs': [' The `Metadata` api trait that returns metadata for the runtime.']},
                     {'name': 'BlockBuilder', 'methods': [
                         {'name': 'apply_extrinsic', 'inputs': [{'name': 'extrinsic', 'type': 865}], 'output': 869,
                          'docs': [' Apply the given extrinsic.', '',
                                   ' Returns an inclusion outcome which specifies if this extrinsic is included in',
                                   ' this block or not.']},
                         {'name': 'finalize_block', 'inputs': [], 'output': 156, 'docs': [' Finish the current block.']},
                         {'name': 'inherent_extrinsics', 'inputs': [{'name': 'inherent', 'type': 873}], 'output': 866,
                          'docs': [' Generate inherent extrinsics. The inherent data will vary from chain to chain.']},
                         {'name': 'check_inherents',
                          'inputs': [{'name': 'block', 'type': 864}, {'name': 'data', 'type': 873}], 'output': 877,
                          'docs': [
                              ' Check that the inherents are valid. The inherent data will vary from chain to chain.']}],
                      'docs': [
                          ' The `BlockBuilder` api trait that provides the required functionality for building a block.']},
                     {'name': 'TaggedTransactionQueue', 'methods': [{'name': 'validate_transaction',
                                                                     'inputs': [{'name': 'source', 'type': 878},
                                                                                {'name': 'tx', 'type': 865},
                                                                                {'name': 'block_hash', 'type': 12}],
                                                                     'output': 879,
                                                                     'docs': [' Validate the transaction.', '',
                                                                              ' This method is invoked by the transaction pool to learn details about given transaction.',
                                                                              ' The implementation should make sure to verify the correctness of the transaction',
                                                                              ' against current state. The given `block_hash` corresponds to the hash of the block',
                                                                              ' that is used as current state.', '',
                                                                              ' Note that this call may be performed by the pool multiple times and transactions',
                                                                              ' might be verified in any possible order.']}],
                      'docs': [' The `TaggedTransactionQueue` api trait for interfering with the transaction queue.']},
                     {'name': 'ValidateStatement', 'methods': [{'name': 'validate_statement',
                                                                'inputs': [{'name': 'source', 'type': 881},
                                                                           {'name': 'statement', 'type': 443}],
                                                                'output': 882, 'docs': [' Validate the statement.']}],
                      'docs': [' Runtime API trait for statement validation.']}, {'name': 'OffchainWorkerApi', 'methods': [
            {'name': 'offchain_worker', 'inputs': [{'name': 'header', 'type': 156}], 'output': 32,
             'docs': [' Starts the off-chain task for given block header.']}], 'docs': [' The offchain worker api.']},
                     {'name': 'GrandpaApi', 'methods': [{'name': 'grandpa_authorities', 'inputs': [], 'output': 65,
                                                         'docs': [
                                                             ' Get the current GRANDPA authorities and weights. This should not change except',
                                                             ' for when changes are scheduled and the corresponding delay has passed.',
                                                             '',
                                                             ' When called at block B, it will return the set of authorities that should be',
                                                             ' used to finalize descendants of this block (B+1, B+2, ...). The block B itself',
                                                             ' is finalized by the authorities from block B-1.']},
                                                        {'name': 'submit_report_equivocation_unsigned_extrinsic',
                                                         'inputs': [{'name': 'equivocation_proof', 'type': 247},
                                                                    {'name': 'key_owner_proof', 'type': 885}],
                                                         'output': 886, 'docs': [
                                                            ' Submits an unsigned extrinsic to report an equivocation. The caller',
                                                            ' must provide the equivocation proof and a key ownership proof',
                                                            ' (should be obtained using `generate_key_ownership_proof`). The',
                                                            ' extrinsic will be unsigned and should only be accepted for local',
                                                            ' authorship (not to be broadcast to the network). This method returns',
                                                            ' `None` when creation of the extrinsic fails, e.g. if equivocation',
                                                            ' reporting is disabled for the given runtime (i.e. this method is',
                                                            ' hardcoded to return `None`). Only useful in an offchain context.']},
                                                        {'name': 'generate_key_ownership_proof',
                                                         'inputs': [{'name': 'set_id', 'type': 11},
                                                                    {'name': 'authority_id', 'type': 67}], 'output': 887,
                                                         'docs': [
                                                             ' Generates a proof of key ownership for the given authority in the',
                                                             ' given set. An example usage of this module is coupled with the',
                                                             ' session historical module to prove that a given authority key is',
                                                             ' tied to a given staking identity during a specific session. Proofs',
                                                             ' of key ownership are necessary for submitting equivocation reports.',
                                                             ' NOTE: even though the API takes a `set_id` as parameter the current',
                                                             ' implementations ignore this parameter and instead rely on this',
                                                             ' method being called at the correct block height, i.e. any point at',
                                                             ' which the given set id is live on-chain. Future implementations will',
                                                             ' instead use indexed data through an offchain worker, not requiring',
                                                             ' older states to be available.']},
                                                        {'name': 'current_set_id', 'inputs': [], 'output': 11,
                                                         'docs': [' Get current GRANDPA authority set id.']}],
                      'docs': [' APIs for integrating the GRANDPA finality gadget into runtimes.',
                               ' This should be implemented on the runtime side.', '',
                               ' This is primarily used for negotiating authority-set changes for the',
                               ' gadget. GRANDPA uses a signaling model of changing authority sets:',
                               ' changes should be signaled with a delay of N blocks, and then automatically',
                               ' applied in the runtime after those N blocks have passed.', '',
                               ' The consensus protocol will coordinate the handoff externally.']},
                     {'name': 'NominationPoolsApi', 'methods': [
                         {'name': 'pending_rewards', 'inputs': [{'name': 'who', 'type': 0}], 'output': 6,
                          'docs': [' Returns the pending rewards for the member that the AccountId was given for.']},
                         {'name': 'points_to_balance',
                          'inputs': [{'name': 'pool_id', 'type': 4}, {'name': 'points', 'type': 6}], 'output': 6,
                          'docs': [' Returns the equivalent balance of `points` for a given pool.']},
                         {'name': 'balance_to_points',
                          'inputs': [{'name': 'pool_id', 'type': 4}, {'name': 'new_funds', 'type': 6}], 'output': 6,
                          'docs': [' Returns the equivalent points of `new_funds` for a given pool.']}],
                      'docs': [' Runtime api for accessing information about nomination pools.']}, {'name': 'StakingApi',
                                                                                                    'methods': [{
                                                                                                        'name': 'nominations_quota',
                                                                                                        'inputs': [
                                                                                                            {
                                                                                                                'name': 'balance',
                                                                                                                'type': 6}],
                                                                                                        'output': 4,
                                                                                                        'docs': [
                                                                                                            ' Returns the nominations quota for a nominator with a given balance.']}],
                                                                                                    'docs': []},
                     {'name': 'BabeApi', 'methods': [{'name': 'configuration', 'inputs': [], 'output': 888,
                                                      'docs': [' Return the configuration for BABE.']},
                                                     {'name': 'current_epoch_start', 'inputs': [], 'output': 159,
                                                      'docs': [' Returns the slot that started the current epoch.']},
                                                     {'name': 'current_epoch', 'inputs': [], 'output': 889,
                                                      'docs': [' Returns information regarding the current epoch.']},
                                                     {'name': 'next_epoch', 'inputs': [], 'output': 889, 'docs': [
                                                         ' Returns information regarding the next epoch (which was already',
                                                         ' previously announced).']},
                                                     {'name': 'generate_key_ownership_proof',
                                                      'inputs': [{'name': 'slot', 'type': 159},
                                                                 {'name': 'authority_id', 'type': 158}], 'output': 890,
                                                      'docs': [
                                                          ' Generates a proof of key ownership for the given authority in the',
                                                          ' current epoch. An example usage of this module is coupled with the',
                                                          ' session historical module to prove that a given authority key is',
                                                          ' tied to a given staking identity during a specific session. Proofs',
                                                          ' of key ownership are necessary for submitting equivocation reports.',
                                                          ' NOTE: even though the API takes a `slot` as parameter the current',
                                                          ' implementations ignores this parameter and instead relies on this',
                                                          ' method being called at the correct block height, i.e. any point at',
                                                          ' which the epoch for the given slot is live on-chain. Future',
                                                          ' implementations will instead use indexed data through an offchain',
                                                          ' worker, not requiring older states to be available.']},
                                                     {'name': 'submit_report_equivocation_unsigned_extrinsic',
                                                      'inputs': [{'name': 'equivocation_proof', 'type': 155},
                                                                 {'name': 'key_owner_proof', 'type': 891}], 'output': 886,
                                                      'docs': [
                                                          ' Submits an unsigned extrinsic to report an equivocation. The caller',
                                                          ' must provide the equivocation proof and a key ownership proof',
                                                          ' (should be obtained using `generate_key_ownership_proof`). The',
                                                          ' extrinsic will be unsigned and should only be accepted for local',
                                                          ' authorship (not to be broadcast to the network). This method returns',
                                                          ' `None` when creation of the extrinsic fails, e.g. if equivocation',
                                                          ' reporting is disabled for the given runtime (i.e. this method is',
                                                          ' hardcoded to return `None`). Only useful in an offchain context.']}],
                      'docs': [' API necessary for block authorship with BABE.']}, {'name': 'AuthorityDiscoveryApi',
                                                                                    'methods': [{'name': 'authorities',
                                                                                                 'inputs': [],
                                                                                                 'output': 610, 'docs': [
                                                                                            ' Retrieve authority identifiers of the current and next authority set.']}],
                                                                                    'docs': [
                                                                                        ' The authority discovery api.', '',
                                                                                        ' This api is used by the `client/authority-discovery` module to retrieve identifiers',
                                                                                        ' of the current and next authority set.']},
        {
            'name': 'AccountNonceApi',
            'methods': [
                {
                    'name': 'account_nonce', 'inputs': [{'name': 'account', 'type': 'AccountId'}], 'output': 'Index',
                    'docs': [' Get current account nonce of given `AccountId`.']}],
                      'docs': [' The API to query account nonce.']}, {'name': 'AssetsApi', 'methods': [
            {'name': 'account_balances', 'inputs': [{'name': 'account', 'type': 0}], 'output': 631,
             'docs': [' Returns the list of `AssetId`s and corresponding balance that an `AccountId` has.']}], 'docs': []},
                     {'name': 'ContractsApi', 'methods': [{'name': 'call', 'inputs': [{'name': 'origin', 'type': 0},
                                                                                      {'name': 'dest', 'type': 0},
                                                                                      {'name': 'value', 'type': 6},
                                                                                      {'name': 'gas_limit', 'type': 423},
                                                                                      {'name': 'storage_deposit_limit',
                                                                                       'type': 331},
                                                                                      {'name': 'input_data', 'type': 13}],
                                                           'output': 892, 'docs': [
                             ' Perform a call from a specified account to a given contract.', '',
                             ' See [`crate::Pallet::bare_call`].']}, {'name': 'instantiate',
                                                                      'inputs': [{'name': 'origin', 'type': 0},
                                                                                 {'name': 'value', 'type': 6},
                                                                                 {'name': 'gas_limit', 'type': 423},
                                                                                 {'name': 'storage_deposit_limit',
                                                                                  'type': 331},
                                                                                 {'name': 'code', 'type': 899},
                                                                                 {'name': 'data', 'type': 13},
                                                                                 {'name': 'salt', 'type': 13}],
                                                                      'output': 900,
                                                                      'docs': [' Instantiate a new contract.', '',
                                                                               ' See `[crate::Pallet::bare_instantiate]`.']},
                                                          {'name': 'upload_code', 'inputs': [{'name': 'origin', 'type': 0},
                                                                                             {'name': 'code', 'type': 13}, {
                                                                                                 'name': 'storage_deposit_limit',
                                                                                                 'type': 331},
                                                                                             {'name': 'determinism',
                                                                                              'type': 262}], 'output': 903,
                                                           'docs': [
                                                               ' Upload new code without instantiating a contract from it.',
                                                               '', ' See [`crate::Pallet::bare_upload_code`].']},
                                                          {'name': 'get_storage', 'inputs': [{'name': 'address', 'type': 0},
                                                                                             {'name': 'key', 'type': 13}],
                                                           'output': 905,
                                                           'docs': [' Query a given storage key in a given contract.', '',
                                                                    ' Returns `Ok(Some(Vec<u8>))` if the storage value exists under the given key in the',
                                                                    " specified account and `Ok(None)` if it doesn't. If the account specified by the address",
                                                                    " doesn't exist, or doesn't have a contract then `Err` is returned."]}],
                      'docs': [' The API used to dry-run contract interactions.']}, {'name': 'TransactionPaymentApi',
                                                                                     'methods': [{'name': 'query_info',
                                                                                                  'inputs': [{'name': 'uxt',
                                                                                                              'type': 865},
                                                                                                             {'name': 'len',
                                                                                                              'type': 4}],
                                                                                                  'output': 907,
                                                                                                  'docs': []}, {
                                                                                                     'name': 'query_fee_details',
                                                                                                     'inputs': [
                                                                                                         {'name': 'uxt',
                                                                                                          'type': 865},
                                                                                                         {'name': 'len',
                                                                                                          'type': 4}],
                                                                                                     'output': 908,
                                                                                                     'docs': []}, {
                                                                                                     'name': 'query_weight_to_fee',
                                                                                                     'inputs': [
                                                                                                         {'name': 'weight',
                                                                                                          'type': 9}],
                                                                                                     'output': 6,
                                                                                                     'docs': []}, {
                                                                                                     'name': 'query_length_to_fee',
                                                                                                     'inputs': [
                                                                                                         {'name': 'length',
                                                                                                          'type': 4}],
                                                                                                     'output': 6,
                                                                                                     'docs': []}],
                                                                                     'docs': []},
                     {'name': 'AssetConversionApi', 'methods': [{'name': 'quote_price_tokens_for_exact_tokens',
                                                                 'inputs': [{'name': 'asset1', 'type': 399},
                                                                            {'name': 'asset2', 'type': 399},
                                                                            {'name': 'amount', 'type': 6},
                                                                            {'name': 'include_fee', 'type': 43}],
                                                                 'output': 331, 'docs': [
                             ' Provides a quote for [`Pallet::swap_tokens_for_exact_tokens`].', '',
                             ' Note that the price may have changed by the time the transaction is executed.',
                             ' (Use `amount_in_max` to control slippage.)']},
                                                                {'name': 'quote_price_exact_tokens_for_tokens',
                                                                 'inputs': [{'name': 'asset1', 'type': 399},
                                                                            {'name': 'asset2', 'type': 399},
                                                                            {'name': 'amount', 'type': 6},
                                                                            {'name': 'include_fee', 'type': 43}],
                                                                 'output': 331, 'docs': [
                                                                    ' Provides a quote for [`Pallet::swap_exact_tokens_for_tokens`].',
                                                                    '',
                                                                    ' Note that the price may have changed by the time the transaction is executed.',
                                                                    ' (Use `amount_out_min` to control slippage.)']},
                                                                {'name': 'get_reserves',
                                                                 'inputs': [{'name': 'asset1', 'type': 399},
                                                                            {'name': 'asset2', 'type': 399}], 'output': 911,
                                                                 'docs': [
                                                                     ' Returns the size of the liquidity pool for the given asset pair.']}],
                      'docs': [' This runtime api allows people to query the size of the liquidity pools',
                               ' and quote prices for swaps.']}, {'name': 'TransactionPaymentCallApi', 'methods': [
            {'name': 'query_call_info', 'inputs': [{'name': 'call', 'type': 141}, {'name': 'len', 'type': 4}],
             'output': 907, 'docs': [' Query information of a dispatch class, weight, and fee of a given encoded `Call`.']},
            {'name': 'query_call_fee_details', 'inputs': [{'name': 'call', 'type': 141}, {'name': 'len', 'type': 4}],
             'output': 908, 'docs': [' Query fee details of a given encoded `Call`.']},
            {'name': 'query_weight_to_fee', 'inputs': [{'name': 'weight', 'type': 9}], 'output': 6,
             'docs': [' Query the output of the current `WeightToFee` given some input.']},
            {'name': 'query_length_to_fee', 'inputs': [{'name': 'length', 'type': 4}], 'output': 6,
             'docs': [' Query the output of the current `LengthToFee` given some input.']}], 'docs': []},
                     {'name': 'NftsApi', 'methods': [
                         {'name': 'owner', 'inputs': [{'name': 'collection', 'type': 4}, {'name': 'item', 'type': 4}],
                          'output': 42, 'docs': []},
                         {'name': 'collection_owner', 'inputs': [{'name': 'collection', 'type': 4}], 'output': 42,
                          'docs': []}, {'name': 'attribute',
                                        'inputs': [{'name': 'collection', 'type': 4}, {'name': 'item', 'type': 4},
                                                   {'name': 'key', 'type': 13}], 'output': 448, 'docs': []},
                         {'name': 'custom_attribute',
                          'inputs': [{'name': 'account', 'type': 0}, {'name': 'collection', 'type': 4},
                                     {'name': 'item', 'type': 4}, {'name': 'key', 'type': 13}], 'output': 448, 'docs': []},
                         {'name': 'system_attribute',
                          'inputs': [{'name': 'collection', 'type': 4}, {'name': 'item', 'type': 4},
                                     {'name': 'key', 'type': 13}], 'output': 448, 'docs': []},
                         {'name': 'collection_attribute',
                          'inputs': [{'name': 'collection', 'type': 4}, {'name': 'key', 'type': 13}], 'output': 448,
                          'docs': []}], 'docs': []}, {'name': 'MmrApi', 'methods': [
            {'name': 'mmr_root', 'inputs': [], 'output': 913, 'docs': [' Return the on-chain MMR root hash.']},
            {'name': 'mmr_leaf_count', 'inputs': [], 'output': 915,
             'docs': [' Return the number of MMR blocks in the chain.']}, {'name': 'generate_proof', 'inputs': [
                {'name': 'block_numbers', 'type': 114}, {'name': 'best_known_block_number', 'type': 38}], 'output': 916,
                                                                           'docs': [
                                                                               ' Generate MMR proof for a series of block numbers. If `best_known_block_number = Some(n)`,',
                                                                               ' use historical MMR state at given block height `n`. Else, use current MMR state.']},
            {'name': 'verify_proof', 'inputs': [{'name': 'leaves', 'type': 918}, {'name': 'proof', 'type': 920}],
             'output': 921, 'docs': [' Verify MMR proof against on-chain MMR for a batch of leaves.', '',
                                     ' Note this function will use on-chain MMR root hash and check if the proof matches the hash.',
                                     ' Note, the leaves should be sorted such that corresponding leaves and leaf indices have the',
                                     ' same position in both the `leaves` vector and the `leaf_indices` vector contained in the [Proof]']},
            {'name': 'verify_proof_stateless',
             'inputs': [{'name': 'root', 'type': 12}, {'name': 'leaves', 'type': 918}, {'name': 'proof', 'type': 920}],
             'output': 921, 'docs': [' Verify MMR proof against given root hash for a batch of leaves.', '',
                                     ' Note this function does not require any on-chain storage - the',
                                     ' proof is verified against given MMR root hash.', '',
                                     ' Note, the leaves should be sorted such that corresponding leaves and leaf indices have the',
                                     ' same position in both the `leaves` vector and the `leaf_indices` vector contained in the [Proof]']}],
                                                      'docs': [' API to interact with MMR pallet.']},
                     {'name': 'SessionKeys', 'methods': [
                         {'name': 'generate_session_keys', 'inputs': [{'name': 'seed', 'type': 448}], 'output': 13,
                          'docs': [' Generate a set of session keys with optionally using the given seed.',
                                   ' The keys should be stored within the keystore exposed via runtime', ' externalities.',
                                   '', ' The seed needs to be a valid `utf8` string.', '',
                                   ' Returns the concatenated SCALE encoded public keys.']},
                         {'name': 'decode_session_keys', 'inputs': [{'name': 'encoded', 'type': 13}], 'output': 922,
                          'docs': [' Decode the given public session keys.', '',
                                   ' Returns the list of public raw public keys + key type.']}],
                      'docs': [' Session keys runtime api.']}]


def get_type_def(name: str, metadata: 'GenericMetadataVersioned'):
    from scalecodec.types import U32, Array, U8, Struct, Text, Vec, Hash, Compact, Tuple, Option, Enum, U64
    from substrateinterface.scale.types import Balance, BlockNumber
    from substrateinterface.scale.account import AccountId
    from substrateinterface.scale.extrinsic import Extrinsic

    ApiId = Array(U8, 8)
    RuntimeVersionApi = Tuple(ApiId, U32)
    RuntimeVersion = Struct(
        spec_name=Text, impl_name=Text, authoring_version=U32, spec_version=U32, impl_version=U32,
        apis=Vec(RuntimeVersionApi), transaction_version=U32, state_version=U8
        )

    si_digest_id = metadata.portable_registry.get_si_type_id("sp_runtime::generic::digest::digest")

    Header = Struct(
        parent_hash=Hash, number=Compact(BlockNumber), state_root=Hash, extrinsics_root=Hash,
        digest=metadata.portable_registry.get_scale_type_def(si_digest_id)
    )

    si_weight_id = metadata.portable_registry.get_si_type_id("sp_weights::weight_v2::Weight")
    if si_weight_id is not None:
        Weight = metadata.portable_registry.get_scale_type_def(si_weight_id)
    else:
        Weight = U64

    InclusionFee = Struct(base_fee=Balance, len_fee=Balance, adjusted_weight_fee=Balance)
    FeeDetails = Struct(inclusion_fee=Option(InclusionFee), tip=Balance)
    DispatchClass = Enum(Normal=None, Operational=None, Mandatory=None)
    RuntimeDispatchInfo = Struct(weight=Weight, class_=DispatchClass, partialFee=Balance)

    try:
        return {
            "AccountId": AccountId(),
            "Index": U32,
            "RuntimeVersion": RuntimeVersion,
            "Header": Header,
            "RuntimeDispatchInfo": RuntimeDispatchInfo,
            "FeeDetails": FeeDetails,
            "Extrinsic": Extrinsic(metadata),
            "u32": U32
        }[name]
    except KeyError:
        raise ValueError(f'Type def for "{name}" not found')
