import base64
from datetime import datetime, timezone
import json
import subprocess
from stellar_sdk import xdr
from stellar_sdk import parse_transaction_envelope_from_xdr
from stellar_sdk import *
from stellar_sdk.operation.revoke_sponsorship import RevokeSponsorshipType

NETWORK = Network.PUBLIC_NETWORK_PASSPHRASE
MAX_VALUE_LENGTH = 104


def summary(s: str, left: int = 0, right: int = 0):
    return f"{s[: left]}..{s[-right:]}"


def printable_asset(asset: Asset):
    if asset.type == "native":
        return "XLM"
    else:
        return f"{asset.code}@{summary(asset.issuer, 3, 4)}"


def printable_price(p: Price):
    return add_separators(f"{p.n / p.d:.7f}")


def printable_asset_amount(asset: Asset, amount: str):
    return f"{add_separators(amount)} {printable_asset(asset)}"


def printable_authorization_flag(flag: AuthorizationFlag):
    out = []
    if flag & AuthorizationFlag.AUTHORIZATION_REQUIRED:
        out.append("AUTH_REQUIRED")
    if flag & AuthorizationFlag.AUTHORIZATION_REVOCABLE:
        out.append("AUTH_REVOCABLE")
    if flag & AuthorizationFlag.AUTHORIZATION_IMMUTABLE:
        out.append("AUTH_IMMUTABLE")
    if flag & AuthorizationFlag.AUTHORIZATION_CLAWBACK_ENABLED:
        out.append("AUTH_CLAWBACK_ENABLED")
    return ", ".join(out)


def printable_trust_line_entry_flag(flag: TrustLineEntryFlag):
    out = []
    if flag & TrustLineEntryFlag.AUTHORIZED_FLAG:
        out.append("AUTHORIZED")
    if flag & TrustLineEntryFlag.AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG:
        out.append("AUTHORIZED_TO_MAINTAIN_LIABILITIES")
    if flag & TrustLineEntryFlag.UNAUTHORIZED_FLAG:
        out.append("UNAUTHORIZED")
    return ", ".join(out)


# TrustLineFlags
def printable_trust_line_flag(flag: TrustLineFlags):
    out = []
    if flag & TrustLineFlags.AUTHORIZED_FLAG:
        out.append("AUTHORIZED")
    if flag & TrustLineFlags.AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG:
        out.append("AUTHORIZED_TO_MAINTAIN_LIABILITIES")
    if flag & TrustLineFlags.TRUSTLINE_CLAWBACK_ENABLED_FLAG:
        out.append("TRUSTLINE_CLAWBACK_ENABLED")
    return ", ".join(out)


def is_printable_binary(data: bytes) -> bool:
    for byte in data:
        if byte > 0x7E or byte < 0x20:
            return False
    return True


def add_separators(number_string: int | str, separator: str = ",") -> str:
    if isinstance(number_string, int):
        number_string = str(number_string)
    parts = number_string.split(".")
    integer_part = parts[0]
    decimal_part = parts[1] if len(parts) > 1 else ""
    integer_part = f"{int(integer_part):,}"
    if decimal_part:
        return f"{integer_part}.{decimal_part}"
    else:
        return integer_part


def timestamp_to_utc_string(timestamp: int) -> str:
    utc_time = datetime.fromtimestamp(timestamp, timezone.utc)
    return utc_time.strftime("%Y-%m-%d %H:%M:%S")


class Formatter:
    def __init__(self, te: TransactionEnvelope):
        self.lines = []
        self.te = te

    def add(self, line):
        self.lines.append(line)

    def format_tx_source(self, tx_source: MuxedAccount):
        # Here is inconsistent with libstellar.
        self.add(f"Tx Source; {tx_source.universal_account_id}")

    def format_op_source(self, op_source: MuxedAccount):
        # Here is inconsistent with libstellar.
        if op_source:
            self.add(f"Op Source; {op_source.universal_account_id}")

    def format_min_seq_ledger_gap(self, min_seq_ledger_gap: int):
        if min_seq_ledger_gap:
            self.add(f"Min Seq Ledger Gap; {min_seq_ledger_gap}")

    def format_min_seq_age(self, min_seq_age: int):
        if min_seq_age:
            self.add(f"Min Seq Age; {min_seq_age}")

    def format_min_seq_num(self, min_seq_num: int):
        if min_seq_num:
            self.add(f"Min Seq Num; {min_seq_num}")

    def format_ledger_bounds(self, ledger_bounds: LedgerBounds):
        if not ledger_bounds:
            return
        if ledger_bounds.min_ledger:
            self.add(f"Ledger Bounds Min; {ledger_bounds.min_ledger}")
        if ledger_bounds.max_ledger:
            self.add(f"Ledger Bounds Max; {ledger_bounds.max_ledger}")

    def format_time_bounds(self, time_bounds: TimeBounds):
        if not time_bounds:
            return
        if time_bounds.min_time:
            self.add(
                f"Valid After (UTC); {timestamp_to_utc_string(time_bounds.min_time)}"
            )
        if time_bounds.max_time:
            self.add(
                f"Valid Before (UTC); {timestamp_to_utc_string(time_bounds.max_time)}"
            )

    def format_preconditions(self, preconditions: Preconditions):
        self.format_time_bounds(preconditions.time_bounds)
        self.format_ledger_bounds(preconditions.ledger_bounds)
        self.format_min_seq_num(preconditions.min_sequence_number)
        self.format_min_seq_age(preconditions.min_sequence_age)
        self.format_min_seq_ledger_gap(preconditions.min_sequence_ledger_gap)

    def format_fee(self, fee: int):
        # assume we are in public network
        self.add(f"Max Fee; {Operation.from_xdr_amount(fee)} XLM")

    def format_sequence(self, sequence: int):
        self.add(f"Sequence Num; {sequence}")

    def format_memo(self, memo: Memo):
        if isinstance(memo, NoneMemo):
            pass
        elif isinstance(memo, TextMemo):
            if is_printable_binary(memo.memo_text):
                self.add(f"Memo Text; {memo.memo_text.decode()}")
            else:
                self.add(f"Memo Text; Base64: {base64.b64encode(memo.memo_text)}")
        elif isinstance(memo, IdMemo):
            self.add(f"Memo ID; {memo.memo_id}")
        elif isinstance(memo, HashMemo):
            self.add(f"Memo Hash; {memo.memo_hash.upper()}")
        elif isinstance(memo, ReturnHashMemo):
            self.add(f"Memo Return; {memo.memo_return.upper()}")
        else:
            raise ValueError("Unknown memo type")

    def format_sc_val(self, arg: xdr.SCVal, args_len: int, index: int):
        title = f"Arg {index + 1} of {args_len}"

        if arg.type == xdr.SCValType.SCV_BOOL:
            self.add(f"{title}; {'true' if arg.b else 'false'}")
        if arg.type == xdr.SCValType.SCV_VOID:
            return self.add(f"{title}; [void]")
        if arg.type == xdr.SCValType.SCV_ERROR:
            # not implemented in libstellar
            return self.add(f"{title}; [error]")
        if arg.type == xdr.SCValType.SCV_U32:
            self.add(f"{title}; {add_separators(scval.from_uint32(arg))}")
        if arg.type == xdr.SCValType.SCV_I32:
            self.add(f"{title}; {add_separators(scval.from_int32(arg))}")
        if arg.type == xdr.SCValType.SCV_U64:
            self.add(f"{title}; {add_separators(scval.from_uint64(arg))}")
        if arg.type == xdr.SCValType.SCV_I64:
            self.add(f"{title}; {add_separators(scval.from_int64(arg))}")
        if arg.type == xdr.SCValType.SCV_TIMEPOINT:
            self.add(f"{title}; {timestamp_to_utc_string(scval.from_timepoint(arg))}")
        if arg.type == xdr.SCValType.SCV_DURATION:
            self.add(f"{title}; {add_separators(scval.from_duration(arg))}")
        if arg.type == xdr.SCValType.SCV_U128:
            self.add(f"{title}; {add_separators(scval.from_uint128(arg))}")
        if arg.type == xdr.SCValType.SCV_I128:
            self.add(f"{title}; {add_separators(scval.from_int128(arg))}")
        if arg.type == xdr.SCValType.SCV_U256:
            self.add(f"{title}; {add_separators(scval.from_uint256(arg))}")
        if arg.type == xdr.SCValType.SCV_I256:
            self.add(f"{title}; {add_separators(scval.from_int256(arg))}")
        if arg.type == xdr.SCValType.SCV_BYTES:
            self.add(f"{title}; [Bytes Data]")
        if arg.type == xdr.SCValType.SCV_STRING:
            s = scval.from_string(arg)
            if not s:
                self.add("[empty string]")
                return
            if is_printable_binary(s):
                if len(s) <= MAX_VALUE_LENGTH:
                    self.add(f"{title}; {s.decode()}")
                else:
                    v = f"{s.decode()[:MAX_VALUE_LENGTH // 2]}..{s.decode()[-(MAX_VALUE_LENGTH // 2) + 2:]}"
                    self.add(f"{title}; {v}")
            else:
                self.add("[unprintable string]")

        if arg.type == xdr.SCValType.SCV_SYMBOL:
            self.add(f"{title}; {scval.from_symbol(arg)}")
        if arg.type == xdr.SCValType.SCV_VEC:
            self.add(f"{title}; [unable to display]")
        if arg.type == xdr.SCValType.SCV_MAP:
            self.add(f"{title}; [unable to display]")
        if arg.type == xdr.SCValType.SCV_ADDRESS:
            self.add(f"{title}; {scval.from_address(arg).address}")
        if arg.type == xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE:
            self.add(f"{title}; [unable to display]")
        if arg.type == xdr.SCValType.SCV_LEDGER_KEY_NONCE:
            self.add(f"{title}; [unable to display]")
        if arg.type == xdr.SCValType.SCV_CONTRACT_INSTANCE:
            self.add(f"{title}; [unable to display]")

    def sub_invocation_count(self, sub_invocation: xdr.SorobanAuthorizedInvocation):
        count = 0
        for sub in sub_invocation.sub_invocations:
            count += 1
            count += self.sub_invocation_count(sub)
        return count

    def format_sub_invocation(
            self,
            sub_invocation: xdr.SorobanAuthorizedInvocation,
            current_index: int,
            auth_count: int,
    ) -> int:
        current_index += 1
        self.add(f"Nested Authorization; {current_index} of {auth_count}")

        if (
                sub_invocation.function.type
                == xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN
        ):
            self.add("Soroban; Invoke Smart Contract")
            self.add(
                f"Contract ID; {Address.from_xdr_sc_address(sub_invocation.function.contract_fn.contract_address).address}"
            )
            self.add(
                f"Function; {sub_invocation.function.contract_fn.function_name.sc_symbol.decode()}"
            )
            for index, arg in enumerate(sub_invocation.function.contract_fn.args):
                self.format_sc_val(
                    arg, len(sub_invocation.function.contract_fn.args), index
                )
        else:
            self.add("Soroban; Create Smart Contract")

        for sub in sub_invocation.sub_invocations:
            current_index = self.format_sub_invocation(sub, current_index, auth_count)
        return current_index

    def format_op_invoke_host_function(self, op: InvokeHostFunction):
        if (
                op.host_function.type
                == xdr.HostFunctionType.HOST_FUNCTION_TYPE_CREATE_CONTRACT
        ):
            self.add("Soroban; Create Smart Contract")
            self.format_op_source(op.source)
        elif (
                op.host_function.type
                == xdr.HostFunctionType.HOST_FUNCTION_TYPE_UPLOAD_CONTRACT_WASM
        ):
            self.add("Soroban; Upload Smart Contract Wasm")
            self.format_op_source(op.source)
        elif (
                op.host_function.type
                == xdr.HostFunctionType.HOST_FUNCTION_TYPE_INVOKE_CONTRACT
        ):
            self.add("Soroban; Invoke Smart Contract")
            self.add(
                f"Contract ID; {Address.from_xdr_sc_address(op.host_function.invoke_contract.contract_address).address}"
            )
            self.add(
                f"Function; {op.host_function.invoke_contract.function_name.sc_symbol.decode()}"
            )
            for index, arg in enumerate(op.host_function.invoke_contract.args):
                self.format_sc_val(
                    arg, len(op.host_function.invoke_contract.args), index
                )
            self.format_op_source(op.source)

            auth_count = 0
            for auth in op.auth:
                if (
                        auth.credentials.type
                        != xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT
                ):
                    continue
                for sub in auth.root_invocation.sub_invocations:
                    auth_count += 1
                    auth_count += self.sub_invocation_count(sub)

            auth_index = 0
            for auth in op.auth:
                if (
                        auth.credentials.type
                        == xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT
                ):
                    for sub in auth.root_invocation.sub_invocations:
                        auth_index = self.format_sub_invocation(
                            sub, auth_index, auth_count
                        )
        else:
            raise ValueError("Unknown host function type")

    def format_op_create_account(self, op: CreateAccount):
        self.add(f"Operation Type; Create Account")
        self.add(f"Destination; {op.destination}")
        self.add(
            f"Starting Balance; {printable_asset_amount(Asset.native(), op.starting_balance)}"
        )
        self.format_op_source(op.source)

    def format_op_path_payment_strict_receive(self, op: PathPaymentStrictReceive):
        self.add(f"Send Max; {printable_asset_amount(op.send_asset, op.send_max)}")
        self.add(f"Destination; {op.destination.universal_account_id}")
        self.add(f"Receive; {printable_asset_amount(op.dest_asset, op.dest_amount)}")
        self.format_op_source(op.source)

    def format_op_path_payment_strict_send(self, op: PathPaymentStrictSend):
        self.add(f"Send; {printable_asset_amount(op.send_asset, op.send_amount)}")
        self.add(f"Destination; {op.destination.universal_account_id}")
        self.add(f"Receive Min; {printable_asset_amount(op.dest_asset, op.dest_min)}")
        self.format_op_source(op.source)

    def format_op_manage_sell_offer(self, op: ManageSellOffer):
        if op.amount == "0":
            self.add("Delete Offer; {op.offer_id}")
        else:
            if op.offer_id == 0:
                self.add("Create Offer; Type Active")
            else:
                self.add("Change Offer; {op.offer_id}")
            self.add(f"Buy; {printable_asset(op.buying)}")
            self.add(f"Sell; {printable_asset_amount(op.selling, op.amount)}")
            buying_asset_code = op.buying.code if op.buying.type != 'native' else 'XLM'
            selling_asset_code = op.selling.code if op.selling.type != 'native' else 'XLM'
            self.add(f"Price; {printable_price(op.price)} {buying_asset_code}/{selling_asset_code}")
        self.format_op_source(op.source)

    def format_op_create_passive_sell_offer(self, op: CreatePassiveSellOffer):
        self.add("Operation Type; Create Passive Sell Offer")
        self.add(f"Buy; {printable_asset(op.buying)}")
        self.add(f"Sell; {printable_asset_amount(op.selling, op.amount)}")
        buying_asset_code = op.buying.code if op.buying.type != 'native' else 'XLM'
        selling_asset_code = op.selling.code if op.selling.type != 'native' else 'XLM'
        self.add(f"Price; {printable_price(op.price)} {buying_asset_code}/{selling_asset_code}")
        self.format_op_source(op.source)

    def format_op_manage_buy_offer(self, op: ManageBuyOffer):
        if op.amount == "0":
            self.add("Delete Offer; {op.offer_id}")
        else:
            if op.offer_id == 0:
                self.add("Create Offer; Type Active")
            else:
                self.add("Change Offer; {op.offer_id}")
            self.add(f"Sell; {printable_asset(op.selling)}")
            self.add(f"Buy; {printable_asset_amount(op.buying, op.amount)}")
            buying_asset_code = op.buying.code if op.buying.type != 'native' else 'XLM'
            selling_asset_code = op.selling.code if op.selling.type != 'native' else 'XLM'
            self.add(f"Price; {printable_price(op.price)} {selling_asset_code}/{buying_asset_code}")
        self.format_op_source(op.source)

    def format_change_trust(self, op: ChangeTrust):
        if op.limit == "0":
            title = "Remove Trust"
        else:
            title = "Change Trust"
        if isinstance(op.asset, Asset):
            self.add(f"{title}; {printable_asset(op.asset)}")
            self.add(f"Trust Limit; {add_separators(op.limit)}")
        else:
            self.add(f"{title}; Liquidity Pool Asset")
            self.add(f"Asset A; {printable_asset(op.asset.asset_a)}")
            self.add(f"Asset B; {printable_asset(op.asset.asset_b)}")
            self.add(f"Pool Fee Rate; 0.3%")
            self.add(f"Trust Limit; {add_separators(op.limit)}")
        self.format_op_source(op.source)

    def format_op_allow_trust(self, op: AllowTrust):
        self.add("Operation Type; Allow Trust")
        self.add(f"Trustor; {op.trustor}")
        self.add(f"Asset Code: {op.asset_code}")
        self.add(f"Authorize Flag; {printable_trust_line_entry_flag(op.authorize)}")
        self.format_op_source(op.source)

    def format_op_account_merge(self, op: AccountMerge, tx_source: MuxedAccount):
        self.add("Operation Type; Account Merge")
        if op.source:
            self.add(f"Merge Account; {op.source.universal_account_id}")
        else:
            self.add(f"Merge Account; {tx_source.universal_account_id}")
        self.add(f"Destination; {op.destination}")
        self.format_op_source(op.source)

    def format_op_bump_sequence(self, op: BumpSequence):
        self.add("Operation Type; Bump Sequence")
        self.add(f"Bump To; {op.bump_to}")
        self.format_op_source(op.source)

    def format_op_extend_footprint_ttl(self, op: ExtendFootprintTTL):
        self.add("Operation Type; Extend Footprint TTL")
        self.format_op_source(op.source)

    def format_op_restore_footprint(self, op: RestoreFootprint):
        self.add("Operation Type; Restore Footprint")
        self.format_op_source(op.source)

    def format_op_clawback(self, op: Clawback):
        self.add("Operation Type; Clawback")
        self.add(f"Clawback Balance; {printable_asset_amount(op.asset, op.amount)}")
        self.add(f"From; {op.from_.universal_account_id}")
        self.format_op_source(op.source)

    def format_op_begin_sponsoring_future_reserves(
            self, op: BeginSponsoringFutureReserves
    ):
        self.add("Operation Type; Begin Sponsoring Future Reserves")
        self.add(f"Sponsored ID; {op.sponsored_id}")
        self.format_op_source(op.source)

    def format_op_end_sponsoring_future_reserves(self, op: EndSponsoringFutureReserves):
        self.add("Operation Type; End Sponsoring Future Reserves")
        self.format_op_source(op.source)

    def format_op_payment(self, op: Payment):
        self.add(f"Send; {printable_asset_amount(op.asset, op.amount)}")
        self.add(f"Destination; {op.destination.universal_account_id}")
        self.format_op_source(op.source)

    def format_op_clawback_claimable_balance(self, op: ClawbackClaimableBalance):
        self.add("Operation Type; Clawback Claimable Balance")
        self.add(f"Balance ID; {summary(op.balance_id, 12, 12)}")
        self.format_op_source(op.source)

    def format_op_claim_claimable_balance(self, op: ClaimClaimableBalance):
        self.add("Operation Type; Claim Claimable Balance")
        self.add(f"Balance ID; {summary(op.balance_id, 12, 12)}")
        self.format_op_source(op.source)

    def format_op_liquidity_pool_deposit(self, op: LiquidityPoolDeposit):
        self.add("Operation Type; Liquidity Pool Deposit")
        self.add(f"Liquidity Pool ID; {op.liquidity_pool_id}")
        self.add(f"Max Amount A; {add_separators(op.max_amount_a)}")
        self.add(f"Max Amount B; {add_separators(op.max_amount_b)}")
        self.add(f"Min Price; {printable_price(op.min_price)}")
        self.add(f"Max Price; {printable_price(op.max_price)}")
        self.format_op_source(op.source)

    def format_op_liquidity_pool_withdraw(self, op: LiquidityPoolWithdraw):
        self.add("Operation Type; Liquidity Pool Withdraw")
        self.add(f"Liquidity Pool ID; {op.liquidity_pool_id}")
        self.add(f"Amount; {add_separators(op.amount)}")
        self.add(f"Min Amount A; {add_separators(op.min_amount_a)}")
        self.add(f"Min Amount B; {add_separators(op.min_amount_b)}")
        self.format_op_source(op.source)

    def format_op_set_options(self, op: SetOptions):
        self.add("Operation Type; Set Options")
        is_empty_body = True
        if op.inflation_dest is not None:
            self.add(f"Inflation Dest; {op.inflation_dest}")
            is_empty_body = False
        if op.clear_flags is not None:
            self.add(f"Clear Flags; {printable_authorization_flag(op.clear_flags)}")
            is_empty_body = False
        if op.set_flags is not None:
            self.add(f"Set Flags; {printable_authorization_flag(op.set_flags)}")
            is_empty_body = False
        if op.master_weight is not None:
            self.add(f"Master Weight; {op.master_weight}")
            is_empty_body = False
        if op.low_threshold is not None:
            self.add(f"Low Threshold; {op.low_threshold}")
            is_empty_body = False
        if op.med_threshold is not None:
            self.add(f"Medium Threshold; {op.med_threshold}")
            is_empty_body = False
        if op.high_threshold is not None:
            self.add(f"High Threshold; {op.high_threshold}")
            is_empty_body = False
        if op.home_domain is not None:
            if op.home_domain == "":
                self.add("Home Domain; [remove home domain from account]")
            else:
                self.add(f"Home Domain; {op.home_domain}")
            is_empty_body = False
        if op.signer is not None:
            if op.signer.weight:
                title = "Add Signer"
            else:
                title = "Remove Signer"
            if op.signer.signer_key.signer_key_type == xdr.SignerKeyType.SIGNER_KEY_TYPE_ED25519:
                self.add(f"{title}; Type Public Key")
            elif op.signer.signer_key.signer_key_type == xdr.SignerKeyType.SIGNER_KEY_TYPE_HASH_X:
                self.add(f"{title}; Type Hash(x)")
            elif op.signer.signer_key.signer_key_type == xdr.SignerKeyType.SIGNER_KEY_TYPE_PRE_AUTH_TX:
                self.add(f"{title}; Type Pre-Auth")
            elif op.signer.signer_key.signer_key_type == xdr.SignerKeyType.SIGNER_KEY_TYPE_ED25519_SIGNED_PAYLOAD:
                self.add(f"{title}; Type Ed25519 Signed Payload")
            else:
                raise ValueError("Unknown signer key type")
            if op.signer.signer_key.signer_key_type == xdr.SignerKeyType.SIGNER_KEY_TYPE_ED25519_SIGNED_PAYLOAD:
                self.add(f"Signer Key; {summary(op.signer.signer_key.encoded_signer_key, 12, 12)}")
            else:
                self.add(f"Signer Key; {op.signer.signer_key.encoded_signer_key}")

            is_empty_body = False
        if is_empty_body:
            self.add("SET_OPTIONS; [BODY IS EMPTY]")
        self.format_op_source(op.source)

    def format_op_set_trust_line_flags(self, op: SetTrustLineFlags):
        self.add("Operation Type; Set Trust Line Flags")
        self.add(f"Trustor; {op.trustor}")
        self.add(f"Asset: {printable_asset(op.asset)}")
        if op.clear_flags:
            self.add(f"Clear Flags; {printable_trust_line_flag(op.clear_flags)}")
        else:
            self.add("Clear Flags; [none]")
        if op.set_flags:
            self.add(f"Set Flags; {printable_trust_line_flag(op.set_flags)}")
        else:
            self.add("Set Flags; [none]")
        self.format_op_source(op.source)

    def format_op_manage_data(self, op: ManageData):
        if op.data_value is None:
            self.add(f"Remove Data; {op.data_name}")
        else:
            self.add(f"Set Data; {op.data_name}")
            if is_printable_binary(op.data_value):
                self.add(f"Data Value; {op.data_value.decode()}")
            else:
                self.add(f"Data Value; Base64: {base64.b64encode(op.data_value)}")
        self.format_op_source(op.source)

    def format_op_create_claimable_balance(self, op: CreateClaimableBalance):
        self.add("Operation Type; Create Claimable Balance")
        self.add(f"Balance; {printable_asset_amount(op.asset, op.amount)}")
        self.add(f"WARNING; Currently does not support displaying claimant details")
        self.format_op_source(op.source)

    def format_op_revoke_sponsorship(self, op: RevokeSponsorship):
        if op.revoke_sponsorship_type == RevokeSponsorshipType.SIGNER:
            self.add("Operation Type; Revoke Sponsorship (SIGNER_KEY)")
            self.add(f"Account ID; {op.signer.account_id}")
            if op.signer.signer_key.signer_key_type == xdr.SignerKeyType.SIGNER_KEY_TYPE_ED25519:
                self.add("Signer Key Type; Public Key")
            elif op.signer.signer_key.signer_key_type == xdr.SignerKeyType.SIGNER_KEY_TYPE_HASH_X:
                self.add("Signer Key Type; Hash(x)")
            elif op.signer.signer_key.signer_key_type == xdr.SignerKeyType.SIGNER_KEY_TYPE_PRE_AUTH_TX:
                self.add("Signer Key Type; Pre-Auth")
            elif op.signer.signer_key.signer_key_type == xdr.SignerKeyType.SIGNER_KEY_TYPE_ED25519_SIGNED_PAYLOAD:
                self.add("Signer Key Type; Ed25519 Signed Payload")
            if op.signer.signer_key.signer_key_type == xdr.SignerKeyType.SIGNER_KEY_TYPE_ED25519_SIGNED_PAYLOAD:
                self.add(f"Signer Key; {summary(op.signer.signer_key.encoded_signer_key, 12, 12)}")
            else:
                self.add(f"Signer Key; {op.signer.signer_key.encoded_signer_key}")
        elif op.revoke_sponsorship_type == RevokeSponsorshipType.ACCOUNT:
            self.add("Operation Type; Revoke Sponsorship (ACCOUNT)")
            self.add(f"Account ID; {op.account_id}")
        elif op.revoke_sponsorship_type == RevokeSponsorshipType.OFFER:
            self.add("Operation Type; Revoke Sponsorship (OFFER)")
            self.add(f"Seller ID; {op.offer.seller_id}")
            self.add(f"Offer ID; {op.offer.offer_id}")
        elif op.revoke_sponsorship_type == RevokeSponsorshipType.TRUSTLINE:
            self.add("Operation Type; Revoke Sponsorship (TRUSTLINE)")
            self.add(f"Account ID; {op.trustline.account_id}")
            if isinstance(op.trustline.asset, Asset):
                self.add(f"Asset; {printable_asset(op.trustline.asset)}")
            else:
                self.add(f"Liquidity Pool ID; {op.trustline.asset.liquidity_pool_id}")
        elif op.revoke_sponsorship_type == RevokeSponsorshipType.DATA:
            self.add("Operation Type; Revoke Sponsorship (DATA)")
            self.add(f"Account ID; {op.data.account_id}")
            self.add(f"Data Name; {op.data.data_name}")
        elif op.revoke_sponsorship_type == RevokeSponsorshipType.CLAIMABLE_BALANCE:
            self.add("Operation Type; Revoke Sponsorship (CLAIMABLE_BALANCE)")
            self.add(f"Balance ID; {op.claimable_balance_id}")
        elif op.revoke_sponsorship_type == RevokeSponsorshipType.LIQUIDITY_POOL:
            self.add("Operation Type; Revoke Sponsorship (LIQUIDITY_POOL)")
            self.add(f"Liquidity Pool ID; {op.liquidity_pool_id}")
        else:
            raise ValueError("Unknown revoke sponsorship type")

        self.format_op_source(op.source)

    def format_operation(self, op: Operation, tx_source: MuxedAccount):
        if isinstance(op, CreateAccount):
            self.format_op_create_account(op)
        elif isinstance(op, Payment):
            self.format_op_payment(op)
        elif isinstance(op, PathPaymentStrictReceive):
            self.format_op_path_payment_strict_receive(op)
        elif isinstance(op, ManageSellOffer):
            self.format_op_manage_sell_offer(op)
        elif isinstance(op, CreatePassiveSellOffer):
            self.format_op_create_passive_sell_offer(op)
        elif isinstance(op, SetOptions):
            self.format_op_set_options(op)
        elif isinstance(op, ChangeTrust):
            self.format_change_trust(op)
        elif isinstance(op, AllowTrust):
            self.format_op_allow_trust(op)
        elif isinstance(op, AccountMerge):
            self.format_op_account_merge(op, tx_source)
        elif isinstance(op, Inflation):
            raise ValueError("Inflation operation is not supported")
        elif isinstance(op, ManageData):
            self.format_op_manage_data(op)
        elif isinstance(op, BumpSequence):
            self.format_op_bump_sequence(op)
        elif isinstance(op, ManageBuyOffer):
            self.format_op_manage_buy_offer(op)
        elif isinstance(op, PathPaymentStrictSend):
            self.format_op_path_payment_strict_send(op)
        elif isinstance(op, CreateClaimableBalance):
            self.format_op_create_claimable_balance(op)
        elif isinstance(op, ClaimClaimableBalance):
            self.format_op_claim_claimable_balance(op)
        elif isinstance(op, BeginSponsoringFutureReserves):
            self.format_op_begin_sponsoring_future_reserves(op)
        elif isinstance(op, EndSponsoringFutureReserves):
            self.format_op_end_sponsoring_future_reserves(op)
        elif isinstance(op, RevokeSponsorship):
            self.format_op_revoke_sponsorship(op)
        elif isinstance(op, Clawback):
            self.format_op_clawback(op)
        elif isinstance(op, ClawbackClaimableBalance):
            self.format_op_clawback_claimable_balance(op)
        elif isinstance(op, SetTrustLineFlags):
            self.format_op_set_trust_line_flags(op)
        elif isinstance(op, LiquidityPoolDeposit):
            self.format_op_liquidity_pool_deposit(op)
        elif isinstance(op, LiquidityPoolWithdraw):
            self.format_op_liquidity_pool_withdraw(op)
        elif isinstance(op, InvokeHostFunction):
            self.format_op_invoke_host_function(op)
        elif isinstance(op, ExtendFootprintTTL):
            self.format_op_extend_footprint_ttl(op)
        elif isinstance(op, RestoreFootprint):
            self.format_op_restore_footprint(op)
        else:
            raise ValueError("Unknown operation type")

    def format_transaction(self, tx: Transaction):
        self.format_memo(tx.memo)
        self.format_fee(tx.fee)
        self.format_sequence(tx.sequence)
        if tx.preconditions:
            self.format_preconditions(tx.preconditions)
        self.format_tx_source(tx.source)
        for index, op in enumerate(tx.operations):
            if len(tx.operations) > 1:
                self.add(f"Operation {index + 1} of {len(tx.operations)}")
            self.format_operation(op, tx.source)

    def format_network(self, network: str):
        if network == Network.PUBLIC_NETWORK_PASSPHRASE:
            pass
        elif network == Network.TESTNET_NETWORK_PASSPHRASE:
            self.add("Network: Testnet")
        else:
            self.add("Network: Unknown")

    def format_transaction_envelope(self):
        self.format_network(self.te.network_passphrase)
        self.format_transaction(self.te.transaction)

    def get_formatted(self):
        return "\n".join(self.lines)


def execute_command(command):
    try:
        output = subprocess.check_output(command, shell=True, universal_newlines=True)
        return output.strip()
    except subprocess.CalledProcessError as e:
        # print(f"Error executing command: {e}")
        return None


def format_with_c(te: TransactionEnvelope):
    data = base64.b64encode(te.signature_base()).decode()
    command = f"./build/test_tx_formatter {data}"
    output = execute_command(command)
    return output


def compare_output(te: TransactionEnvelope):
    resp_c = format_with_c(te)
    formatter = Formatter(te)
    formatter.format_transaction_envelope()
    resp_py = formatter.get_formatted()
    return resp_c == resp_py, resp_c, resp_py


if __name__ == "__main__":
    with open("./soroban_txs.json", "r") as f:
        records = json.load(f)
        for idx, item in enumerate(records):
            tx_envelope = item["tx_envelope"]
            te = TransactionEnvelope.from_xdr(
                tx_envelope, Network.PUBLIC_NETWORK_PASSPHRASE
            )
            print("Processing tx:", idx + 1)
            eq, resp_c, resp_py = compare_output(te)
            if not eq:
                print(te.to_xdr())
                print("-" * 24)
                print(base64.b64encode(te.signature_base()).decode())
                print("-" * 24)
                print(resp_c)
                print("-" * 24)
                print(resp_py)
                raise ValueError("Output mismatch")
