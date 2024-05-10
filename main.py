import base64
from datetime import datetime, timezone
import json
import subprocess
from stellar_sdk import xdr
from stellar_sdk import parse_transaction_envelope_from_xdr
from stellar_sdk import *

NETWORK = Network.PUBLIC_NETWORK_PASSPHRASE
MAX_VALUE_LENGTH = 104


def summary(s: str, left: int = 0, right: int = 0):
    return f"{s[: left]}..{s[-right:]}"


def printable_asset(asset: Asset):
    if asset.type == "native":
        return "XLM"
    else:
        return f"{asset.code}@{summary(asset.issuer, 3, 4)}"


def printable_asset_amount(asset: Asset, amount: str):
    return f"{add_separators(amount)} {printable_asset(asset)}"


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
                    v = f"{s[:MAX_VALUE_LENGTH // 2]}..{s[-MAX_VALUE_LENGTH // 2:]}"
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

    def format_op_payment(self, op: Payment):
        self.add(f"Send; {printable_asset_amount(op.asset, op.amount)}")
        self.add(f"Destination; {op.destination.universal_account_id}")
        self.format_op_source(op.source)

    def format_operation(self, op: Operation):
        if isinstance(op, Payment):
            self.format_op_payment(op)
        elif isinstance(op, InvokeHostFunction):
            self.format_op_invoke_host_function(op)

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
            self.format_operation(op)

    def format_network(self, network: str):
        if network == Network.PUBLIC_NETWORK_PASSPHRASE:
            # self.add("Network; Public")
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
        print(f"Error executing command: {e}")
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
    if resp_c != resp_py:
        print(resp_c)
        print(resp_py)
        print(te.to_xdr())

if __name__ == "__main__":
    with open("./soroban_txs.json", "r") as f:
        records = json.load(f)
        for idx, item in enumerate(records):
            tx_envelope = item['tx_envelope']
            te = TransactionEnvelope.from_xdr(tx_envelope, Network.PUBLIC_NETWORK_PASSPHRASE)
            compare_output(te)
