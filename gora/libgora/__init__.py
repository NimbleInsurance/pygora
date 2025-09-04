import sys
import os
import hashlib
import base64
import time
import struct
import json
import logging
import subprocess
import enum
from pathlib import Path
import algosdk as asdk
from algosdk import encoding, logic
from algosdk.transaction import *
from algosdk.atomic_transaction_composer import *

logger = logging.getLogger(__name__)

if "GORA_DEV_VER" not in os.environ:
    os.environ["GORA_DEV_VER"] = "latest-dqs"

# Aggregation values
class Aggr(enum.IntEnum):
    NONE = 0
    MIN = 1
    MAX = 2
    AVG = 3


cli_tool_ver = os.getenv("GORA_DEV_VER", "latest-release")
cli_tool_url = f'https://download.gora.io/{cli_tool_ver}/linux/gora'
dev_node_docker_name = "gora-nr-dev"

script_dir, script_file = os.path.split(os.path.abspath(__file__))
gora_main_abi_spec = open(script_dir + "/main-contract.json", "r").read()
gora_main_app = asdk.abi.Contract.from_json(gora_main_abi_spec)


"""
Run Gora CLI tool.
"""
def run_cli(cli_cmd, args = [], env = {}, is_rt = False, cwd = None):
    cli_tool_path = os.getenv("GORA_DEV_CLI_TOOL", "./gora_cli")
    
    cmd = [ cli_tool_path, cli_cmd, *args ]
    logger.info(f'Running: "{" ".join(cmd)}"')
    passed_env = { **os.environ, **env }
    if is_rt:
        return subprocess.run(cmd, env=passed_env, cwd=cwd)
    else:
        return subprocess.check_output(cmd, env=passed_env, cwd=cwd, text=True)


class Config(object):
    GORA_HOME = Path.home() / ".gora"
    GORA_CONFIG_FILE = GORA_HOME / ".gora"

    def __init__(self, create_if_not_exists=False):
        do_setup = ''
        
        if not Config.GORA_CONFIG_FILE.exists():
            if sys.stdin.isatty():
                do_setup = input("Valid configuration not found.  Initialize gora setup now [Y/N]? ")

            if create_if_not_exists or do_setup.lower()[0]=="y":
                if not Config.GORA_HOME.exists():
                    Config.GORA_HOME.mkdir()
                self.create_dev_config()

        self.load_config()

    def load_config(self):
        with open(Config.GORA_CONFIG_FILE) as cfin:
            self.local_cfg = json.load(cfin)
            self.main_app_info = {}

        gora_net_cfg = self.local_cfg["blockchain"]["perNetworkConfig"]["override"]
        self.main_app_info["id"] = gora_net_cfg["appIds"]["main"]
        logger.info("Main app ID:" + str(self.main_app_info["id"]))

        self.main_app_info["addr"] = logic.get_application_address(self.main_app_info["id"])
        addr_decoded = base64.b32decode(self.main_app_info["addr"] + "======")
        self.main_app_info["addr_bin"] = addr_decoded[:-4] # remove CRC

    @staticmethod
    def create_dev_config():
        if Config.GORA_CONFIG_FILE.exists():
            os.remove(Config.GORA_CONFIG_FILE)

        server = ':'.join([os.getenv("ALGOD_SERVER", "localhost"),os.getenv("ALGOD_PORT",4001)])
        return run_cli(
            "dev-init",
            [ "--dest-server", server ],
            { "GORA_CONFIG_FILE": Config.GORA_CONFIG_FILE },
            True,
            Config.GORA_HOME
        )

    def __getattr__(self, key):
        return self.main_app_info[key]


"""
Return Gora token asset ID
"""
def get_token_asset_id(algod_client):
    config = Config()
    acc_info = algod_client.account_info(config.addr)
    return acc_info["assets"][0]["asset-id"]

"""
Setup an Algo deposit with Gora for a given account and app.
"""
def setup_algo_deposit(
        algod_client,
        payer_account,
        app_addr,
        algo_deposit_amount=20_000_000
):
    logger.info(f"Setting up ALGO deposit with Gora (amount: {algo_deposit_amount})")

    config = Config()
    composer = AtomicTransactionComposer()
    unsigned_payment_txn = PaymentTxn(
        sender=payer_account.address,
        sp=algod_client.suggested_params(),
        receiver=logic.get_application_address(config.id),
        amt=algo_deposit_amount,
    )
    
    signer = AccountTransactionSigner(payer_account.private_key)
    signed_payment_txn = TransactionWithSigner(
        unsigned_payment_txn,
        signer
    )
    
    composer.add_method_call(
        app_id=config.id,
        method=gora_main_app.get_method_by_name("deposit_algo"),
        sender=payer_account.address,
        sp=algod_client.suggested_params(),
        signer=signer,
        method_args=[ signed_payment_txn, app_addr ]
    )
    
    composer.execute(algod_client, 4)

"""
Setup a token deposit with Gora for a given account and app.
"""
def setup_token_deposit(
        algod_client,
        payer_account,
        app_addr,
        token_deposit_amount=10_000_000_000
):
    logger.info(f"Setting up token deposit with Gora (amount: {token_deposit_amount})")

    config = Config()
    acc_info = algod_client.account_info(config.addr)

    token_asset_id = acc_info["assets"][0]["asset-id"]
    composer = AtomicTransactionComposer()
    
    unsigned_transfer_txn = AssetTransferTxn(
        sender=payer_account.address,
        sp=algod_client.suggested_params(),
        receiver=logic.get_application_address(config.id),
        index=token_asset_id,
        amt=token_deposit_amount,
    )
    
    signer = AccountTransactionSigner(payer_account.private_key)
    signed_transfer_txn = TransactionWithSigner(
        unsigned_transfer_txn,
        signer
    )
    
    composer.add_method_call(
        app_id=config.id,
        method=gora_main_app.get_method_by_name("deposit_token"),
        sender=payer_account.address,
        sp=algod_client.suggested_params(),
        signer=signer,
        method_args=[ signed_transfer_txn, token_asset_id, app_addr ]
    )
    
    composer.execute(algod_client, 4)

"""
Return Algorand storage box name for a Gora request key and requester address.
"""
def get_ora_box_name(req_key, addr):
    pub_key = encoding.decode_address(addr)
    hash_src = pub_key + req_key
    name_hash = hashlib.new("sha512_256", hash_src)
    return name_hash.digest()

"""
Return text description of a numeric oracle response.
"""
def describe_ora_num(packed):
    if packed is None:
        return "None"
    if packed[0] == 0:
        return "NaN"

    int_part = struct.unpack_from('>Q', packed, 1)
    dec_part = struct.unpack_from('>Q', packed, 9)
    prefix = "-" if packed[0] == 2 else ""
    return prefix + str(int_part[0]) + "." + str(dec_part[0])

"""
Return last oracle response as a byte string.
"""
def get_ora_value(algod_client, app_id, addr, key_name = "last_oracle_value",
                  max_time = 10, interval = 0.5):

    print(f"Waiting for for oracle return value (up to {max_time} seconds)")
    key = base64.b64encode(key_name.encode())
    start_time = time.time()

    while time.time() - start_time < max_time:
        app_info = algod_client.account_application_info(addr, app_id)
        global_vars = app_info["created-app"].get("global-state", [])
        value_vars = [ x for x in global_vars if x["key"].encode() == key ]
        if (value_vars):
            value = base64.b64decode(value_vars[0]["value"]["bytes"])
            return value

"""
Return true if dev NR container is running, false otherwise.
"""
def is_dev_nr_running():
    cmd = [ "docker", "ps", "--filter", "name=" + dev_node_docker_name,
            "--format", "Aha" ]
    return bool(subprocess.check_output(cmd))


# Export the main classes and functions
__all__ = [
    'Aggr',
    'Config',
    'get_token_asset_id',
    'setup_algo_deposit',
    'setup_token_deposit',
    'get_ora_box_name',
    'describe_ora_num',
    'get_ora_value',
    'is_dev_nr_running',
    'run_cli'
]
