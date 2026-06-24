#!/usr/bin/env python3
"""
deploy_contract.py  —  SENTINEL-X MILBASTERLog Deployer
========================================================

Deploys MILBASTERLog.sol to Ethereum Sepolia testnet and
writes CONTRACT_ADDR into .env automatically.

Prerequisites:
    pip install py-solc-x web3 python-dotenv --break-system-packages

Usage:
    python3 deploy_contract.py

Environment variables required in .env:
    INFURA_SEPOLIA_URL   — Alchemy/Infura HTTPS endpoint for Sepolia
    PRIVATE_KEY          — MetaMask private key (no 0x prefix)
    ACCOUNT              — Your wallet address (0x...)
"""

import os, sys, json, time
from pathlib import Path
from dotenv import load_dotenv, set_key

load_dotenv()

RPC_URL     = os.getenv("INFURA_SEPOLIA_URL")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
ACCOUNT     = os.getenv("ACCOUNT")
ENV_FILE    = Path(__file__).parent / ".env"

# ── Preflight checks ──────────────────────────────────────────────────────────
missing = []
if not RPC_URL or "your_" in RPC_URL:     missing.append("INFURA_SEPOLIA_URL")
if not PRIVATE_KEY or "your_" in PRIVATE_KEY: missing.append("PRIVATE_KEY")
if not ACCOUNT or "your_" in ACCOUNT:     missing.append("ACCOUNT")

if missing:
    print(f"\n❌ Missing .env values: {', '.join(missing)}")
    print("   Fill in .env before running this script.\n")
    sys.exit(1)

# ── Import Web3 ───────────────────────────────────────────────────────────────
try:
    from web3 import Web3
    from eth_account import Account
except ImportError:
    print("❌ Run: pip install web3 eth-account python-dotenv --break-system-packages")
    sys.exit(1)

# ── Connect ───────────────────────────────────────────────────────────────────
print(f"\n🔌 Connecting to Sepolia via {RPC_URL[:60]}...")
w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 30}))
if not w3.is_connected():
    print("❌ Could not connect. Check your INFURA_SEPOLIA_URL.")
    sys.exit(1)
print(f"✅ Connected — block #{w3.eth.block_number}")

acct = Account.from_key(PRIVATE_KEY)
balance_wei = w3.eth.get_balance(acct.address)
balance_eth = w3.from_wei(balance_wei, "ether")
print(f"💰 Account: {acct.address}")
print(f"💰 Balance: {balance_eth:.4f} ETH")
if balance_eth < 0.001:
    print("❌ Insufficient balance for deployment. Get Sepolia ETH from a faucet.")
    sys.exit(1)

# ── MILBASTERLog contract source ──────────────────────────────────────────────
SOLIDITY_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MILBASTERLog {
    struct LogEntry {
        uint256 ts;
        string  eventHash;
        uint8   anomalyType;
        int16   trustDelta;
        address reporter;
    }

    LogEntry[] public logs;

    event LogAdded(
        uint256 indexed index,
        string  eventHash,
        uint8   anomalyType,
        int16   trustDelta,
        address indexed reporter,
        uint256 ts
    );

    function addLog(
        string  calldata eventHash,
        uint8   anomalyType,
        int16   trustDelta
    ) external {
        logs.push(LogEntry({
            ts:          block.timestamp,
            eventHash:   eventHash,
            anomalyType: anomalyType,
            trustDelta:  trustDelta,
            reporter:    msg.sender
        }));
        emit LogAdded(
            logs.length - 1,
            eventHash,
            anomalyType,
            trustDelta,
            msg.sender,
            block.timestamp
        );
    }

    function getLog(uint256 index) external view returns (
        uint256 ts,
        string  memory eventHash,
        uint8   anomalyType,
        int16   trustDelta,
        address reporter
    ) {
        LogEntry storage e = logs[index];
        return (e.ts, e.eventHash, e.anomalyType, e.trustDelta, e.reporter);
    }

    function count() external view returns (uint256) {
        return logs.length;
    }
}
"""

# ── Compile ───────────────────────────────────────────────────────────────────
print("\n🔨 Compiling MILBASTERLog.sol...")
try:
    from solcx import compile_source, install_solc, get_installed_solc_versions
    if not get_installed_solc_versions():
        print("   Installing solc 0.8.20...")
        install_solc("0.8.20")
    compiled = compile_source(
        SOLIDITY_SOURCE,
        output_values=["abi", "bin"],
        solc_version="0.8.20"
    )
    contract_id  = "<stdin>:MILBASTERLog"
    abi          = compiled[contract_id]["abi"]
    bytecode     = compiled[contract_id]["bin"]
    print(f"✅ Compiled — ABI has {len(abi)} entries, bytecode {len(bytecode)//2} bytes")
except ImportError:
    print("❌ Run: pip install py-solc-x --break-system-packages")
    sys.exit(1)

# ── Deploy ────────────────────────────────────────────────────────────────────
print("\n🚀 Deploying to Sepolia...")
Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
nonce    = w3.eth.get_transaction_count(acct.address)

# ── EIP-1559 gas pricing (fixes stuck-TX issue with legacy gasPrice) ──────
# Sepolia is an EIP-1559 chain. Legacy type-0 txs with only gasPrice and
# no priority fee get deprioritized by validators → sit in mempool forever.
# Use maxPriorityFeePerGas (tip to validator) + maxFeePerGas (hard cap).
latest_block = w3.eth.get_block("latest")
base_fee     = latest_block.get("baseFeePerGas", w3.to_wei(10, "gwei"))
priority_fee = w3.to_wei(2, "gwei")          # 2 Gwei tip — enough for Sepolia
max_fee      = base_fee * 2 + priority_fee   # generous cap: survives 1 doubling

print(f"   base fee  : {w3.from_wei(base_fee, 'gwei'):.2f} Gwei")
print(f"   priority  : {w3.from_wei(priority_fee, 'gwei'):.2f} Gwei tip")
print(f"   max fee   : {w3.from_wei(max_fee, 'gwei'):.2f} Gwei cap")

txn = Contract.constructor().build_transaction({
    "chainId":              11155111,
    "gas":                  800000,
    "maxFeePerGas":         max_fee,
    "maxPriorityFeePerGas": priority_fee,
    "nonce":                nonce,
    "from":                 acct.address,
    "type":                 "0x2",   # EIP-1559
})

signed  = acct.sign_transaction(txn)
raw     = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
tx_hash = w3.eth.send_raw_transaction(raw)
tx_hex  = Web3.to_hex(tx_hash)
print(f"\n⏳ TX submitted: {tx_hex}")
print(f"   Track it: https://sepolia.etherscan.io/tx/{tx_hex}")
print("   Waiting for confirmation (up to 5 min)...")

receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
if receipt.status != 1:
    print(f"❌ Deployment failed — receipt status: {receipt.status}")
    sys.exit(1)

contract_addr = receipt.contractAddress
print(f"\n✅ Contract deployed!")
print(f"   Address : {contract_addr}")
print(f"   Block   : {receipt.blockNumber}")
print(f"   Gas used: {receipt.gasUsed}")
print(f"\n   Sepolia explorer: https://sepolia.etherscan.io/address/{contract_addr}")

# ── Update .env ───────────────────────────────────────────────────────────────
set_key(str(ENV_FILE), "CONTRACT_ADDR", contract_addr)
print(f"\n✅ CONTRACT_ADDR written to .env: {contract_addr}")

# ── Save compiled ABI (overwrite with freshly compiled version) ───────────────
abi_path = Path(__file__).parent / "MILBASTERLog_abi.json"
with open(abi_path, "w") as f:
    json.dump(abi, f, indent=2)
print(f"✅ ABI saved to {abi_path}")

print("\n🎉 Done! Next step: run the daemon WITHOUT --dry-run:")
print("   sudo python3 sentinel_daemon.py")
