/** Hardhat compiles the contracts (EVM target Paris) and runs the registry tests and the local gas measurements on
 *  its default hardfork (Osaka, the current mainnet rules; recorded in data/gas_local.jsonl). Testnet runs use ethers
 *  directly (scripts/testnet.js), with the key and RPC URLs read from an .env file that is never printed. */
require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "paris" },
  },
};
