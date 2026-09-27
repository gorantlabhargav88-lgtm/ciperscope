import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';

dotenv.config({ path: path.resolve(__dirname, '../../../.env') });

async function main() {
  const rpcUrl = process.env.BLOCKCHAIN_RPC_URL;
  const privateKey = process.env.BLOCKCHAIN_PRIVATE_KEY;
  const network = process.env.BLOCKCHAIN_NETWORK || 'sepolia';

  if (!rpcUrl) {
    console.error('Error: BLOCKCHAIN_RPC_URL is not set in .env');
    process.exit(1);
  }

  if (!privateKey) {
    console.error('Error: BLOCKCHAIN_PRIVATE_KEY is not set in .env');
    console.error('Please configure a valid private key with testnet ETH before deploying.');
    process.exit(1);
  }

  const artifactPath = path.resolve(__dirname, '../CipherScopeAnchor.json');
  if (!fs.existsSync(artifactPath)) {
    console.log('Artifact not found. Compiling first...');
    const { compileContract } = await import('./compile');
    compileContract();
  }

  const { abi, bytecode } = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));

  console.log(`Connecting to network: ${network} (${rpcUrl})...`);
  const provider = new ethers.JsonRpcProvider(rpcUrl);

  const wallet = new ethers.Wallet(privateKey, provider);
  console.log(`Deployer address: ${wallet.address}`);

  const balance = await provider.getBalance(wallet.address);
  console.log(`Deployer balance: ${ethers.formatEther(balance)} ETH`);

  if (balance === 0n) {
    console.error('Error: Deployer balance is 0. Please fund your testnet wallet with Sepolia ETH before deploying.');
    process.exit(1);
  }

  console.log('Deploying CipherScopeAnchor contract...');
  const factory = new ethers.ContractFactory(abi, bytecode, wallet);
  const contract = await factory.deploy();

  console.log(`Deployment transaction submitted: ${contract.deploymentTransaction()?.hash}`);
  console.log('Waiting for block confirmation...');
  await contract.waitForDeployment();

  const contractAddress = await contract.getAddress();
  console.log('====================================================');
  console.log('CipherScopeAnchor successfully deployed!');
  console.log(`Contract Address: ${contractAddress}`);
  console.log(`Network:          ${network}`);
  console.log(`Deployment TX:    ${contract.deploymentTransaction()?.hash}`);
  console.log('====================================================');
  console.log('Please add the following to your .env file:');
  console.log(`BLOCKCHAIN_ENABLED=true`);
  console.log(`BLOCKCHAIN_CONTRACT_ADDRESS=${contractAddress}`);
  console.log('====================================================');
}

if (require.main === module) {
  main().catch((err) => {
    console.error('Deployment failed:', err);
    process.exit(1);
  });
}
