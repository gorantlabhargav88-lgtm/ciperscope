import * as fs from 'fs';
import * as path from 'path';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const solc = require('solc');

export function compileContract(): { abi: any[]; bytecode: string } {
  const contractPath = path.resolve(__dirname, '../contracts/CipherScopeAnchor.sol');
  const source = fs.readFileSync(contractPath, 'utf8');

  const input = {
    language: 'Solidity',
    sources: {
      'CipherScopeAnchor.sol': {
        content: source,
      },
    },
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      outputSelection: {
        '*': {
          '*': ['abi', 'evm.bytecode'],
        },
      },
    },
  };

  const output = JSON.parse(solc.compile(JSON.stringify(input)));

  if (output.errors) {
    const fatal = output.errors.filter((e: any) => e.severity === 'error');
    if (fatal.length > 0) {
      console.error('Solidity compilation errors:', fatal);
      throw new Error(`Solidity compilation failed: ${fatal.map((f: any) => f.formattedMessage).join('\n')}`);
    }
  }

  const contract = output.contracts['CipherScopeAnchor.sol']['CipherScopeAnchor'];
  const abi = contract.abi;
  const bytecode = '0x' + contract.evm.bytecode.object;

  const outputPath = path.resolve(__dirname, '../CipherScopeAnchor.json');
  fs.writeFileSync(outputPath, JSON.stringify({ abi, bytecode }, null, 2));

  console.log(`Compiled CipherScopeAnchor.sol successfully -> ${outputPath}`);
  return { abi, bytecode };
}

if (require.main === module) {
  compileContract();
}
