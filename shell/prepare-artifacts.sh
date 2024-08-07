

#!/usr/bin/env bash

# Strict mode: https://gist.github.com/vncsna/64825d5609c146e80de8b1fd623011ca
set -euo pipefail


# Delete the current artifacts
artifacts=./artifacts
rm -rf $artifacts

# Create the new artifacts directories
mkdir $artifacts \
  "$artifacts/interfaces" 

forge build

cp out/Safe7579.sol/Safe7579.json $artifacts
cp out/Safe7579Launchpad.sol/Safe7579Launchpad.json $artifacts
cp out/DCUtil.sol/BatchedExecUtil.json $artifacts
cp out/DCUtil.sol/ModuleInstallUtil.json $artifacts
cp out/DCUtil.sol/Safe7579DCUtil.json $artifacts



interfaces=./artifacts/interfaces


cp out/ISafe7579.sol/ISafe7579.json $interfaces
cp out/ISafeOp.sol/ISafeOp.json $interfaces
cp out/ISafe.sol/ISafe.json $interfaces
cp out/IERC7579Account.sol/IERC7579Account.json $interfaces
cp out/IERC7579Account.sol/IERC7579AccountEvents.json $interfaces
cp out/IERC7579Account.sol/IERC7579AccountView.json $interfaces
cp out/IERC7579Module.sol/IExecutor.json $interfaces
cp out/IERC7579Module.sol/IFallback.json $interfaces
cp out/IERC7579Module.sol/IHook.json $interfaces
cp out/IERC7579Module.sol/IModule.json $interfaces
cp out/IERC7579Module.sol/IValidator.json $interfaces
cp out/IMSA.sol/IMSA.json $interfaces

pnpm prettier --write ./artifacts
