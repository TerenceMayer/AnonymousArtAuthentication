const { ethers } = require("hardhat");

async function main() {
  console.log("Deploying Anonymous Art Authentication contract...");

  // Get the ContractFactory
  const AnonymousArtAuthentication = await ethers.getContractFactory("AnonymousArtAuthentication");

  // Deploy the contract
  const contract = await AnonymousArtAuthentication.deploy();

  await contract.waitForDeployment();

  const contractAddress = await contract.getAddress();
  console.log("AnonymousArtAuthentication deployed to:", contractAddress);

  // Verify deployment
  console.log("\nContract verification:");
  console.log("Owner:", await contract.owner());
  console.log("Next Artwork ID:", await contract.nextArtworkId());
  console.log("Next Expert ID:", await contract.nextExpertId());

  console.log("\n=== Deployment Summary ===");
  console.log(`Contract Address: ${contractAddress}`);
  console.log(`Network: ${network.name}`);
  console.log(`Deployer: ${(await ethers.getSigners())[0].address}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });