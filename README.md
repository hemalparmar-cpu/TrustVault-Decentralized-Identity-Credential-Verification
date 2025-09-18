TrustVault: Decentralized Identity & Credential Verification
Project Description
TrustVault is a blockchain-based decentralized identity and credential verification system built on Ethereum. It allows users to register their digital identities, receive verifiable credentials from trusted issuers, and provide a transparent, tamper-proof way to verify qualifications and achievements.
Project Vision
To create a trustless, decentralized ecosystem where individuals have complete control over their digital identity and credentials, eliminating the need for centralized authorities while ensuring authenticity and preventing fraud in credential verification.
Key Features

Decentralized Identity Registration: Users can register their digital identity on the blockchain
Credential Issuance: Verified issuers can issue tamper-proof credentials to registered users
Transparent Verification: Anyone can verify the authenticity of credentials without relying on third parties
Immutable Records: All credentials and identities are stored permanently on the blockchain
Access Control: Only verified issuers can issue credentials, preventing fraudulent certifications
User-Friendly Interface: Simple web interface for easy interaction with the smart contract

Future Scope

Multi-Chain Support: Expand to other blockchain networks for better scalability
Advanced Privacy Features: Implement zero-knowledge proofs for selective disclosure
Integration APIs: Develop APIs for easy integration with existing HR and educational systems
Mobile Application: Create mobile apps for easier access and management
Reputation System: Implement a reputation scoring system for issuers and users
NFT Credentials: Convert credentials to NFTs for enhanced ownership and transferability
Decentralized Storage: Integrate with IPFS for storing larger credential documents
Multi-Signature Support: Add multi-sig functionality for institutional credential issuance

Technical Stack

Smart Contract: Solidity ^0.8.19
Frontend: HTML5, CSS3, JavaScript
Blockchain Interaction: Ethers.js
Deployment: Ethereum network compatible

Getting Started

Deploy the smart contract to your preferred Ethereum network
Update the contract address in frontend/app.js
Open frontend/index.html in a web browser
Connect your MetaMask wallet
Start registering identities and issuing credentials!

Contract Functions
Core Functions

registerIdentity(string name, string email): Register a new digital identity
issueCredential(address user, string title, string description): Issue a credential to a registered user
verifyCredential(address user, uint256 credentialId): Verify and retrieve credential details

Helper Functions

addVerifiedIssuer(address issuer): Add a new verified credential issuer (owner only)
getUserCredentialCount(address user): Get the number of credentials for a user

Adress: 0x37F265613990DD9EDEBa9bdEEb08A5380Cc8e90D


<img width="1918" height="918" alt="image" src="https://github.com/user-attachments/assets/4fea6f86-a42b-438a-9ee9-036e274c6866" />


