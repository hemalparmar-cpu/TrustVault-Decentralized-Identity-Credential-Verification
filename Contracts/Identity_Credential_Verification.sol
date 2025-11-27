// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IdentityCredentialVerification
 * @dev On-chain registry for identity credentials with issuer-based verification
 * @notice Trusted issuers can register and revoke hashed credentials for subjects
 */
contract Identity_Credential_Verification {
    
    // --- Roles & State ---
    
    address public owner;
    
    // Issuers are trusted entities (KYC providers, institutions, etc.)
    mapping(address => bool) public isIssuer;
    
    // Credential status enum
    enum CredentialStatus {
        None,       // 0 = not registered
        Active,     // 1 = valid credential
        Revoked     // 2 = explicitly revoked
    }
    
    struct Credential {
        address subject;          // holder of the credential
        address issuer;           // entity that issued the credential
        bytes32 credentialHash;   // hash of off-chain credential data
        uint256 issuedAt;         // timestamp when issued
        uint256 expiresAt;        // 0 means no explicit expiry
        CredentialStatus status;  // current status
        string  schema;           // optional schema / type ID (e.g., "KYC_BASIC_V1")
    }
    
    // credentialId => Credential
    mapping(bytes32 => Credential) public credentials;
    
    // subject => list of credentialIds
    mapping(address => bytes32[]) public credentialsOf;
    
    // issuer => list of credentialIds
    mapping(address => bytes32[]) public issuedBy;
    
    // --- Events ---
    
    event IssuerAdded(address indexed issuer);
    event IssuerRemoved(address indexed issuer);
    
    event CredentialIssued(
        bytes32 indexed credentialId,
        address indexed subject,
        address indexed issuer,
        uint256 issuedAt,
        uint256 expiresAt,
        string schema
    );
    
    event CredentialRevoked(
        bytes32 indexed credentialId,
        address indexed issuer,
        uint256 revokedAt
    );
    
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    // --- Modifiers ---
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    modifier onlyIssuer() {
        require(isIssuer[msg.sender], "Not an issuer");
        _;
    }
    
    modifier credentialExists(bytes32 credentialId) {
        require(credentials[credentialId].status != CredentialStatus.None, "Credential not found");
        _;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    // --- Issuer Management ---
    
    /**
     * @dev Add a trusted issuer
     * @param issuer Address of the issuer to authorize
     */
    function addIssuer(address issuer) external onlyOwner {
        require(issuer != address(0), "Zero address");
        require(!isIssuer[issuer], "Already issuer");
        
        isIssuer[issuer] = true;
        emit IssuerAdded(issuer);
    }
    
    /**
     * @dev Remove a trusted issuer
     * @param issuer Address of the issuer to remove
     */
    function removeIssuer(address issuer) external onlyOwner {
        require(isIssuer[issuer], "Not issuer");
        isIssuer[issuer] = false;
        emit IssuerRemoved(issuer);
    }
    
    // --- Credential Lifecycle ---
    
    /**
     * @dev Issue a new credential for a subject
     * @param subject Address of credential holder
     * @param credentialHash Hash of the off-chain credential data
     * @param expiresAt Expiration timestamp (0 for no expiry)
     * @param schema Schema/type identifier string
     * @return credentialId The key under which the credential is stored
     */
    function issueCredential(
        address subject,
        bytes32 credentialHash,
        uint256 expiresAt,
        string calldata schema
    )
        external
        onlyIssuer
        returns (bytes32 credentialId)
    {
        require(subject != address(0), "Invalid subject");
        require(credentialHash != bytes32(0), "Invalid hash");
        if (expiresAt != 0) {
            require(expiresAt > block.timestamp, "Already expired");
        }
        
        // Derive unique credentialId from issuer + subject + hash
        credentialId = keccak256(abi.encodePacked(msg.sender, subject, credentialHash));
        require(credentials[credentialId].status == CredentialStatus.None, "Credential exists");
        
        credentials[credentialId] = Credential({
            subject: subject,
            issuer: msg.sender,
            credentialHash: credentialHash,
            issuedAt: block.timestamp,
            expiresAt: expiresAt,
            status: CredentialStatus.Active,
            schema: schema
        });
        
        credentialsOf[subject].push(credentialId);
        issuedBy[msg.sender].push(credentialId);
        
        emit CredentialIssued(
            credentialId,
            subject,
            msg.sender,
            block.timestamp,
            expiresAt,
            schema
        );
    }
    
    /**
     * @dev Revoke an existing credential
     * @param credentialId Identifier of the credential to revoke
     * @notice Only the original issuer can revoke
     */
    function revokeCredential(bytes32 credentialId)
        external
        credentialExists(credentialId)
    {
        Credential storage cred = credentials[credentialId];
        require(cred.issuer == msg.sender, "Not issuer");
        require(cred.status == CredentialStatus.Active, "Not active");
        
        cred.status = CredentialStatus.Revoked;
        emit CredentialRevoked(credentialId, msg.sender, block.timestamp);
    }
    
    // --- Views & Helpers ---
    
    /**
     * @dev Check if a credential is currently valid
     * @param credentialId Credential identifier
     * @return isValid True if credential is active and not expired
     */
    function isCredentialValid(bytes32 credentialId)
        public
        view
        credentialExists(credentialId)
        returns (bool isValid)
    {
        Credential memory cred = credentials[credentialId];
        if (cred.status != CredentialStatus.Active) return false;
        if (cred.expiresAt != 0 && block.timestamp > cred.expiresAt) return false;
        return true;
    }
    
    /**
     * @dev Get full credential data
     * @param credentialId Credential identifier
     */
    function getCredential(bytes32 credentialId)
        external
        view
        credentialExists(credentialId)
        returns (
            address subject,
            address issuer,
            bytes32 credentialHash,
            uint256 issuedAt,
            uint256 expiresAt,
            CredentialStatus status,
            string memory schema
        )
    {
        Credential memory cred = credentials[credentialId];
        return (
            cred.subject,
            cred.issuer,
            cred.credentialHash,
            cred.issuedAt,
            cred.expiresAt,
            cred.status,
            cred.schema
        );
    }
    
    /**
     * @dev Get all credential IDs associated with a subject
     * @param subject Address of the subject
     */
    function getCredentialsOf(address subject)
        external
        view
        returns (bytes32[] memory)
    {
        return credentialsOf[subject];
    }
    
    /**
     * @dev Get all credential IDs issued by a specific issuer
     * @param issuer Address of the issuer
     */
    function getIssuedBy(address issuer)
        external
        view
        returns (bytes32[] memory)
    {
        return issuedBy[issuer];
    }
    
    /**
     * @dev Transfer contract ownership
     * @param newOwner New owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        address prev = owner;
        owner = newOwner;
        emit OwnershipTransferred(prev, newOwner);
    }
}
