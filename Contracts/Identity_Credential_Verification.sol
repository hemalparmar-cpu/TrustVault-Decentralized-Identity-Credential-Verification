--- Constants / Types
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    enum CredentialState { Issued, Verified, Revoked }

    struct Credential {
        uint256 id;
        address subject;
        address issuer;
        string title;
        string description; --- Custom errors (cheaper than revert strings)
    error ZeroAddress();
    error AlreadyRegistered();
    error NotRegistered();
    error InvalidInput();
    error EmailInUse();
    error NotIssuer();
    error CredentialNotFound();
    error NotAuthorized();
    error EmptyArray();
    error EmptyTitle();

    --- Events
    event IdentityRegistered(address indexed user, string name, string email);
    event IdentityUpdated(address indexed user, string name, string email);
    event IdentityDeregistered(address indexed user);

    event IssuerGranted(address indexed issuer);
    event IssuerRevoked(address indexed issuer);

    event CredentialIssued(uint256 indexed credentialId, address indexed subject, address indexed issuer, string title);
    event CredentialBatchIssued(uint256[] ids, address indexed issuer);
    event CredentialVerified(uint256 indexed credentialId, address indexed verifier);
    event CredentialRevoked(uint256 indexed credentialId, address indexed revokedBy);
    event CredentialUpdated(uint256 indexed credentialId, string newTitle, string newDescription, address indexed updatedBy);

    Start IDs at 1 for clearer truthiness
        _credentialIdCounter.increment();
        _issuers.add(_msgSender());
    }

    --- Identity management

    function registerIdentity(string calldata name, string calldata email) external whenNotPaused {
        if (_identities[_msgSender()].isRegistered) revert AlreadyRegistered();
        if (bytes(name).length == 0 || bytes(email).length == 0) revert InvalidInput();

        bytes32 h = keccak256(bytes(email));
        if (_emailHashToAddress[h] != address(0)) revert EmailInUse();

        clear old only if bound to sender
            if (_emailHashToAddress[oldHash] == _msgSender()) {
                _emailHashToAddress[oldHash] = address(0);
            }
            _emailHashToAddress[newHash] = _msgSender();
            idRec.email = email;
        }
        idRec.name = name;

        emit IdentityUpdated(_msgSender(), name, email);
    }

    function deregisterIdentity() external whenNotPaused onlyRegistered(_msgSender()) {
        Identity storage idRec = _identities[_msgSender()];
        bytes32 h = keccak256(bytes(idRec.email));
        if (_emailHashToAddress[h] == _msgSender()) {
            _emailHashToAddress[h] = address(0);
        }
        delete _identities[_msgSender()];
        emit IdentityDeregistered(_msgSender());
    }

    function getIdentity(address user) external view returns (Identity memory) {
        return _identities[user];
    }

    function getIdentityByEmail(string calldata email) external view returns (address) {
        if (bytes(email).length == 0) return address(0);
        return _emailHashToAddress[keccak256(bytes(email))];
    }

    function isEmailBound(string calldata email) external view returns (bool) {
        if (bytes(email).length == 0) return false;
        return _emailHashToAddress[keccak256(bytes(email))] != address(0);
    }

    /--- Issuer management (owner)

    function grantIssuer(address account) external onlyOwner whenNotPaused {
        if (account == address(0)) revert ZeroAddress();
        grantRole(ISSUER_ROLE, account);
        _issuers.add(account);
        emit IssuerGranted(account);
    }

    function revokeIssuer(address account) external onlyOwner whenNotPaused {
        if (account == address(0)) revert ZeroAddress();
        revokeRole(ISSUER_ROLE, account);
        _issuers.remove(account);
        emit IssuerRevoked(account);
    }

    function isIssuer(address account) external view returns (bool) {
        return hasRole(ISSUER_ROLE, account);
    }

    function renounceIssuerRole() external whenNotPaused {
        renounceRole(ISSUER_ROLE, _msgSender());
        _issuers.remove(_msgSender());
        emit IssuerRevoked(_msgSender());
    }

    function listIssuers(uint256 cursor, uint256 pageSize) external view returns (address[] memory page, uint256 newCursor) {
        uint256 total = _issuers.length();
        if (cursor >= total) return (new address, cursor);
        uint256 to = cursor + pageSize;
        if (to > total) to = total;
        page = new address[](to - cursor);
        for (uint256 i = cursor; i < to; ) {
            page[i - cursor] = _issuers.at(i);
            unchecked { ++i; }
        }
        return (page, to);
    }

    /--- Pause / Unpause
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    @dev Core internal issue function (no modifiers) - minimally checks inputs.
    function _issueCredential(address issuer, address subject, string calldata title, string calldata description)
        internal returns (uint256)
    {
        if (subject == address(0) || bytes(title).length == 0) revert InvalidInput();

        uint256 cid = _nextId();

        _credentials[cid] = Credential({
            id: cid,
            subject: subject,
            issuer: issuer,
            title: title,
            description: description,
            timestamp: uint64(block.timestamp),
            state: CredentialState.Issued
        });

        _userCredentialIds[subject].push(cid);
        _issuerCredentialIds[issuer].push(cid);

        emit CredentialIssued(cid, subject, issuer, title);
        return cid;
    }

    /@notice Batch issue credentials; ensures subjects are registered.
    function batchIssueCredentials(
        address[] calldata subjects,
        string[] calldata titles,
        string[] calldata descriptions
    ) external nonReentrant whenNotPaused onlyIssuer returns (uint256[] memory) {
        uint256 n = subjects.length;
        if (n == 0) revert EmptyArray();
        if (titles.length != n || descriptions.length != n) revert InvalidInput();

        uint256[] memory issuedIds = new uint256[](n);
        for (uint256 i = 0; i < n; ) {
            @notice Issue and mark verified atomically.
    function issueAndVerify(address subject, string calldata title, string calldata description)
        external whenNotPaused onlyIssuer onlyRegistered(subject) returns (uint256)
    {
        uint256 cid = _issueCredential(_msgSender(), subject, title, description);
        _credentials[cid].state = CredentialState.Verified;
        emit CredentialVerified(cid, _msgSender());
        return cid;
    }

    function verifyCredential(uint256 credentialId) external whenNotPaused onlyIssuer credentialExists(credentialId) {
        Credential storage cred = _credentials[credentialId];
        if (cred.state != CredentialState.Issued) revert InvalidInput();
        cred.state = CredentialState.Verified;
        emit CredentialVerified(credentialId, _msgSender());
    }

    function batchVerify(uint256[] calldata credentialIds) external whenNotPaused onlyIssuer {
        uint256 len = credentialIds.length;
        if (len == 0) revert EmptyArray();
        for (uint256 i = 0; i < len; ) {
            uint256 id = credentialIds[i];
            if (id != 0) {
                Credential storage cred = _credentials[id];
                if (cred.id != 0 && cred.state == CredentialState.Issued) {
                    cred.state = CredentialState.Verified;
                    emit CredentialVerified(id, _msgSender());
                }
            }
            unchecked { ++i; }
        }
    }

    allow if owner OR the credential's issuer matches caller
                    if (callerIsOwner || cred.issuer == _msgSender()) {
                        cred.state = CredentialState.Revoked;
                        emit CredentialRevoked(id, _msgSender());
                    }
                }
            }
            unchecked { ++i; }
        }
    }

    function updateCredentialMetadata(uint256 credentialId, string calldata newTitle, string calldata newDescription)
        external whenNotPaused credentialExists(credentialId)
    {
        if (bytes(newTitle).length == 0) revert EmptyTitle();

        Credential storage cred = _credentials[credentialId];
        if (_msgSender() != cred.issuer) revert NotAuthorized();
        if (cred.state == CredentialState.Revoked) revert InvalidInput();

        cred.title = newTitle;
        cred.description = newDescription;
        emit CredentialUpdated(credentialId, newTitle, newDescription, _msgSender());
    }

    counter started at 1 and increments after use; subtract 1 to get issued count
        return _credentialIdCounter.current() - 1;
    }

    function getUserCredentials(address user) external view returns (uint256[] memory) {
        return _userCredentialIds[user];
    }

    function getIssuerCredentials(address issuer) external view returns (uint256[] memory) {
        return _issuerCredentialIds[issuer];
    }

    function getUserCredentialsPaged(address user, uint256 cursor, uint256 pageSize)
        external view returns (uint256[] memory page, uint256 newCursor)
    {
        uint256 length = _userCredentialIds[user].length;
        if (cursor >= length) return (new uint256, cursor);
        uint256 to = cursor + pageSize;
        if (to > length) to = length;
        page = new uint256[](to - cursor);
        for (uint256 i = cursor; i < to; ) {
            page[i - cursor] = _userCredentialIds[user][i];
            unchecked { ++i; }
        }
        return (page, to);
    }

    function getIssuerCredentialsPaged(address issuer, uint256 cursor, uint256 pageSize)
        external view returns (uint256[] memory page, uint256 newCursor)
    {
        uint256 length = _issuerCredentialIds[issuer].length;
        if (cursor >= length) return (new uint256, cursor);
        uint256 to = cursor + pageSize;
        if (to > length) to = length;
        page = new uint256[](to - cursor);
        for (uint256 i = cursor; i < to; ) {
            page[i - cursor] = _issuerCredentialIds[issuer][i];
            unchecked { ++i; }
        }
        return (page, to);
    }

    /--- Admin utilities
    function ownerForceRevoke(uint256 credentialId) external onlyOwner credentialExists(credentialId) whenNotPaused {
        Credential storage cred = _credentials[credentialId];
        if (cred.state == CredentialState.Revoked) return;
        cred.state = CredentialState.Revoked;
        emit CredentialRevoked(credentialId, _msgSender());
    }

    function adminClearEmailBinding(string calldata email) external onlyOwner whenNotPaused {
        bytes32 h = keccak256(bytes(email));
        _emailHashToAddress[h] = address(0);
    }

    function renounceAllRoles() external onlyOwner whenNotPaused {
        small helper view for frontends
    function getCredentialState(uint256 credentialId) external view returns (CredentialState) {
        return _credentials[credentialId].state;
    }

    /**
     * @notice New helper: retrieve multiple credentials in a single call.
     * @dev Returns a memory array of Credential structs for the supplied ids. If an id is invalid (0 or not found)
     * the returned slot will contain a zeroed credential (id == 0).
     */
    function batchGetCredentials(uint256[] calldata ids) external view returns (Credential[] memory) {
        uint256 n = ids.length;
        Credential[] memory out = new Credential[](n);
        for (uint256 i = 0; i < n; ) {
            uint256 id = ids[i];
            if (id != 0 && _credentials[id].id != 0) {
                leave zeroed
            }
            unchecked { ++i; }
        }
        return out;
    }

    End
End
End
End
End
End
// 
// 
End
// 
