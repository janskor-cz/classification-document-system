# Project Requirements & Implementation Tasks

## Core Requirements
1. Enterprise credential must be created during registration of a new user. Login must be used only for accessing the wallet inside of identus agent.
2. Enterprise credential must be issued by real DID process. Not by mock VC.
3. Main page of the user should contain list of all DID created and with whom this connection is created.
4. Admin page should filter all DID to issuer by company.
5. Every document should contain not only sensitivity credential, but releasability credential. For testing purpose it should have this possibilities. Public (all entities can see a document), releasable to: (can contain list of companies. It can contain record with one company or with multiple different companies)
6. Main goal for releasibility is to be able to select all companies with which workers company has created trust through DID between registration authorities for their company. So it should be 1 RA which are creating VC for every company RA. Then companies can create a trust by creation of DID. This implementation should be done at the end after all encryption tasks to document will be done.

---

## Implementation Tasks

### Phase 1: Fix Real Credential Issuance ⚠️ IN PROGRESS
- [x] **Task 1.1**: Fix DIDComm connection handshake during registration ✅
  - Created holder_wallet_manager.py for managing user DIDs
  - Implemented proper invitation acceptance flow
  - Added connection tracking for users
  
- [x] **Task 1.2**: Remove all mock VC fallbacks ✅ COMPLETED
  - Remove create_mock_vc_from_database function
  - Remove development mode credential creation
  - Ensure only real Identus credentials are used

- [x] **Task 1.3**: Implement proper holder wallet integration ✅
  - Created HolderWalletManager class
  - Added holder DID creation for each new user
  - Store holder DID in user profile (added holder_did column)
  - Use holder agent to accept credential invitations
  
- [ ] **Task 1.4**: Fix enterprise credential issuance flow (IN PROGRESS)
  - Issue enterprise credential immediately after user creation
  - Store credential record ID in database
  - Verify credential is properly stored in holder wallet

### Phase 2: DID Connections Management
- [x] **Task 2.1**: Create DID connections tracking table ✅
  - Added `did_connections` table to database
  - Track: connection_id, user_id, their_did, my_did, state, created_at
  - Track connection metadata (label, enterprise, purpose)

- [ ] **Task 2.2**: Add DID connections to user dashboard
  - Create "My Connections" section on dashboard
  - Show all DIDs created by user
  - Display connection partners and status
  - Add connection management (view details, revoke)

- [ ] **Task 2.3**: Implement admin DID filtering
  - Add "DID Management" section to admin panel
  - Filter DIDs by enterprise/company
  - Show issuer information for each DID
  - Display connection statistics per company

### Phase 3: Releasability Credentials
- [ ] **Task 3.1**: Create releasability credential schema
  - Define credential structure for releasability
  - Support levels: "Public", "Company-specific", "Multi-company"
  - Create Identus schema for releasability

- [ ] **Task 3.2**: Update document model
  - Add `releasability_level` field to documents table
  - Add `releasable_to_companies` JSON field
  - Update document upload form

- [ ] **Task 3.3**: Implement releasability UI
  - Add releasability selector in document upload
  - Show company list for selection
  - Display releasability info on documents

- [ ] **Task 3.4**: Enforce releasability access control
  - Check user's company against releasability list
  - Verify trust relationships exist
  - Apply access restrictions

### Phase 4: Registration Authority & Trust Network
- [ ] **Task 4.1**: Create Registration Authority system
  - One RA per company
  - RA manages company's root DID
  - RA issues all company credentials

- [ ] **Task 4.2**: Implement inter-company trust
  - Create trust establishment protocol
  - Store trust relationships in database
  - Verify trust chains for access

- [ ] **Task 4.3**: Cross-company document sharing
  - Use trust relationships for access control
  - Implement secure document exchange
  - Audit cross-company access

---

## Current Status

### Completed ✅
- Multi-tenant architecture setup
- Basic enterprise credential system
- Document classification levels
- Mock VC removal

### In Progress 🚧
- Real DIDComm credential issuance
- Connection state management

### Not Started ❌
- DID connections dashboard
- Releasability credentials
- Registration Authority system
- Trust network implementation

---

## Next Steps (Priority Order)
1. Fix DIDComm connection handshake (Task 1.1) - CRITICAL
2. Implement holder wallet integration (Task 1.3) - CRITICAL
3. Add DID connections to dashboard (Task 2.2) - HIGH
4. Create releasability credential system (Task 3.1-3.4) - MEDIUM
5. Build Registration Authority system (Task 4.1-4.3) - LOW

---

## Technical Debt
- Connection state doesn't progress without manual intervention
- No real holder wallet integration
- Missing DID connection tracking
- No releasability concept implemented
- No inter-company trust mechanism