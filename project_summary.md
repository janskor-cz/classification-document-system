# Classification-Based Document Access Control System - Project Summary

## Project Overview
This is a **Flask-based web application** that integrates with **Hyperledger Identus** to create a secure document classification and access control system. The system uses **Self-Sovereign Identity (SSI)** principles with corporate custody to manage document security through credential-based access control.

## Core Concept
Users obtain verifiable credentials from a Registration Authority to:
1. **Label documents** with appropriate classification levels (Public/Internal/Confidential)  
2. **Access documents** that match their credential authorization levels

## Architecture Components

### **Current Working Infrastructure**
- **Flask Web Application** (port 5000) - Main web interface and API
- **Hyperledger Identus Issuer Agent** (port 8080) - Issues and manages credentials ✅ **WORKING**
- **PostgreSQL Database** - User accounts, credentials, documents, audit logs
- **3-Agent Architecture Planned**:
  - **Registration Authority** (Issuer Agent, port 8080) - Issues credentials ✅
  - **Holder Agent** (port 7000) - User credential storage 🔄 **PLANNED**  
  - **Verifier Agent** (port 9000) - Document access verification 🔄 **PLANNED**

### **Authentication Evolution**
**Phase 1** (Working Package 1): Email/password with enterprise account salt
**Phase 2** (Working Package 2): DID-based authentication with enterprise account linkage

## Enterprise Account Model
- **Enterprise Account Name** used as salt for identity generation: `SHA256(email + password + enterprise_account_name)`
- **Corporate Custody**: Registration Authority can recover user access using enterprise account authority
- **Multi-Tenant**: Support multiple enterprise accounts (e.g., "ACME_CORP", "TECH_DIVISION")
- **Lost Credential Recovery**: Admin can regenerate user identity and re-issue credentials

## Two-Stage Credential System

### **Stage 1: Enterprise Credential** 
- **Purpose**: Basic employee verification and system access
- **Required for**: All system operations (foundational credential)
- **Contains**: Employee name, department, employee ID, enterprise account

### **Stage 2: Classification Credentials**
Three levels of document classification credentials:
- **Public Classification Credential** (Level 1)
- **Internal Classification Credential** (Level 2)  
- **Confidential Classification Credential** (Level 3)

## Document Control Rules

### **Document Labeling Control**
- Users can **ONLY classify documents UP TO their highest classification credential level**
- Example: User with Internal credential can label documents as "Public" or "Internal" but NOT "Confidential"

### **Document Access Control**  
- Users can **ONLY access documents AT their exact classification credential level**
- **No hierarchical access**: Internal credential doesn't automatically grant Public access
- **Exact matching**: Must have specific credential for specific document classification

### **Security Model**
- **No Over-Classification**: System prevents users from labeling documents above their authorization
- **Strict Access Control**: Document access requires exact classification credential match
- **Complete Audit Trail**: All document creation and access attempts logged

## User Journey

### **Complete Workflow**:
1. **Registration**: User creates account with email/password under enterprise account
2. **Enterprise Credential Request**: User requests basic enterprise credential → Admin approval → Issued
3. **Classification Credential Request**: User requests specific classification levels → Business justification → Admin approval → Issued
4. **Document Upload**: User can classify documents up to their maximum credential level
5. **Document Access**: User can access documents matching their exact credential levels

### **Admin Workflow**:
1. **Enterprise Credential Approval**: Verify employee identity and enterprise membership
2. **Classification Credential Approval**: Review business justification and grant appropriate access levels
3. **Recovery Management**: Handle lost credentials using enterprise account authority
4. **Audit & Monitoring**: Oversee all credential and document operations

## Technical Implementation

### **Current Status**
- ✅ **Flask Application**: Working with basic authentication
- ✅ **Identus Issuer Agent**: Single agent running on port 8080
- ✅ **Database Schema**: Basic user and document management
- ✅ **Web Interface**: HTML templates with Bootstrap UI

### **Working Package 1 - Enterprise Account Authentication**
**Goal**: Complete Registration Authority workflow with email/password authentication
**Key Features**:
- Enterprise account-based identity generation
- Two-stage credential request and approval system
- Document classification control based on user credentials
- Admin interfaces for credential approval
- Complete audit trail and recovery mechanisms

### **Working Package 2 - DID-Based Authentication Migration**
**Goal**: Migrate to DID-based authentication while preserving enterprise control
**Key Features**:
- User-created DIDs with enterprise account linkage
- Browser extension integration for DID authentication
- Credential migration from email-based to DID-based
- Maintain corporate custody through enterprise account association

## Future Browser Extension
- **Hyperledger Identus TypeScript SDK** integration for browser wallets
- **DID-based authentication** replacing email/password
- **Corporate control maintained** through enterprise account linkage
- **Credential storage** in user's browser extension wallet

## Security & Compliance Features
- **Cryptographic Identity Generation**: Deterministic identity hashing
- **Credential-Based Access Control**: All operations require valid credentials  
- **Enterprise Recovery**: Admin can recover lost user access
- **Complete Audit Trail**: All credential and document operations logged
- **Classification-Based Encryption**: Documents encrypted based on classification level
- **Role-Based Administration**: Separate user and admin privileges

## Key Benefits
1. **Corporate Custody**: Full control for IT administrators
2. **Document Security**: Classification-based protection
3. **User Autonomy**: Self-service credential requests (with approval)
4. **Scalability**: Multi-enterprise account support
5. **Compliance**: Complete audit trail for regulatory requirements
6. **Recovery**: Lost credential recovery capabilities
7. **Future-Proof**: Migration path to full SSI with DID-based authentication

## Development Environment
- **Python/Flask**: Web application framework
- **Hyperledger Identus**: SSI credential management
- **PostgreSQL**: Database for users, credentials, documents
- **Docker**: Container orchestration for Identus agents
- **Bootstrap**: Frontend UI framework
- **GitHub Codespaces**: Development environment support

This system provides enterprise-grade document classification and access control while maintaining the flexibility to evolve toward full Self-Sovereign Identity implementation.
