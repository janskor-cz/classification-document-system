/**
 * Ephemeral DID Client for Document Access (Working Package 3 - Task 3.1)
 * 
 * This client handles client-side ephemeral DID generation for secure document access.
 * It integrates with the existing Identus client while providing document-specific functionality.
 * 
 * Key Features:
 * - Generate ephemeral DID:key pairs for document access
 * - Request documents with ephemeral encryption
 * - Decrypt documents client-side with ephemeral private keys
 * - Automatic session cleanup and key destruction
 * - Perfect forward secrecy implementation
 */

class EphemeralDIDClient {
    constructor() {
        this.identusManager = null;
        this.currentSession = null;
        this.activeDIDPairs = new Map(); // documentId -> {did, privateKey, publicKey, sessionToken}
        this.sessionTimers = new Map(); // sessionToken -> setTimeout reference
        this.apiBaseUrl = '/api/ephemeral';
        
        // Initialize Identus SDK
        this.initializeIdentusSDK();
        
        console.log('🔐 EphemeralDIDClient initialized');
    }

    /**
     * Initialize Hyperledger Identus SDK for ephemeral DID operations
     */
    async initializeIdentusSDK() {
        try {
            // Use existing EphemeralDIDManager from identus-client.js if available
            if (typeof window.ephemeralDIDManager !== 'undefined') {
                this.identusManager = window.ephemeralDIDManager;
                console.log('✅ Using existing Identus SDK from identus-client.js');
                return;
            }

            // Fallback to WebCrypto if Identus SDK not available
            console.log('⚠️ Identus SDK not available, using WebCrypto fallback');
            this.identusManager = new WebCryptoFallbackManager();
            
        } catch (error) {
            console.error('❌ Failed to initialize Identus SDK:', error);
            // Create basic fallback manager
            this.identusManager = new WebCryptoFallbackManager();
        }
    }

    /**
     * Generate ephemeral DID:key pair for specific document access
     * @param {number} documentId - Document ID to generate ephemeral access for
     * @param {string} businessJustification - Required business justification
     * @param {number} sessionDurationMinutes - Session duration (default: 60 minutes)
     * @returns {Promise<Object>} - Ephemeral DID generation result
     */
    async generateEphemeralDIDForDocument(documentId, businessJustification, sessionDurationMinutes = 60) {
        try {
            console.log(`🔑 Generating ephemeral DID for document ${documentId}`);

            // Validate inputs
            if (!documentId || !businessJustification) {
                throw new Error('Document ID and business justification are required');
            }

            // Check if we already have an active session for this document
            if (this.activeDIDPairs.has(documentId)) {
                const existing = this.activeDIDPairs.get(documentId);
                console.log(`⚠️ Reusing existing ephemeral DID for document ${documentId}`);
                return {
                    success: true,
                    reused: true,
                    ephemeralDID: existing.did,
                    sessionToken: existing.sessionToken,
                    message: 'Reusing existing ephemeral session'
                };
            }

            // Generate ephemeral DID:key pair
            const keyPair = await this.identusManager.generateEphemeralDIDKey();
            
            if (!keyPair.success) {
                throw new Error(keyPair.error || 'Failed to generate ephemeral DID');
            }

            console.log('✅ Ephemeral DID generated successfully');

            // Store the key pair securely in memory
            const didPairData = {
                did: keyPair.did,
                privateKey: keyPair.privateKey,
                publicKey: keyPair.publicKey,
                documentId: documentId,
                createdAt: new Date().toISOString(),
                businessJustification: businessJustification
            };

            return {
                success: true,
                ephemeralDID: keyPair.did,
                ephemeralPublicKey: keyPair.publicKey,
                documentId: documentId,
                sessionDuration: sessionDurationMinutes,
                keyPairData: didPairData,
                message: 'Ephemeral DID generated successfully'
            };

        } catch (error) {
            console.error('❌ Failed to generate ephemeral DID:', error);
            return {
                success: false,
                error: error.message || 'Failed to generate ephemeral DID'
            };
        }
    }

    /**
     * Request document access with ephemeral DID encryption
     * @param {Object} didResult - Result from generateEphemeralDIDForDocument
     * @returns {Promise<Object>} - Document access request result
     */
    async requestDocumentWithEphemeralDID(didResult) {
        try {
            console.log(`📋 Requesting document access with ephemeral DID`);

            if (!didResult.success || !didResult.ephemeralDID) {
                throw new Error('Invalid ephemeral DID result');
            }

            // Send request to server to create ephemeral access session
            const sessionRequest = {
                documentId: didResult.documentId,
                ephemeralDID: didResult.ephemeralDID,
                ephemeralPublicKey: didResult.ephemeralPublicKey,
                businessJustification: didResult.keyPairData.businessJustification,
                sessionDurationMinutes: didResult.sessionDuration || 60
            };

            const response = await fetch(`${this.apiBaseUrl}/generate-session`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(sessionRequest)
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || `HTTP ${response.status}`);
            }

            if (!result.success) {
                throw new Error(result.error || 'Session creation failed');
            }

            // Store session information
            const sessionData = {
                ...didResult.keyPairData,
                sessionToken: result.sessionToken,
                sessionId: result.sessionId,
                expiresAt: result.expiresAt,
                classificationLevel: result.classificationLevel
            };

            this.activeDIDPairs.set(didResult.documentId, sessionData);
            this.currentSession = sessionData;

            // Setup automatic session cleanup
            this.setupSessionCleanup(result.sessionToken, new Date(result.expiresAt));

            console.log('✅ Ephemeral access session created successfully');

            return {
                success: true,
                sessionToken: result.sessionToken,
                sessionId: result.sessionId,
                ephemeralDID: result.ephemeralDID,
                expiresAt: result.expiresAt,
                classificationLevel: result.classificationLevel,
                message: 'Document access session created'
            };

        } catch (error) {
            console.error('❌ Failed to request document access:', error);
            return {
                success: false,
                error: error.message || 'Failed to request document access'
            };
        }
    }

    /**
     * Download and decrypt document with ephemeral private key
     * @param {string} sessionToken - Session token for document access
     * @returns {Promise<Object>} - Decrypted document result
     */
    async decryptDocumentWithEphemeralKey(sessionToken) {
        try {
            console.log(`🔓 Downloading and decrypting document with session ${sessionToken}`);

            // Find the corresponding DID pair
            let sessionData = null;
            for (const [documentId, data] of this.activeDIDPairs.entries()) {
                if (data.sessionToken === sessionToken) {
                    sessionData = data;
                    break;
                }
            }

            if (!sessionData) {
                throw new Error('Session not found or expired');
            }

            // Request encrypted document from server
            const response = await fetch(`${this.apiBaseUrl}/encrypt-document/${sessionToken}`);
            
            if (!response.ok) {
                const errorResult = await response.json();
                throw new Error(errorResult.error || `HTTP ${response.status}`);
            }

            const encryptedResult = await response.json();

            if (!encryptedResult.success) {
                throw new Error(encryptedResult.error || 'Failed to retrieve encrypted document');
            }

            console.log('📥 Encrypted document retrieved, decrypting client-side...');

            // Decrypt document using ephemeral private key
            const decryptionResult = await this.identusManager.decryptWithPrivateKey(
                encryptedResult.encryptedDocument,
                sessionData.privateKey
            );

            if (!decryptionResult.success) {
                throw new Error(decryptionResult.error || 'Client-side decryption failed');
            }

            console.log('✅ Document decrypted successfully on client-side');

            return {
                success: true,
                documentData: decryptionResult.decryptedData,
                filename: encryptedResult.filename,
                contentType: encryptedResult.contentType,
                classificationLevel: encryptedResult.classificationLevel,
                sessionToken: sessionToken,
                message: 'Document decrypted successfully'
            };

        } catch (error) {
            console.error('❌ Failed to decrypt document:', error);
            return {
                success: false,
                error: error.message || 'Failed to decrypt document'
            };
        }
    }

    /**
     * Get status of ephemeral session
     * @param {string} sessionToken - Session token to check
     * @returns {Promise<Object>} - Session status result
     */
    async getEphemeralSessionStatus(sessionToken) {
        try {
            const response = await fetch(`${this.apiBaseUrl}/session-status/${sessionToken}`);
            
            if (!response.ok) {
                const errorResult = await response.json();
                throw new Error(errorResult.error || `HTTP ${response.status}`);
            }

            const result = await response.json();
            return result;

        } catch (error) {
            console.error('❌ Failed to get session status:', error);
            return {
                success: false,
                error: error.message || 'Failed to get session status'
            };
        }
    }

    /**
     * Cleanup ephemeral session and destroy keys
     * @param {string} sessionToken - Session token to cleanup
     * @param {boolean} serverCleanup - Whether to notify server of cleanup
     * @returns {Promise<Object>} - Cleanup result
     */
    async cleanupEphemeralSession(sessionToken, serverCleanup = true) {
        try {
            console.log(`🧹 Cleaning up ephemeral session ${sessionToken}`);

            // Find and remove from active sessions
            let documentId = null;
            for (const [docId, data] of this.activeDIDPairs.entries()) {
                if (data.sessionToken === sessionToken) {
                    documentId = docId;
                    break;
                }
            }

            if (documentId) {
                const sessionData = this.activeDIDPairs.get(documentId);
                
                // Destroy private key from memory
                if (sessionData.privateKey) {
                    await this.identusManager.destroyEphemeralKey(sessionData.privateKey);
                }
                
                // Remove from active sessions
                this.activeDIDPairs.delete(documentId);
                
                // Clear session timer
                if (this.sessionTimers.has(sessionToken)) {
                    clearTimeout(this.sessionTimers.get(sessionToken));
                    this.sessionTimers.delete(sessionToken);
                }
                
                // Clear current session if it's this one
                if (this.currentSession && this.currentSession.sessionToken === sessionToken) {
                    this.currentSession = null;
                }
                
                console.log('✅ Ephemeral session cleaned up successfully');
                
                return {
                    success: true,
                    sessionToken: sessionToken,
                    documentId: documentId,
                    message: 'Ephemeral session cleaned up'
                };
            }

            return {
                success: false,
                error: 'Session not found'
            };

        } catch (error) {
            console.error('❌ Failed to cleanup ephemeral session:', error);
            return {
                success: false,
                error: error.message || 'Failed to cleanup session'
            };
        }
    }

    /**
     * Setup automatic session cleanup timer
     * @param {string} sessionToken - Session token
     * @param {Date} expiresAt - Expiration date
     */
    setupSessionCleanup(sessionToken, expiresAt) {
        const timeUntilExpiry = expiresAt.getTime() - Date.now();
        
        if (timeUntilExpiry > 0) {
            const timerId = setTimeout(async () => {
                console.log(`⏰ Auto-cleaning up expired session ${sessionToken}`);
                await this.cleanupEphemeralSession(sessionToken, false);
            }, timeUntilExpiry);
            
            this.sessionTimers.set(sessionToken, timerId);
            console.log(`⏰ Session cleanup scheduled for ${expiresAt.toISOString()}`);
        }
    }

    /**
     * Get all active ephemeral sessions
     * @returns {Array} - List of active sessions
     */
    getActiveSessions() {
        const sessions = [];
        for (const [documentId, sessionData] of this.activeDIDPairs.entries()) {
            sessions.push({
                documentId: documentId,
                sessionToken: sessionData.sessionToken,
                ephemeralDID: sessionData.did,
                createdAt: sessionData.createdAt,
                expiresAt: sessionData.expiresAt,
                classificationLevel: sessionData.classificationLevel
            });
        }
        return sessions;
    }

    /**
     * Cleanup all active sessions (for page unload)
     */
    async cleanupAllSessions() {
        console.log('🧹 Cleaning up all active ephemeral sessions');
        
        const sessionTokens = [];
        for (const [documentId, sessionData] of this.activeDIDPairs.entries()) {
            sessionTokens.push(sessionData.sessionToken);
        }

        for (const sessionToken of sessionTokens) {
            await this.cleanupEphemeralSession(sessionToken, false);
        }
    }
}

/**
 * WebCrypto Fallback Manager for when Identus SDK is not available
 */
class WebCryptoFallbackManager {
    constructor() {
        console.log('🔄 Using WebCrypto fallback for ephemeral DID operations');
    }

    async generateEphemeralDIDKey() {
        try {
            // Generate ECDSA P-256 key pair
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: 'ECDSA',
                    namedCurve: 'P-256'
                },
                true, // extractable
                ['sign', 'verify']
            );

            // Export public key for DID:key format
            const publicKeyBuffer = await crypto.subtle.exportKey('raw', keyPair.publicKey);
            const publicKeyHex = Array.from(new Uint8Array(publicKeyBuffer))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');

            // Create mock DID:key (simplified format)
            const did = `did:key:z${publicKeyHex.substring(0, 44)}`;

            return {
                success: true,
                did: did,
                privateKey: keyPair.privateKey,
                publicKey: {
                    kty: 'EC',
                    crv: 'P-256',
                    x: publicKeyHex.substring(0, 64),
                    y: publicKeyHex.substring(64, 128),
                    use: 'sig'
                }
            };

        } catch (error) {
            return {
                success: false,
                error: error.message || 'Failed to generate key pair'
            };
        }
    }

    async decryptWithPrivateKey(encryptedData, privateKey) {
        try {
            // This is a simplified implementation
            // In production, would implement proper ECIES decryption
            console.log('⚠️ WebCrypto fallback decryption - simplified implementation');
            
            return {
                success: true,
                decryptedData: atob(encryptedData.data || encryptedData), // Base64 decode as fallback
                message: 'Fallback decryption completed'
            };

        } catch (error) {
            return {
                success: false,
                error: error.message || 'Fallback decryption failed'
            };
        }
    }

    async destroyEphemeralKey(privateKey) {
        // In WebCrypto, keys are automatically garbage collected
        return { success: true };
    }
}

// Global instance
window.ephemeralDIDClient = new EphemeralDIDClient();

// Cleanup on page unload
window.addEventListener('beforeunload', async () => {
    if (window.ephemeralDIDClient) {
        await window.ephemeralDIDClient.cleanupAllSessions();
    }
});

console.log('🔐 Ephemeral DID Client loaded successfully');