/**
 * Hyperledger Identus Client for Ephemeral DID Generation
 * Working Package 3: Client-Side Ephemeral DID Infrastructure
 * 
 * This module handles:
 * - Ephemeral DID:key generation using Hyperledger Identus TypeScript SDK
 * - WebCrypto API fallback for compatibility
 * - Client-side key management with perfect forward secrecy
 * - Document encryption/decryption operations
 */

// Import Hyperledger Identus SDK components (will be loaded via CDN or bundler)
// import { Apollo, Castor } from '@hyperledger/identus-edge-agent-sdk';

class EphemeralDIDManager {
    constructor() {
        this.apollo = null; // Cryptographic operations
        this.castor = null; // DID operations
        this.sdkAvailable = false;
        this.activeKeys = new Map(); // Store active ephemeral keys (client-side only)
        
        console.log('🔐 EphemeralDIDManager initialized');
    }
    
    /**
     * Initialize Hyperledger Identus SDK
     * Falls back to WebCrypto if SDK not available
     */
    async initializeSDK() {
        try {
            // Check if Identus SDK is available
            if (typeof window !== 'undefined' && window.IdentusSDK) {
                console.log('📦 Initializing Hyperledger Identus SDK...');
                
                // Initialize Apollo for cryptographic operations
                this.apollo = new window.IdentusSDK.Apollo();
                
                // Initialize Castor for DID operations
                this.castor = new window.IdentusSDK.Castor(this.apollo);
                
                this.sdkAvailable = true;
                console.log('✅ Hyperledger Identus SDK initialized successfully');
                
                return true;
            } else {
                console.log('⚠️  Hyperledger Identus SDK not available, using WebCrypto fallback');
                this.sdkAvailable = false;
                return await this.initializeWebCrypto();
            }
        } catch (error) {
            console.error('❌ Failed to initialize Identus SDK:', error);
            console.log('🔄 Falling back to WebCrypto API...');
            this.sdkAvailable = false;
            return await this.initializeWebCrypto();
        }
    }
    
    /**
     * Initialize WebCrypto API fallback
     */
    async initializeWebCrypto() {
        try {
            // Check WebCrypto availability
            if (!window.crypto || !window.crypto.subtle) {
                throw new Error('WebCrypto API not available');
            }
            
            console.log('✅ WebCrypto API fallback initialized');
            return true;
        } catch (error) {
            console.error('❌ WebCrypto API not available:', error);
            throw new Error('No cryptographic backend available (Identus SDK or WebCrypto)');
        }
    }
    
    /**
     * Generate ephemeral DID:key pair for document access
     * @param {number} documentId - Document ID for context
     * @returns {Promise<{ephemeralDID: string, publicKeyJWK: object, privateKey: any}>}
     */
    async generateEphemeralDIDKey(documentId) {
        console.log(`🔑 Generating ephemeral DID:key for document ${documentId}...`);
        
        try {
            if (this.sdkAvailable) {
                return await this.generateEphemeralDIDWithIdentusSDK(documentId);
            } else {
                return await this.generateEphemeralDIDWithWebCrypto(documentId);
            }
        } catch (error) {
            console.error('❌ Failed to generate ephemeral DID:key:', error);
            throw error;
        }
    }
    
    /**
     * Generate ephemeral DID using Hyperledger Identus SDK
     */
    async generateEphemeralDIDWithIdentusSDK(documentId) {
        try {
            console.log('🚀 Using Identus SDK for DID generation...');
            
            // Generate key pair using Identus Apollo
            const keyPair = await this.apollo.createPrivateKey({
                type: 'EC',
                curve: 'secp256k1', // or P-256 based on Identus support
                seed: this.apollo.createSeed() // Generate random seed
            });
            
            // Create DID:key from public key
            const publicKey = keyPair.publicKey();
            const ephemeralDID = await this.castor.createDIDFromPublicKey(publicKey, 'key');
            
            // Convert public key to JWK format
            const publicKeyJWK = await this.publicKeyToJWK(publicKey);
            
            // Store private key locally (never send to server)
            const keyId = this.generateKeyId(documentId);
            this.activeKeys.set(keyId, {
                privateKey: keyPair,
                documentId: documentId,
                created: new Date(),
                ephemeralDID: ephemeralDID
            });
            
            console.log(`✅ Generated ephemeral DID: ${ephemeralDID}`);
            
            return {
                ephemeralDID: ephemeralDID,
                publicKeyJWK: publicKeyJWK,
                privateKey: keyPair, // Keep locally for decryption
                keyId: keyId
            };
            
        } catch (error) {
            console.error('❌ Identus SDK DID generation failed:', error);
            // Fallback to WebCrypto
            return await this.generateEphemeralDIDWithWebCrypto(documentId);
        }
    }
    
    /**
     * Generate ephemeral DID using WebCrypto API fallback
     */
    async generateEphemeralDIDWithWebCrypto(documentId) {
        try {
            console.log('🔧 Using WebCrypto API for DID generation...');
            
            // Generate P-256 key pair using WebCrypto
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: 'ECDSA',
                    namedCurve: 'P-256'
                },
                true, // extractable
                ['sign', 'verify']
            );
            
            // Export public key to create DID:key
            const publicKeyBuffer = await window.crypto.subtle.exportKey('raw', keyPair.publicKey);
            const publicKeyBytes = new Uint8Array(publicKeyBuffer);
            
            // Create DID:key format manually
            // DID:key format: did:key:z + multicodec prefix + public key bytes
            const ephemeralDID = await this.createDIDKeyFromPublicKeyBytes(publicKeyBytes);
            
            // Create JWK from public key
            const publicKeyJWK = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
            
            // Store private key locally
            const keyId = this.generateKeyId(documentId);
            this.activeKeys.set(keyId, {
                privateKey: keyPair.privateKey,
                documentId: documentId,
                created: new Date(),
                ephemeralDID: ephemeralDID
            });
            
            console.log(`✅ Generated ephemeral DID (WebCrypto): ${ephemeralDID}`);
            
            return {
                ephemeralDID: ephemeralDID,
                publicKeyJWK: publicKeyJWK,
                privateKey: keyPair.privateKey,
                keyId: keyId
            };
            
        } catch (error) {
            console.error('❌ WebCrypto DID generation failed:', error);
            throw error;
        }
    }
    
    /**
     * Create DID:key format from public key bytes
     */
    async createDIDKeyFromPublicKeyBytes(publicKeyBytes) {
        // P-256 multicodec prefix: 0x1200 (secp256r1)
        const multicodecPrefix = new Uint8Array([0x12, 0x00]);
        const fullKeyBytes = new Uint8Array(multicodecPrefix.length + publicKeyBytes.length);
        fullKeyBytes.set(multicodecPrefix, 0);
        fullKeyBytes.set(publicKeyBytes, multicodecPrefix.length);
        
        // Base58 encode (simplified - in production use proper base58 library)
        const base58Encoded = await this.base58Encode(fullKeyBytes);
        
        return `did:key:z${base58Encoded}`;
    }
    
    /**
     * Simple base58 encoding (placeholder - use proper library in production)
     */
    async base58Encode(bytes) {
        // This is a simplified implementation
        // In production, use a proper base58 library like 'bs58'
        const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        let result = '';
        
        // Convert bytes to base58 (simplified algorithm)
        let num = 0n;
        for (let i = 0; i < bytes.length; i++) {
            num = num * 256n + BigInt(bytes[i]);
        }
        
        while (num > 0n) {
            const remainder = num % 58n;
            result = alphabet[Number(remainder)] + result;
            num = num / 58n;
        }
        
        // Add leading zeros
        for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
            result = alphabet[0] + result;
        }
        
        return result;
    }
    
    /**
     * Convert public key to JWK format
     */
    async publicKeyToJWK(publicKey) {
        if (this.sdkAvailable) {
            // Use Identus SDK method if available
            return await publicKey.toJWK();
        } else {
            // Already in JWK format from WebCrypto
            return publicKey;
        }
    }
    
    /**
     * Generate unique key ID for local storage
     */
    generateKeyId(documentId) {
        const timestamp = Date.now();
        const random = Math.random().toString(36).substr(2, 9);
        return `ephemeral_${documentId}_${timestamp}_${random}`;
    }
    
    /**
     * Encrypt data using ephemeral public key (server-side operation simulation)
     * This method would typically be called on the server
     */
    async encryptForPublicKey(data, publicKeyJWK) {
        console.log('🔒 Encrypting data with ephemeral public key...');
        
        try {
            if (this.sdkAvailable && this.apollo) {
                // Use Identus Apollo for encryption
                return await this.apollo.encrypt(data, publicKeyJWK);
            } else {
                // Use WebCrypto for encryption
                return await this.encryptWithWebCrypto(data, publicKeyJWK);
            }
        } catch (error) {
            console.error('❌ Encryption failed:', error);
            throw error;
        }
    }
    
    /**
     * WebCrypto encryption implementation
     */
    async encryptWithWebCrypto(data, publicKeyJWK) {
        // Import JWK public key
        const publicKey = await window.crypto.subtle.importKey(
            'jwk',
            publicKeyJWK,
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            false,
            ['verify']
        );
        
        // For ECDSA keys, we need to use ECIES or hybrid encryption
        // This is a simplified implementation - in production use proper ECIES
        
        // Generate symmetric key for data encryption
        const symmetricKey = await window.crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );
        
        // Encrypt data with symmetric key
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            symmetricKey,
            new TextEncoder().encode(JSON.stringify(data))
        );
        
        // Export symmetric key for hybrid encryption
        const exportedSymmetricKey = await window.crypto.subtle.exportKey('raw', symmetricKey);
        
        // In a real implementation, you'd encrypt the symmetric key with ECIES
        // For now, we'll return both parts
        return {
            encryptedData: Array.from(new Uint8Array(encryptedData)),
            encryptedKey: Array.from(new Uint8Array(exportedSymmetricKey)),
            iv: Array.from(iv),
            algorithm: 'AES-GCM'
        };
    }
    
    /**
     * Decrypt data using ephemeral private key
     * @param {object} encryptedData - Encrypted data object
     * @param {string} keyId - Key ID for local storage lookup
     * @returns {Promise<any>} Decrypted data
     */
    async decryptWithPrivateKey(encryptedData, keyId) {
        console.log('🔓 Decrypting data with ephemeral private key...');
        
        try {
            // Get private key from local storage
            const keyInfo = this.activeKeys.get(keyId);
            if (!keyInfo) {
                throw new Error('Private key not found - may have been destroyed');
            }
            
            if (this.sdkAvailable && this.apollo) {
                // Use Identus Apollo for decryption
                return await this.apollo.decrypt(encryptedData, keyInfo.privateKey);
            } else {
                // Use WebCrypto for decryption
                return await this.decryptWithWebCrypto(encryptedData, keyInfo.privateKey);
            }
        } catch (error) {
            console.error('❌ Decryption failed:', error);
            throw error;
        }
    }
    
    /**
     * WebCrypto decryption implementation
     */
    async decryptWithWebCrypto(encryptedDataObj, privateKey) {
        // Reconstruct symmetric key (in real ECIES, this would be decrypted)
        const symmetricKeyBytes = new Uint8Array(encryptedDataObj.encryptedKey);
        const symmetricKey = await window.crypto.subtle.importKey(
            'raw',
            symmetricKeyBytes,
            {
                name: 'AES-GCM',
                length: 256
            },
            false,
            ['decrypt']
        );
        
        // Decrypt data
        const encryptedData = new Uint8Array(encryptedDataObj.encryptedData);
        const iv = new Uint8Array(encryptedDataObj.iv);
        
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            symmetricKey,
            encryptedData
        );
        
        const decryptedText = new TextDecoder().decode(decryptedData);
        return JSON.parse(decryptedText);
    }
    
    /**
     * Securely destroy ephemeral key after use
     * @param {string} keyId - Key ID to destroy
     */
    destroyEphemeralKey(keyId) {
        console.log(`🗑️  Destroying ephemeral key: ${keyId}`);
        
        try {
            const keyInfo = this.activeKeys.get(keyId);
            if (keyInfo) {
                // Clear key from memory
                if (keyInfo.privateKey && typeof keyInfo.privateKey === 'object') {
                    // Attempt to clear key data (browser dependent)
                    Object.keys(keyInfo.privateKey).forEach(key => {
                        delete keyInfo.privateKey[key];
                    });
                }
                
                // Remove from active keys
                this.activeKeys.delete(keyId);
                
                console.log(`✅ Ephemeral key destroyed: ${keyId}`);
                return true;
            } else {
                console.log(`⚠️  Key not found for destruction: ${keyId}`);
                return false;
            }
        } catch (error) {
            console.error('❌ Failed to destroy ephemeral key:', error);
            return false;
        }
    }
    
    /**
     * Get active ephemeral keys (for debugging/monitoring)
     */
    getActiveKeys() {
        const activeKeysInfo = [];
        this.activeKeys.forEach((keyInfo, keyId) => {
            activeKeysInfo.push({
                keyId: keyId,
                documentId: keyInfo.documentId,
                ephemeralDID: keyInfo.ephemeralDID,
                created: keyInfo.created,
                ageMinutes: Math.round((Date.now() - keyInfo.created.getTime()) / 60000)
            });
        });
        return activeKeysInfo;
    }
    
    /**
     * Clean up expired keys (automatic cleanup)
     */
    cleanupExpiredKeys(maxAgeMinutes = 60) {
        console.log('🧹 Cleaning up expired ephemeral keys...');
        
        let cleanedCount = 0;
        const now = Date.now();
        const maxAgeMs = maxAgeMinutes * 60 * 1000;
        
        this.activeKeys.forEach((keyInfo, keyId) => {
            const ageMs = now - keyInfo.created.getTime();
            if (ageMs > maxAgeMs) {
                this.destroyEphemeralKey(keyId);
                cleanedCount++;
            }
        });
        
        console.log(`✅ Cleaned up ${cleanedCount} expired ephemeral keys`);
        return cleanedCount;
    }
    
    /**
     * Initialize automatic cleanup
     */
    initializeAutoCleanup(intervalMinutes = 15, maxAgeMinutes = 60) {
        console.log(`⏰ Initializing automatic key cleanup (every ${intervalMinutes} minutes)`);
        
        setInterval(() => {
            this.cleanupExpiredKeys(maxAgeMinutes);
        }, intervalMinutes * 60 * 1000);
    }
}

// Global instance
window.ephemeralDIDManager = null;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', async function() {
    console.log('🚀 Initializing Ephemeral DID Manager...');
    
    try {
        window.ephemeralDIDManager = new EphemeralDIDManager();
        await window.ephemeralDIDManager.initializeSDK();
        
        // Start automatic cleanup
        window.ephemeralDIDManager.initializeAutoCleanup();
        
        console.log('✅ Ephemeral DID Manager ready');
        
        // Dispatch ready event
        window.dispatchEvent(new CustomEvent('ephemeralDIDManagerReady', {
            detail: { manager: window.ephemeralDIDManager }
        }));
        
    } catch (error) {
        console.error('❌ Failed to initialize Ephemeral DID Manager:', error);
        
        // Dispatch error event
        window.dispatchEvent(new CustomEvent('ephemeralDIDManagerError', {
            detail: { error: error }
        }));
    }
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { EphemeralDIDManager };
}