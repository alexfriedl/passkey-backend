/**
 * Security Configuration for Passkey Registration
 * 
 * Defines which domains require enhanced security (App Attest)
 * and which can use standard WebAuthn flow
 */

export interface SecurityConfig {
  requiresAppAttest: (email: string) => boolean;
  isEnhancedDomain: (domain: string) => boolean;
  allowStandardFallback: boolean;
}

// Domains that require App Attest (enhanced security)
const ENHANCED_SECURITY_DOMAINS = [
  'merck.com',
  'merckgroup.com',
  'emdgroup.com',
];

// Email patterns for enhanced security (regex)
const ENHANCED_SECURITY_PATTERNS = [
  /.*@.*\.merck\.com$/,
  /.*@.*\.merckgroup\.com$/,
  /.*@.*\.emdgroup\.com$/
];

export const securityConfig: SecurityConfig = {
  /**
   * Check if an email requires App Attest
   */
  requiresAppAttest: (email: string): boolean => {
    if (!email) return false;
    
    // Check direct domain match
    const domain = email.split('@')[1]?.toLowerCase();
    if (!domain) return false;
    
    if (ENHANCED_SECURITY_DOMAINS.includes(domain)) {
      return true;
    }
    
    // Check pattern match (for subdomains)
    return ENHANCED_SECURITY_PATTERNS.some(pattern => pattern.test(email));
  },
  
  /**
   * Check if a domain is configured for enhanced security
   */
  isEnhancedDomain: (domain: string): boolean => {
    if (!domain) return false;
    return ENHANCED_SECURITY_DOMAINS.includes(domain.toLowerCase());
  },
  
  /**
   * Allow standard registration as fallback when App Attest is not available
   */
  allowStandardFallback: process.env.ALLOW_STANDARD_FALLBACK !== 'false'
};

// Export helper functions
export const requiresAppAttest = securityConfig.requiresAppAttest;
export const isEnhancedDomain = securityConfig.isEnhancedDomain;