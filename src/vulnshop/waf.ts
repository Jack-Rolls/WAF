/**
 * WAF Rules Engine and Inspector
 * 
 * Defines OWASP-aligned detection rules and inspection logic.
 * Rules are kept as a flat, readable array for easy auditability.
 */

export interface WafRule {
  id: string;
  category: 'sqli' | 'xss' | 'path_traversal' | 'command_injection';
  severity: 'low' | 'med' | 'high';
  description: string;
  pattern: RegExp;
}

export interface InspectionResult {
  matchedRules: WafRule[];
  verdict: 'allowed' | 'blocked' | 'challenged';
  matchedCategories: Set<string>;
}

/**
 * WAF Detection Rules
 * ~15 rules across 4 OWASP categories
 * Each rule targets a common attack pattern
 */
export const WAF_RULES: WafRule[] = [
  // === SQL Injection ===
  {
    id: 'sqli_001',
    category: 'sqli',
    severity: 'high',
    description: 'Single quote with OR keyword (OR 1=1 variant)',
    pattern: /['"]?\s*or\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i,
  },
  {
    id: 'sqli_002',
    category: 'sqli',
    severity: 'high',
    description: 'UNION SELECT statement',
    pattern: /union\s+select/i,
  },
  {
    id: 'sqli_003',
    category: 'sqli',
    severity: 'high',
    description: 'SQL comment sequence (-- or #)',
    pattern: /(--\s|#\s|\/\*)/,
  },
  {
    id: 'sqli_004',
    category: 'sqli',
    severity: 'med',
    description: 'DROP TABLE keyword',
    pattern: /drop\s+(table|database|schema)/i,
  },
  {
    id: 'sqli_005',
    category: 'sqli',
    severity: 'med',
    description: 'EXEC or EXECUTE keyword',
    pattern: /(exec|execute)\s*\(/i,
  },

  // === Cross-Site Scripting (XSS) ===
  {
    id: 'xss_001',
    category: 'xss',
    severity: 'high',
    description: 'Script tag',
    pattern: /<\s*script[^>]*>/i,
  },
  {
    id: 'xss_002',
    category: 'xss',
    severity: 'high',
    description: 'Event handler (onerror, onload, onfocus, etc)',
    pattern: /\s(on\w+)\s*=\s*['"]/i,
  },
  {
    id: 'xss_003',
    category: 'xss',
    severity: 'high',
    description: 'JavaScript protocol',
    pattern: /javascript\s*:/i,
  },
  {
    id: 'xss_004',
    category: 'xss',
    severity: 'med',
    description: 'Data URI protocol with javascript',
    pattern: /data:[^,]*javascript/i,
  },
  {
    id: 'xss_005',
    category: 'xss',
    severity: 'med',
    description: 'SVG with embedded script',
    pattern: /<\s*svg[^>]*onload\s*=/i,
  },

  // === Path Traversal ===
  {
    id: 'path_001',
    category: 'path_traversal',
    severity: 'high',
    description: 'Directory traversal (../ or ..\\)',
    pattern: /\.\.[\/\\]/,
  },
  {
    id: 'path_002',
    category: 'path_traversal',
    severity: 'high',
    description: 'Absolute path to sensitive files (/etc/passwd, /windows/)',
    pattern: /(\/etc\/|\/windows\/|C:\\windows|\/sys\/)/i,
  },
  {
    id: 'path_003',
    category: 'path_traversal',
    severity: 'med',
    description: 'Encoded traversal (%2e%2e)',
    pattern: /%2e%2e|%252e%252e/i,
  },

  // === Command Injection ===
  {
    id: 'cmd_001',
    category: 'command_injection',
    severity: 'high',
    description: 'Command separator with shell command (;, |, &&, ||)',
    pattern: /[;|&]\s*(cat|ls|whoami|nc|ncat|bash|sh|cmd|powershell|wget|curl|dir|net|type|tasklist|del)/i,
  },
  {
    id: 'cmd_002',
    category: 'command_injection',
    severity: 'high',
    description: 'Command substitution with backticks or $(...)',
    pattern: /[`$]\([^)]*\)|\$\{[^}]*\}|`[^`]+`/,
  },
  {
    id: 'cmd_003',
    category: 'command_injection',
    severity: 'med',
    description: 'Newline or carriage return injection',
    pattern: /(%0a|%0d|\\n|\\r)/i,
  },
];

/**
 * Decode URL-encoded string
 * Safely handles malformed encoding without throwing
 */
function safeUrlDecode(encoded: string): string {
  try {
    return decodeURIComponent(encoded);
  } catch {
    // If decode fails, return the original string
    return encoded;
  }
}

/**
 * Inspect a request against all WAF rules
 * Returns matched rules, verdict, and attack categories
 * 
 * Inspection targets:
 * - URL path (decoded)
 * - Query string (decoded)
 * - Request body preview (first 2KB, decoded)
 * - User-Agent header
 * - Referer header
 */
export function inspectRequest(
  method: string,
  path: string,
  query: string | undefined,
  bodyText: string | undefined,
  userAgent: string | undefined,
  referer: string | undefined
): InspectionResult {
  const matchedRules: WafRule[] = [];
  const matchedCategories = new Set<string>();

  // Inspection targets (decoded)
  const inspectionTargets = [
    safeUrlDecode(path),
    query ? safeUrlDecode(query) : '',
    bodyText ? safeUrlDecode(bodyText.substring(0, 2048)) : '',
    userAgent || '',
    referer ? safeUrlDecode(referer) : '',
  ];

  // Run each rule against all inspection targets
  for (const rule of WAF_RULES) {
    for (const target of inspectionTargets) {
      if (rule.pattern.test(target)) {
        matchedRules.push(rule);
        matchedCategories.add(rule.category);
        break; // Only match each rule once per request
      }
    }
  }

  // Severity rollup: high → block, med → challenge, low → allow
  let verdict: 'allowed' | 'blocked' | 'challenged' = 'allowed';
  if (matchedRules.some((r) => r.severity === 'high')) {
    verdict = 'blocked';
  } else if (matchedRules.some((r) => r.severity === 'med')) {
    verdict = 'challenged';
  }

  return { matchedRules, verdict, matchedCategories };
}
