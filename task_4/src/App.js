// App.js
import React, { useState, useEffect } from 'react';
import './App.css';

// Enhanced security headers definitions with more comprehensive information
const securityHeaders = [
  {
    name: 'Strict-Transport-Security',
    description: 'Enforces secure (HTTPS) connections to the server',
    recommendation: 'max-age=31536000; includeSubDomains; preload',
    risk: 'High',
    impact: 'Prevents downgrade attacks and cookie hijacking',
    learnMore: 'https://owasp.org/www-project-secure-headers/#strict-transport-security',
    category: 'Transport Security',
  },
  {
    name: 'X-Frame-Options',
    description: 'Protects against clickjacking attacks',
    recommendation: 'DENY or SAMEORIGIN',
    risk: 'Medium',
    impact: 'Prevents your site from being embedded in iframes on malicious sites',
    learnMore: 'https://owasp.org/www-project-secure-headers/#x-frame-options',
    category: 'Content Embedding',
  },
  {
    name: 'X-Content-Type-Options',
    description: 'Prevents MIME-sniffing attacks',
    recommendation: 'nosniff',
    risk: 'Medium',
    impact: 'Ensures browsers respect declared content types, preventing MIME confusion attacks',
    learnMore: 'https://owasp.org/www-project-secure-headers/#x-content-type-options',
    category: 'Content Handling',
  },
  {
    name: 'Content-Security-Policy',
    description: 'Defines approved sources of content',
    recommendation: "default-src 'self'; script-src 'self'; object-src 'none'; img-src 'self'; style-src 'self'; frame-ancestors 'none';",
    risk: 'High',
    impact: 'Mitigates XSS and data injection attacks by controlling resources the browser is allowed to load',
    learnMore: 'https://owasp.org/www-project-secure-headers/#content-security-policy',
    category: 'Content Security',
  },
  {
    name: 'X-XSS-Protection',
    description: 'Mitigates Cross-Site Scripting (XSS) attacks',
    recommendation: '1; mode=block',
    risk: 'Medium',
    impact: 'Enables browser\'s built-in XSS filters to block suspicious scripts',
    learnMore: 'https://owasp.org/www-project-secure-headers/#x-xss-protection',
    category: 'XSS Prevention',
  },
  {
    name: 'Referrer-Policy',
    description: 'Controls how much referrer information should be included with requests',
    recommendation: 'strict-origin-when-cross-origin',
    risk: 'Medium',
    impact: 'Prevents leaking sensitive data through the Referer header',
    learnMore: 'https://owasp.org/www-project-secure-headers/#referrer-policy',
    category: 'Privacy',
  },
  {
    name: 'Permissions-Policy',
    description: 'Controls which browser features can be used (replaces Feature-Policy)',
    recommendation: 'camera=(), microphone=(), geolocation=(), payment=()',
    risk: 'Medium',
    impact: 'Restricts which browser features and APIs can be used, reducing attack surface',
    learnMore: 'https://owasp.org/www-project-secure-headers/#permissions-policy',
    category: 'Feature Control',
  },
  {
    name: 'Cache-Control',
    description: 'Directives for caching mechanisms',
    recommendation: 'no-store, max-age=0',
    risk: 'Medium',
    impact: 'Prevents caching of sensitive data that could be accessed by unauthorized users',
    learnMore: 'https://owasp.org/www-community/controls/Cache_Control_Headers',
    category: 'Caching Policy',
  },
  {
    name: 'X-Permitted-Cross-Domain-Policies',
    description: 'Controls how Adobe products handle data across domains',
    recommendation: 'none',
    risk: 'Low',
    impact: 'Prevents Adobe Flash and Adobe Acrobat from loading data across domains',
    learnMore: 'https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies',
    category: 'Cross-Domain',
  },
  {
    name: 'Clear-Site-Data',
    description: 'Clears browsing data (cookies, storage, cache) associated with the site',
    recommendation: '"cookies", "storage", "cache"',
    risk: 'Low',
    impact: 'Useful for logout functionality to ensure all user data is properly cleared',
    learnMore: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data',
    category: 'Privacy',
  },
  {
    name: 'Cross-Origin-Embedder-Policy',
    description: 'Controls whether the document can load cross-origin resources',
    recommendation: 'require-corp',
    risk: 'Medium',
    impact: 'Protects against Spectre attacks by ensuring cross-origin resources explicitly grant permission',
    learnMore: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy',
    category: 'Resource Loading',
  },
  {
    name: 'Cross-Origin-Opener-Policy',
    description: 'Controls sharing of browsing context group with cross-origin documents',
    recommendation: 'same-origin',
    risk: 'Medium',
    impact: 'Isolates your site from others, preventing attackers from accessing your window object',
    learnMore: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy',
    category: 'Resource Loading',
  },
  {
    name: 'Cross-Origin-Resource-Policy',
    description: 'Controls which cross-origin sites can load the resource',
    recommendation: 'same-origin',
    risk: 'Medium',
    impact: 'Prevents other websites from embedding your resources to protect against side-channel attacks',
    learnMore: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy',
    category: 'Resource Loading',
  },
];

function App() {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [score, setScore] = useState(null);
  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [showExport, setShowExport] = useState(false);
  const [proxyUrl, setProxyUrl] = useState('https://cors-anywhere.herokuapp.com/');
  
  // Initialize dark mode based on user preference or localStorage
  useEffect(() => {
    const savedTheme = localStorage.getItem('darkMode');
    if (savedTheme) {
      setDarkMode(savedTheme === 'true');
    } else {
      // Check if user prefers dark mode
      const prefersDarkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      setDarkMode(prefersDarkMode);
    }
  }, []);
  const [showProxySettings, setShowProxySettings] = useState(false);
  const [darkMode, setDarkMode] = useState(false);

  // Get unique categories for the filter
  const categories = ['All', ...new Set(securityHeaders.map(header => header.category))];

  const checkHeaders = async () => {
    // Reset states
    setResults(null);
    setError('');
    setScore(null);
    setLoading(true);

    try {
      // Format the URL if needed
      let formattedUrl = url;
      if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
        formattedUrl = 'https://' + formattedUrl;
      }

      // For security reasons, we need a backend server to make the request
      // Alternatively for a demo, we can use a CORS proxy service
      const response = await fetch(`${proxyUrl}${formattedUrl}`, {
        method: 'HEAD',
      });

      const headers = {};
      for (const [key, value] of response.headers.entries()) {
        headers[key.toLowerCase()] = value;
      }

      // Process the results
      const headerResults = securityHeaders.map(header => {
        const headerName = header.name.toLowerCase();
        const headerValue = headers[headerName] || null;
        const compliance = analyzeCompliance(headerName, headerValue);
        
        return {
          ...header,
          name: header.name,
          value: headerValue,
          status: headerValue ? 'Implemented' : 'Missing',
          compliance: compliance.status,
          details: compliance.details,
        };
      });

      // Calculate security score
      const scoreDetails = calculateSecurityScore(headerResults);
      
      // Add to history
      const timestamp = new Date().toLocaleString();
      const historyEntry = {
        url: formattedUrl,
        timestamp,
        score: scoreDetails.score,
        results: headerResults,
      };

      setHistory([historyEntry, ...history.slice(0, 9)]); // Keep last 10 entries
      setResults(headerResults);
      setScore(scoreDetails);
    } catch (err) {
      setError(`Error checking headers: ${err.message}. Note: You may need to request temporary access to the CORS proxy service or configure your own proxy.`);
    } finally {
      setLoading(false);
    }
  };

  // Enhanced compliance check function with detailed analysis
  const analyzeCompliance = (headerName, headerValue) => {
    if (!headerValue) {
      return { 
        status: 'Missing', 
        details: 'Header not implemented' 
      };
    }
    
    switch (headerName) {
      case 'strict-transport-security':
        const hasMaxAge = headerValue.includes('max-age=');
        const hasSubdomains = headerValue.includes('includesubdomains');
        const hasPreload = headerValue.includes('preload');
        
        if (hasMaxAge && hasSubdomains && hasPreload) {
          return { 
            status: 'Compliant', 
            details: 'Fully compliant with OWASP recommendations' 
          };
        } else if (hasMaxAge) {
          return { 
            status: 'Partial', 
            details: `Missing: ${!hasSubdomains ? 'includeSubDomains' : ''}${!hasSubdomains && !hasPreload ? ', ' : ''}${!hasPreload ? 'preload' : ''}` 
          };
        } else {
          return { 
            status: 'Non-Compliant', 
            details: 'Missing required max-age directive' 
          };
        }
        
      case 'x-frame-options':
        const value = headerValue.toUpperCase();
        if (value === 'DENY' || value === 'SAMEORIGIN') {
          return { 
            status: 'Compliant', 
            details: 'Value matches OWASP recommendations' 
          };
        } else {
          return { 
            status: 'Non-Compliant', 
            details: 'Value should be DENY or SAMEORIGIN' 
          };
        }
        
      case 'x-content-type-options':
        return headerValue.toLowerCase() === 'nosniff' 
          ? { status: 'Compliant', details: 'Correctly set to nosniff' }
          : { status: 'Non-Compliant', details: 'Value must be nosniff' };
        
      case 'content-security-policy':
        // Basic CSP analysis - could be enhanced further
        const hasDefaultSrc = headerValue.includes('default-src');
        const hasScriptSrc = headerValue.includes('script-src');
        const hasObjectSrc = headerValue.includes('object-src');
        const hasUnsafeInline = headerValue.includes("'unsafe-inline'");
        
        if (hasDefaultSrc && hasScriptSrc && hasObjectSrc && !hasUnsafeInline) {
          return { 
            status: 'Compliant', 
            details: 'Contains key directives with secure values' 
          };
        } else if (hasDefaultSrc || hasScriptSrc) {
          return { 
            status: 'Partial', 
            details: 'Basic protection implemented but missing some recommended directives' 
          };
        } else {
          return { 
            status: 'Non-Compliant', 
            details: 'Missing critical CSP directives' 
          };
        }
        
      case 'x-xss-protection':
        return headerValue === '1; mode=block' 
          ? { status: 'Compliant', details: 'Correctly configured with block mode' }
          : headerValue.includes('1') 
            ? { status: 'Partial', details: 'Enabled but missing mode=block directive' }
            : { status: 'Non-Compliant', details: 'Should be set to 1; mode=block' };
        
      case 'referrer-policy':
        const securePolicies = [
          'no-referrer', 
          'no-referrer-when-downgrade', 
          'strict-origin', 
          'strict-origin-when-cross-origin'
        ];
        return securePolicies.some(policy => headerValue.includes(policy)) 
          ? { status: 'Compliant', details: 'Using a secure referrer policy' }
          : { status: 'Non-Compliant', details: 'Using a less secure referrer policy' };
        
      case 'permissions-policy':
      case 'feature-policy': // Check older header too
        return headerValue.length > 10 
          ? { status: 'Compliant', details: 'Restrictions defined for browser features' }
          : { status: 'Partial', details: 'Implemented but may need more restrictions' };
        
      case 'cache-control':
        const hasNoStore = headerValue.includes('no-store');
        const hasNoCache = headerValue.includes('no-cache');
        const hasPrivate = headerValue.includes('private');
        
        if (hasNoStore) {
          return { status: 'Compliant', details: 'Correctly prevents caching sensitive data' };
        } else if (hasNoCache || hasPrivate) {
          return { status: 'Partial', details: 'Some cache restrictions implemented' };
        } else {
          return { status: 'Non-Compliant', details: 'Should include no-store for sensitive pages' };
        }
        
      case 'x-permitted-cross-domain-policies':
        return headerValue === 'none' 
          ? { status: 'Compliant', details: 'Correctly set to none' }
          : { status: 'Non-Compliant', details: 'Should be set to none for best security' };
          
      case 'cross-origin-embedder-policy':
        return headerValue === 'require-corp' 
          ? { status: 'Compliant', details: 'Correctly set to require-corp' }
          : { status: 'Non-Compliant', details: 'Should be set to require-corp' };
          
      case 'cross-origin-opener-policy':
        return headerValue === 'same-origin' 
          ? { status: 'Compliant', details: 'Correctly set to same-origin' }
          : { status: 'Non-Compliant', details: 'Should be set to same-origin' };
          
      case 'cross-origin-resource-policy':
        return headerValue === 'same-origin' 
          ? { status: 'Compliant', details: 'Correctly set to same-origin' }
          : { status: 'Non-Compliant', details: 'Should be set to same-origin' };
        
      default:
        return { status: 'Unknown', details: 'Analysis not available for this header' };
    }
  };

  const calculateSecurityScore = (headerResults) => {
    // Weighted scoring system
    const weights = {
      'High': 3,
      'Medium': 2,
      'Low': 1
    };
    
    let totalWeight = 0;
    let earnedWeight = 0;
    let criticalMissing = [];
    let implementedCount = 0;
    let compliantCount = 0;
    let partialCount = 0;
    
    headerResults.forEach(header => {
      const weight = weights[header.risk] || 1;
      totalWeight += weight;
      
      if (header.status === 'Implemented') {
        implementedCount++;
        
        if (header.compliance === 'Compliant') {
          earnedWeight += weight;
          compliantCount++;
        } else if (header.compliance === 'Partial') {
          earnedWeight += (weight * 0.5);
          partialCount++;
        }
      } else if (header.risk === 'High') {
        criticalMissing.push(header.name);
      }
    });
    
    const normalizedScore = Math.round((earnedWeight / totalWeight) * 100);
    
    return {
      score: normalizedScore,
      implementedCount,
      compliantCount,
      partialCount, 
      missingCount: headerResults.length - implementedCount,
      criticalMissing
    };
  };

  const getScoreColor = () => {
    if (score.score >= 80) return '#4CAF50'; // Green
    if (score.score >= 50) return '#FF9800'; // Orange
    return '#F44336'; // Red
  };

  const getComplianceColor = (compliance) => {
    switch (compliance) {
      case 'Compliant': return '#4CAF50'; // Green
      case 'Partial': return '#FF9800'; // Orange
      case 'Non-Compliant': return '#F44336'; // Red
      case 'Missing': return '#F44336'; // Red
      default: return '#757575'; // Grey
    }
  };

  const getRiskColor = (risk) => {
    switch (risk) {
      case 'High': return '#F44336'; // Red
      case 'Medium': return '#FF9800'; // Orange
      case 'Low': return '#4CAF50'; // Green
      default: return '#757575'; // Grey
    }
  };

  const exportResults = () => {
    if (!results) return;
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `security-headers-${url.replace(/[^a-z0-9]/gi, '-')}-${timestamp}.json`;
    
    const exportData = {
      url,
      timestamp: new Date().toISOString(),
      score,
      results
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url_to_download = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url_to_download;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url_to_download);
    
    setShowExport(false);
  };

  const exportCSV = () => {
    if (!results) return;
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `security-headers-${url.replace(/[^a-z0-9]/gi, '-')}-${timestamp}.csv`;
    
    let csvContent = "Header,Category,Risk,Status,Compliance,Value,Recommendation,Details\n";
    
    results.forEach(header => {
      const row = [
        `"${header.name}"`,
        `"${header.category}"`,
        `"${header.risk}"`,
        `"${header.status}"`,
        `"${header.compliance}"`,
        `"${header.value || 'Not implemented'}"`,
        `"${header.recommendation.replace(/"/g, '""')}"`,
        `"${header.details.replace(/"/g, '""')}"`
      ];
      csvContent += row.join(',') + "\n";
    });
    
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url_to_download = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url_to_download;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url_to_download);
    
    setShowExport(false);
  };

  const filteredResults = results && selectedCategory !== 'All' 
    ? results.filter(header => header.category === selectedCategory)
    : results;

  // Save theme preference
  useEffect(() => {
    localStorage.setItem('darkMode', darkMode);
    document.body.className = darkMode ? 'dark-mode' : '';
  }, [darkMode]);

  // Toggle dark mode
  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
  };

  return (
    <div className={`app ${darkMode ? 'dark-mode' : ''}`}>
      <header className="app-header">
        <div className="header-content">
          <h1>Web Security Headers Checker</h1>
          <p>Advanced analyzer for OWASP security headers compliance</p>
        </div>
        <div className="theme-switch-wrapper">
          <span className="theme-switch-label">{darkMode ? 'Light' : 'Dark'}</span>
          <label className="theme-switch">
            <input 
              type="checkbox" 
              checked={darkMode} 
              onChange={toggleDarkMode}
              aria-label="Toggle dark mode"
            />
            <span className="slider round">
              <span className="switch-icon">{darkMode ? '☀️' : '🌙'}</span>
            </span>
          </label>
        </div>
      </header>

      <div className="app-nav">
        <button 
          className={!showHistory ? 'active' : ''} 
          onClick={() => setShowHistory(false)}
        >
          Scanner
        </button>
        <button 
          className={showHistory ? 'active' : ''} 
          onClick={() => setShowHistory(true)}
        >
          History
        </button>
        <button 
          className={showProxySettings ? 'active' : ''} 
          onClick={() => setShowProxySettings(!showProxySettings)}
        >
          Settings
        </button>
      </div>

      {showProxySettings ? (
        <main className="app-main">
          <h2>Proxy Settings</h2>
          <div className="settings-section">
            <p>
              This application needs a CORS proxy to fetch headers from websites. 
              You can use the default proxy or specify your own.
            </p>
            <label htmlFor="proxy-url">CORS Proxy URL:</label>
            <input
              id="proxy-url"
              type="text"
              value={proxyUrl}
              onChange={(e) => setProxyUrl(e.target.value)}
              placeholder="https://your-proxy-url/"
              className="url-input"
            />
            <p className="help-text">
              Default: https://cors-anywhere.herokuapp.com/<br/>
              Note: You may need to request temporary access at 
              <a href="https://cors-anywhere.herokuapp.com/corsdemo" target="_blank" rel="noopener noreferrer">
                cors-anywhere.herokuapp.com/corsdemo
              </a>
            </p>
            <button 
              onClick={() => setShowProxySettings(false)} 
              className="check-button"
            >
              Save Settings
            </button>
          </div>
        </main>
      ) : showHistory ? (
        <main className="app-main">
          <h2>Scan History</h2>
          {history.length === 0 ? (
            <div className="no-results">No scan history available</div>
          ) : (
            <div className="history-list">
              {history.map((entry, index) => (
                <div key={index} className="history-item">
                  <div className="history-header">
                    <h3>{entry.url}</h3>
                    <div className="history-meta">
                      <span className="history-time">{entry.timestamp}</span>
                      <span 
                        className="history-score"
                        style={{ 
                          backgroundColor: entry.score >= 80 ? '#4CAF50' : entry.score >= 50 ? '#FF9800' : '#F44336'
                        }}
                      >
                        Score: {entry.score}%
                      </span>
                    </div>
                  </div>
                  <button 
                    className="history-view-btn"
                    onClick={() => {
                      setUrl(entry.url);
                      setResults(entry.results);
                      setScore({
                        score: entry.score,
                        implementedCount: entry.results.filter(r => r.status === 'Implemented').length,
                        compliantCount: entry.results.filter(r => r.compliance === 'Compliant').length,
                        partialCount: entry.results.filter(r => r.compliance === 'Partial').length,
                        missingCount: entry.results.filter(r => r.status === 'Missing').length
                      });
                      setShowHistory(false);
                    }}
                  >
                    View Results
                  </button>
                </div>
              ))}
            </div>
          )}
        </main>
      ) : (
        <main className="app-main">
          <div className="input-section">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL (e.g., example.com or https://example.com)"
              className="url-input"
            />
            <button 
              onClick={checkHeaders} 
              disabled={!url || loading}
              className="check-button"
            >
              {loading ? 'Scanning...' : 'Check Headers'}
            </button>
          </div>

          {error && <div className="error-message">{error}</div>}

          {score && (
            <>
              <div className="score-container">
                <div className="score-grid">
                  <div className="score-box main-score">
                    <h2>Security Score</h2>
                    <div className="score" style={{ backgroundColor: getScoreColor() }}>
                      {score.score}%
                    </div>
                    <p className="score-description">
                      {score.score >= 80 ? 'Good security implementation' : 
                      score.score >= 50 ? 'Moderate security implementation - needs improvement' : 
                      'Poor security implementation - immediate action recommended'}
                    </p>
                  </div>
                  
                  <div className="score-box">
                    <h3>Headers Overview</h3>
                    <div className="score-stats">
                      <div className="stat-item">
                        <span className="stat-value" style={{ color: '#4CAF50' }}>{score.compliantCount}</span>
                        <span className="stat-label">Compliant</span>
                      </div>
                      <div className="stat-item">
                        <span className="stat-value" style={{ color: '#FF9800' }}>{score.partialCount}</span>
                        <span className="stat-label">Partial</span>
                      </div>
                      <div className="stat-item">
                        <span className="stat-value" style={{ color: '#F44336' }}>{score.missingCount}</span>
                        <span className="stat-label">Missing</span>
                      </div>
                    </div>
                  </div>
                  
                  {score.criticalMissing && score.criticalMissing.length > 0 && (
                    <div className="score-box critical-missing">
                      <h3>Critical Headers Missing</h3>
                      <ul className="critical-list">
                        {score.criticalMissing.map((header, index) => (
                          <li key={index}>{header}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
                
                <div className="action-buttons">
                  <button 
                    onClick={() => setShowExport(!showExport)} 
                    className="export-button"
                  >
                    Export Results
                  </button>
                  
                  {showExport && (
                    <div className="export-dropdown">
                      <button onClick={exportResults}>Export as JSON</button>
                      <button onClick={exportCSV}>Export as CSV</button>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}

          {results && (
            <div className="results-container">
              <div className="results-header">
                <h2>Security Headers Analysis</h2>
                <div className="filter-section">
                  <label htmlFor="category-filter">Filter by category:</label>
                  <select 
                    id="category-filter"
                    value={selectedCategory}
                    onChange={(e) => setSelectedCategory(e.target.value)}
                    className="category-select"
                  >
                    {categories.map((category, index) => (
                      <option key={index} value={category}>{category}</option>
                    ))}
                  </select>
                </div>
              </div>

              <table className="results-table">
                <thead>
                  <tr>
                    <th>Header</th>
                    <th>Risk</th>
                    <th>Status</th>
                    <th>Value</th>
                    <th>Recommendation</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredResults.map((header, index) => (
                    <tr key={index} className={header.status === 'Missing' ? 'missing-row' : ''}>
                      <td>
                        <strong>{header.name}</strong>
                        <div className="header-description">{header.description}</div>
                        <div className="header-category">{header.category}</div>
                      </td>
                      <td>
                        <span 
                          className="risk-label"
                          style={{ backgroundColor: getRiskColor(header.risk) }}
                        >
                          {header.risk}
                        </span>
                      </td>
                      <td>
                        <span 
                          className="status-label"
                          style={{ 
                            backgroundColor: getComplianceColor(header.compliance)
                          }}
                        >
                          {header.compliance}
                        </span>
                        <div className="compliance-details">{header.details}</div>
                      </td>
                      <td className="header-value">
                        {header.value || 'Not implemented'}
                      </td>
                      <td className="recommendation">
                        <div className="recommendation-wrapper">
                          <code>{header.recommendation}</code>
                          <a 
                            href={header.learnMore} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="learn-more"
                          >
                            Learn More
                          </a>
                        </div>
                        <div className="header-impact">
                          <strong>Impact:</strong> {header.impact}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </main>
      )}

      <footer className="app-footer">
        <p>
          Based on <a href="https://owasp.org/www-project-secure-headers/" target="_blank" rel="noopener noreferrer">OWASP Secure Headers Project</a>
        </p>
        <p className="disclaimer">
          Note: This tool is for educational purposes only. Always conduct a comprehensive security assessment of your applications.
        </p>
      </footer>
    </div>
  );
}

export default App;