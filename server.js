const express = require('express');
const cors = require('cors');
const multer = require('multer');
const OpenAI = require('openai');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// GitHub service import
let GitHubService;
try {
    GitHubService = require('./services/github-service');
} catch (error) {
    console.log('Warning: GitHub service not found, using fallback');
    GitHubService = class {
        async getRepositoryFiles(owner, repo) {
            return [];
        }
    };
}

const app = express();
const port = process.env.PORT || 8000;

// Add timing middleware
app.use((req, res, next) => {
    req.startTime = Date.now();
    next();
});

// Middleware
app.use(cors({
    origin: '*',
    methods: '*',
    allowedHeaders: '*'
}));
app.use(express.json());

// Configure multer for file uploads
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB limit
    }
});

// OpenAI client
const client = new OpenAI({
    apiKey: "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"
});

// In-memory storage for scans
let scanHistory = [];

// Initialize GitHub service
let githubService;
try {
    githubService = new GitHubService();
} catch (error) {
    console.log(`Warning: GitHub service initialization failed: ${error.message}`);
    githubService = null;
}

// Helper function to extract repo info from GitHub URL
function extractRepoInfo(githubUrl) {
    const pattern = /github\.com\/([^\/]+)\/([^\/]+)/;
    const match = githubUrl.match(pattern);
    if (match) {
        return {
            owner: match[1],
            repo: match[2].replace('.git', '')
        };
    }
    return { owner: null, repo: null };
}

// Enhanced fallback analysis with clear indicators
function enhancedFallbackAnalysis(filename, reason) {
    console.log(`\n🚨 ============== USING FALLBACK DATA ==============`);
    console.log(`📄 Filename: ${filename}`);
    console.log(`❌ Reason: ${reason}`);
    console.log(`⚡ This will be FAST because it's hardcoded!`);
    console.log(`🚨 ================================================\n`);
    
    if (filename.endsWith('.py')) {
        return {
            vulnerabilities: [
                {
                    title: "SQL Injection Vulnerability",
                    severity: "Critical",
                    line: 16,
                    description: "User input is directly concatenated into SQL query without sanitization. This allows attackers to execute arbitrary SQL commands, potentially leading to data breach, data manipulation, or complete database compromise.",
                    fix: "Use parameterized queries with SQLAlchemy or similar ORM: cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))"
                },
                {
                    title: "Hardcoded Database Credentials",
                    severity: "Critical", 
                    line: 13,
                    description: "Database credentials are hardcoded in source code, exposing sensitive authentication information to anyone with code access.",
                    fix: "Use environment variables: conn = sqlite3.connect(os.environ['DB_CONNECTION_STRING'])"
                },
                {
                    title: "Weak Cryptographic Hash (MD5)",
                    severity: "High",
                    line: 21,
                    description: "MD5 is cryptographically broken and vulnerable to collision attacks. Session tokens generated with MD5 can be predicted or forged.",
                    fix: "Use bcrypt for password hashing: import bcrypt; hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())"
                },
                {
                    title: "Missing Input Validation",
                    severity: "Medium",
                    line: 9,
                    description: "User input from request.form is not validated, sanitized, or length-checked before processing.",
                    fix: "Implement input validation: if not username or len(username) > 50: return {'error': 'Invalid username'}"
                },
                {
                    title: "Information Disclosure via Predictable Tokens",
                    severity: "Medium",
                    line: 25,
                    description: "Session token generation using MD5 with predictable inputs can leak user information and allow session hijacking.",
                    fix: "Use cryptographically secure random tokens: import secrets; token = secrets.token_urlsafe(32)"
                },
                {
                    title: "Missing Error Handling",
                    severity: "Low",
                    line: 18,
                    description: "Database operations lack proper exception handling, potentially exposing system information in error messages.",
                    fix: "Add try-catch blocks: try: cursor.execute(query) except sqlite3.Error as e: logger.error(f'Database error: {e}'); return {'error': 'Authentication failed'}"
                }
            ],
            risk_assessment: {
                risk_score: 88, // Very high due to SQL injection + hardcoded creds
                risk_level: "Critical Risk",
                overall_assessment: "🚨 HARDCODED FALLBACK ANALYSIS - NOT FROM LLM. This code contains multiple critical security vulnerabilities that pose immediate risk.",
                recommendations: [
                    "Immediately implement parameterized queries to prevent SQL injection",
                    "Move all credentials to environment variables or secure vault",
                    "Replace MD5 with bcrypt for password hashing",
                    "Add comprehensive input validation and sanitization"
                ]
            },
            code_quality: {
                security_score: 12,
                maintainability: "Poor",
                complexity: "Low"
            },
            _fallback_used: true,
            _fallback_reason: reason,
            _is_real_llm_data: false
        };
    } else if (filename.endsWith('.js')) {
        return {
            vulnerabilities: [
                {
                    title: "Cross-Site Scripting (XSS)",
                    severity: "High",
                    line: 3,
                    description: "User input is directly inserted into DOM using innerHTML without sanitization, allowing script injection attacks.",
                    fix: "Use textContent instead: element.textContent = userInput; or sanitize HTML: DOMPurify.sanitize(userInput)"
                },
                {
                    title: "Prototype Pollution",
                    severity: "High", 
                    line: 8,
                    description: "Object properties are set without validation, potentially allowing prototype pollution attacks that can affect all objects.",
                    fix: "Validate property names: if (['constructor', '__proto__', 'prototype'].includes(key)) return; or use Map instead of Object"
                },
                {
                    title: "Insecure Random Number Generation",
                    severity: "Medium",
                    line: 12,
                    description: "Math.random() is not cryptographically secure and predictable, unsuitable for security-sensitive operations.",
                    fix: "Use crypto.getRandomValues(): const array = new Uint32Array(1); crypto.getRandomValues(array); return array[0]"
                }
            ],
            risk_assessment: {
                risk_score: 65,
                risk_level: "High Risk", 
                overall_assessment: "🚨 HARDCODED FALLBACK ANALYSIS - NOT FROM LLM. Multiple client-side security vulnerabilities present significant XSS and prototype pollution risks.",
                recommendations: [
                    "Implement proper input sanitization for all user data",
                    "Use secure coding practices to prevent prototype pollution",
                    "Replace Math.random() with crypto.getRandomValues() for security operations"
                ]
            },
            code_quality: {
                security_score: 35,
                maintainability: "Fair",
                complexity: "Medium"
            },
            _fallback_used: true,
            _fallback_reason: reason,
            _is_real_llm_data: false
        };
    } else if (filename.endsWith('.java')) {
        return {
            vulnerabilities: [
                {
                    title: "SQL Injection Vulnerability",
                    severity: "Critical",
                    line: 8,
                    description: "String concatenation used for SQL query construction allows SQL injection attacks through user input manipulation.",
                    fix: "Use PreparedStatement: PreparedStatement stmt = conn.prepareStatement('SELECT * FROM users WHERE username = ? AND password = ?'); stmt.setString(1, username); stmt.setString(2, password);"
                },
                {
                    title: "Hardcoded Database Credentials",
                    severity: "Critical",
                    line: 6,
                    description: "Database credentials hardcoded in source code create security risk and maintenance issues.",
                    fix: "Use configuration files or environment variables: String url = System.getenv('DB_URL'); String user = System.getenv('DB_USER');"
                },
                {
                    title: "Resource Leak - Unclosed Connection",
                    severity: "Medium",
                    line: 6,
                    description: "Database connection is not properly closed, leading to connection pool exhaustion and memory leaks.",
                    fix: "Use try-with-resources: try (Connection conn = DriverManager.getConnection(url, user, pass)) { /* use connection */ }"
                }
            ],
            risk_assessment: {
                risk_score: 82,
                risk_level: "Critical Risk",
                overall_assessment: "🚨 HARDCODED FALLBACK ANALYSIS - NOT FROM LLM. Critical security flaws including SQL injection and exposed credentials.",
                recommendations: [
                    "Immediately implement PreparedStatement for all database queries",
                    "Move credentials to secure configuration management",
                    "Implement proper resource management with try-with-resources"
                ]
            },
            code_quality: {
                security_score: 18,
                maintainability: "Poor", 
                complexity: "Low"
            },
            _fallback_used: true,
            _fallback_reason: reason,
            _is_real_llm_data: false
        };
    } else {
        return {
            vulnerabilities: [],
            risk_assessment: {
                risk_score: 0,
                risk_level: "Very Low Risk",
                overall_assessment: "🚨 HARDCODED FALLBACK ANALYSIS - NOT FROM LLM. No security vulnerabilities detected.",
                recommendations: ["Continue following security best practices"]
            },
            code_quality: {
                security_score: 100,
                maintainability: "Good",
                complexity: "Low"
            },
            _fallback_used: true,
            _fallback_reason: reason,
            _is_real_llm_data: false
        };
    }
}

// Enhanced LLM analysis function with comprehensive logging
async function analyzeWithGPT5(code, filename, filePath = null) {
    console.log(`\n🚀 ========== STARTING ANALYSIS ==========`);
    console.log(`📄 File: ${filename}`);
    console.log(`📊 Code length: ${code.length} characters`);
    console.log(`⏰ Start time: ${new Date().toISOString()}`);
    
    const lines = code.split('\n');
    const numberedCode = lines.map((line, i) => `${String(i + 1).padStart(2, ' ')}: ${line}`).join('\n');
    
    console.log(`📝 Code prepared with ${lines.length} lines`);
    
    const prompt = `You are an expert security analyst. Analyze this ${filename} code for ALL security vulnerabilities and provide a comprehensive security assessment.

INSTRUCTIONS:
1. Find ALL security vulnerabilities including: SQL injection, command injection, XSS, hardcoded secrets, weak crypto, path traversal, insecure deserialization, LDAP injection, NoSQL injection, prototype pollution, SSRF, insecure random, authentication bypasses, authorization flaws, input validation, output encoding, race conditions, buffer overflows, memory leaks, resource leaks, information disclosure, missing error handling, insecure configurations, and any other security issues.

2. Analyze every line thoroughly and report ALL findings with EXACT line numbers.

3. Calculate an overall risk score from 0-100 where:
   - 0-20: Very Low Risk (secure code)
   - 21-40: Low Risk (minor issues)
   - 41-60: Medium Risk (moderate concerns)
   - 61-80: High Risk (significant vulnerabilities)
   - 81-100: Critical Risk (severe security flaws)

4. Consider factors like:
   - Number and severity of vulnerabilities
   - Potential impact of exploitation
   - Ease of exploitation
   - Code complexity and error handling
   - Security best practices adherence

Return ONLY valid JSON in this exact format:
{
  "vulnerabilities": [
    {
      "title": "Specific vulnerability name",
      "severity": "Critical|High|Medium|Low",
      "line": 16,
      "description": "Detailed technical description of the vulnerability and potential impact",
      "fix": "Specific remediation steps and secure code examples"
    }
  ],
  "risk_assessment": {
    "risk_score": 75,
    "risk_level": "High Risk",
    "overall_assessment": "Detailed explanation of why this score was assigned, considering all vulnerabilities and security factors",
    "recommendations": [
      "Primary security recommendation",
      "Secondary security recommendation"
    ]
  },
  "code_quality": {
    "security_score": 25,
    "maintainability": "Good|Fair|Poor",
    "complexity": "Low|Medium|High"
  }
}

Code to analyze:
${numberedCode}`;

    console.log(`\n🔑 ========== CHECKING API SETUP ==========`);
    console.log(`API Key exists: ${!!process.env.OPENAI_API_KEY}`);
    console.log(`API Key length: ${process.env.OPENAI_API_KEY?.length || 0}`);
    console.log(`API Key prefix: ${process.env.OPENAI_API_KEY?.substring(0, 10) || 'NONE'}...`);
    console.log(`Client initialized: ${!!client}`);

    try {
        console.log(`\n🤖 ========== CALLING OPENAI API ==========`);
        console.log(`Model: gpt-4o`);
        console.log(`Prompt length: ${prompt.length} characters`);
        console.log(`Temperature: 0.1`);
        console.log(`Max tokens: 2000`);
        
        const startTime = Date.now();
        console.log(`⏰ API call started at: ${new Date().toISOString()}`);
        
        const response = await client.chat.completions.create({
            model: "gpt-4o",
            messages: [
                {
                    role: "system",
                    content: "You are a senior security architect with 15+ years of experience in application security, penetration testing, and secure code review. Provide thorough, accurate security analysis."
                },
                {
                    role: "user",
                    content: prompt
                }
            ],
            temperature: 0.1,
            max_tokens: 2000
        });
        
        const endTime = Date.now();
        const responseTime = endTime - startTime;
        
        console.log(`\n✅ ========== OPENAI API SUCCESS ==========`);
        console.log(`⏱️ Response time: ${responseTime}ms`);
        console.log(`📏 Response length: ${response.choices[0].message.content.length} characters`);
        console.log(`💰 Tokens used: ${response.usage?.total_tokens || 'unknown'}`);
        console.log(`⏰ API call completed at: ${new Date().toISOString()}`);
        
        const content = response.choices[0].message.content.trim();
        
        console.log(`\n📄 ========== RAW LLM RESPONSE ==========`);
        console.log(`Full LLM Response:`);
        console.log('---START OF LLM RESPONSE---');
        console.log(content);
        console.log('---END OF LLM RESPONSE---');
        
        console.log(`\n🔍 ========== PARSING JSON ==========`);
        // More robust JSON extraction
        let jsonMatch = content.match(/\{[\s\S]*\}/);
        if (!jsonMatch) {
            console.log(`❌ No JSON found in main match, trying code block match...`);
            jsonMatch = content.match(/```json\s*([\s\S]*?)\s*```/);
            if (jsonMatch) {
                console.log(`✅ Found JSON in code block`);
                jsonMatch[0] = jsonMatch[1];
            } else {
                console.log(`❌ No JSON found in code block match either`);
            }
        } else {
            console.log(`✅ Found JSON in main match`);
        }
        
        if (jsonMatch) {
            console.log(`📊 JSON to parse (first 500 chars):`);
            console.log(jsonMatch[0].substring(0, 500) + '...');
            
            try {
                const parsed = JSON.parse(jsonMatch[0]);
                
                console.log(`\n✅ ========== JSON PARSE SUCCESS ==========`);
                console.log(`Structure check:`);
                console.log(`- Has vulnerabilities: ${!!parsed.vulnerabilities} (${parsed.vulnerabilities?.length || 0} items)`);
                console.log(`- Has risk_assessment: ${!!parsed.risk_assessment}`);
                console.log(`- Risk score: ${parsed.risk_assessment?.risk_score}`);
                console.log(`- Risk level: ${parsed.risk_assessment?.risk_level}`);
                console.log(`- Has code_quality: ${!!parsed.code_quality}`);
                
                // Validate the response structure
                if (parsed.vulnerabilities && parsed.risk_assessment) {
                    console.log(`\n🎉 ========== REAL LLM SUCCESS! ==========`);
                    console.log(`🐛 LLM found ${parsed.vulnerabilities.length} vulnerabilities:`);
                    parsed.vulnerabilities.forEach((vuln, i) => {
                        console.log(`  ${i+1}. ${vuln.title} (${vuln.severity}) - Line ${vuln.line}`);
                    });
                    console.log(`📊 LLM Risk Score: ${parsed.risk_assessment.risk_score}/100`);
                    console.log(`🎯 LLM Risk Level: ${parsed.risk_assessment.risk_level}`);
                    console.log(`📝 LLM Assessment: ${parsed.risk_assessment.overall_assessment.substring(0, 100)}...`);
                    console.log(`🔥 THIS IS 100% REAL LLM DATA - NOT FALLBACK!`);
                    
                    // Mark as real LLM data
                    parsed._fallback_used = false;
                    parsed._is_real_llm_data = true;
                    parsed._response_time_ms = responseTime;
                    
                    return parsed;
                } else {
                    console.log(`\n❌ ========== LLM RESPONSE INVALID ==========`);
                    console.log(`Missing required fields:`);
                    console.log(`- vulnerabilities: ${!parsed.vulnerabilities}`);
                    console.log(`- risk_assessment: ${!parsed.risk_assessment}`);
                    console.log(`🚨 FALLING BACK TO HARDCODED DATA`);
                    return enhancedFallbackAnalysis(filename, 'Invalid LLM response structure');
                }
                
            } catch (parseError) {
                console.log(`\n❌ ========== JSON PARSE ERROR ==========`);
                console.log(`Parse error: ${parseError.message}`);
                console.log(`JSON that failed to parse (first 300 chars):`);
                console.log(jsonMatch[0].substring(0, 300));
                console.log(`🚨 FALLING BACK TO HARDCODED DATA`);
                return enhancedFallbackAnalysis(filename, `JSON parsing failed: ${parseError.message}`);
            }
        } else {
            console.log(`\n❌ ========== NO JSON FOUND ==========`);
            console.log(`LLM response did not contain valid JSON`);
            console.log(`Response type: ${typeof content}`);
            console.log(`Response starts with: ${content.substring(0, 100)}...`);
            console.log(`🚨 FALLING BACK TO HARDCODED DATA`);
            return enhancedFallbackAnalysis(filename, 'No JSON in response');
        }
        
    } catch (error) {
        console.log(`\n💥 ========== OPENAI API ERROR ==========`);
        console.log(`Error type: ${error.constructor.name}`);
        console.log(`Error message: ${error.message}`);
        console.log(`Error code: ${error.code || 'none'}`);
        console.log(`Error status: ${error.status || 'none'}`);
        console.log(`Error type: ${error.type || 'none'}`);
        
        // Detailed error analysis
        if (error.message.includes('API key') || error.code === 'invalid_api_key') {
            console.log(`\n🔑 API KEY ISSUE DETECTED:`);
            console.log(`- Check if OPENAI_API_KEY is set in .env file`);
            console.log(`- Verify the API key starts with 'sk-'`);
            console.log(`- Make sure there are no extra spaces or quotes`);
        } else if (error.message.includes('quota') || error.code === 'insufficient_quota') {
            console.log(`\n💳 QUOTA ISSUE DETECTED:`);
            console.log(`- Your OpenAI account has exceeded its quota`);
            console.log(`- Add billing information to your OpenAI account`);
            console.log(`- Check your usage limits at platform.openai.com`);
        } else if (error.status === 429 || error.message.includes('rate limit')) {
            console.log(`\n⏱️ RATE LIMIT ISSUE DETECTED:`);
            console.log(`- Too many requests to OpenAI API`);
            console.log(`- Wait a moment and try again`);
            console.log(`- Consider upgrading your OpenAI plan for higher limits`);
        } else if (error.message.includes('model') || error.code === 'model_not_found') {
            console.log(`\n🤖 MODEL ISSUE DETECTED:`);
            console.log(`- The model 'gpt-4o' might not be available for your account`);
            console.log(`- Try using 'gpt-4' or 'gpt-3.5-turbo' instead`);
            console.log(`- Check your OpenAI account's model access`);
        } else if (error.message.includes('network') || error.code === 'ENOTFOUND') {
            console.log(`\n🌐 NETWORK ISSUE DETECTED:`);
            console.log(`- Check your internet connection`);
            console.log(`- Verify you can reach api.openai.com`);
            console.log(`- Check if you're behind a firewall or proxy`);
        }
        
        console.log(`\n🚨 FALLING BACK TO HARDCODED DATA`);
        return enhancedFallbackAnalysis(filename, `API Error: ${error.message}`);
    }
}

// Add test endpoints
app.post('/api/test-llm', async (req, res) => {
    console.log(`\n🧪 ========== LLM SPEED TEST ==========`);
    
    const testCode = `
def test():
    user_input = input("Enter name: ")
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query
`;
    
    const startTime = Date.now();
    console.log(`⏰ Starting test at: ${new Date().toISOString()}`);
    
    try {
        const result = await analyzeWithGPT5(testCode, 'test.py');
        const endTime = Date.now();
        const duration = endTime - startTime;
        
        console.log(`\n⏱️ ========== TEST COMPLETED ==========`);
        console.log(`Total duration: ${duration}ms`);
        
        let analysis = {
            duration_ms: duration,
            is_fast: duration < 1000,
            likely_source: duration < 1000 ? "HARDCODED FALLBACK" : "REAL LLM",
            risk_score: result.risk_assessment?.risk_score,
            fallback_used: result._fallback_used || false,
            is_real_llm: result._is_real_llm_data || false,
            vulnerability_count: result.vulnerabilities?.length || 0,
            response_time_ms: result._response_time_ms
        };
        
        if (duration < 500) {
            analysis.conclusion = "🚨 DEFINITELY HARDCODED - Too fast for LLM";
        } else if (duration < 1000) {
            analysis.conclusion = "⚠️ PROBABLY HARDCODED - Suspiciously fast";
        } else if (duration < 3000) {
            analysis.conclusion = "🤔 MIGHT BE LLM - Could be cached or fast API";
        } else {
            analysis.conclusion = "✅ LIKELY REAL LLM - Normal API response time";
        }
        
        console.log(`📊 Test Result: ${analysis.conclusion}`);
        console.log(`🤖 Real LLM: ${analysis.is_real_llm}`);
        
        res.json({
            test_result: analysis,
            sample_vulnerability: result.vulnerabilities?.[0],
            risk_assessment: result.risk_assessment
        });
        
    } catch (error) {
        const endTime = Date.now();
        const duration = endTime - startTime;
        
        console.log(`💥 Test failed in: ${duration}ms - ${error.message}`);
        
        res.json({
            test_result: {
                duration_ms: duration,
                error: error.message,
                conclusion: "❌ LLM API FAILED - Using fallback"
            }
        });
    }
});

app.get('/api/check-setup', (req, res) => {
    console.log(`\n🔧 ========== SETUP CHECK ==========`);
    
    const checks = {
        openai_key_exists: !!process.env.OPENAI_API_KEY,
        openai_key_length: process.env.OPENAI_API_KEY?.length || 0,
        openai_key_format: process.env.OPENAI_API_KEY?.startsWith('sk-') || false,
        client_initialized: !!client,
        node_env: process.env.NODE_ENV || 'not set'
    };
    
    console.log(`🔑 API Key exists: ${checks.openai_key_exists}`);
    console.log(`📏 API Key length: ${checks.openai_key_length}`);
    console.log(`✅ Proper format (sk-): ${checks.openai_key_format}`);
    console.log(`🤖 Client ready: ${checks.client_initialized}`);
    
    let diagnosis = "Unknown";
    if (!checks.openai_key_exists) {
        diagnosis = "❌ NO API KEY - Will always use fallback";
    } else if (checks.openai_key_length < 20) {
        diagnosis = "❌ INVALID API KEY - Too short";
    } else if (!checks.openai_key_format) {
        diagnosis = "❌ WRONG API KEY FORMAT - Should start with 'sk-'";
    } else {
        diagnosis = "✅ API KEY LOOKS VALID - Should work if quota/billing OK";
    }
    
    console.log(`🎯 Diagnosis: ${diagnosis}`);
    
    res.json({
        setup_status: checks,
        diagnosis: diagnosis,
        next_steps: !checks.openai_key_exists ? 
            ["1. Create OpenAI account", "2. Generate API key", "3. Add to .env file"] :
            ["1. Test with /api/test-llm", "2. Check console logs", "3. Verify billing if needed"]
    });
});

// Routes

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'healthy' });
});

// Analyze uploaded files
app.post('/api/analyze/upload', upload.array('files'), async (req, res) => {
    try {
        console.log(`\n🎬 ========== STARTING FILE ANALYSIS ==========`);
        console.log(`📁 Files received: ${req.files?.length || 0}`);
        
        const files = req.files;
        if (!files || files.length === 0) {
            return res.status(400).json({ error: 'No files uploaded' });
        }

        const allVulnerabilities = [];
        let totalRiskScore = 0;
        let analysisResults = [];
        
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            console.log(`\n🔍 ========== ANALYZING FILE ${i+1}/${files.length} ==========`);
            console.log(`📄 File: ${file.originalname}`);
            console.log(`📊 Size: ${file.size} bytes`);
            
            const code = file.buffer.toString('utf-8');
            console.log(`💻 Code preview (first 100 chars): ${code.substring(0, 100)}...`);
            
            const analysisStart = Date.now();
            const result = await analyzeWithGPT5(code, file.originalname);
            const analysisEnd = Date.now();
            const analysisTime = analysisEnd - analysisStart;
            
            console.log(`\n📊 ========== FILE ANALYSIS COMPLETE ==========`);
            console.log(`⏱️ Analysis time: ${analysisTime}ms`);
            console.log(`🤖 Is real LLM data: ${result._is_real_llm_data || false}`);
            console.log(`📊 Risk score: ${result.risk_assessment?.risk_score}`);
            console.log(`🐛 Vulnerabilities: ${result.vulnerabilities?.length || 0}`);
            
            if (analysisTime < 1000) {
                console.log(`🚨 SUSPICIOUSLY FAST! Likely using fallback data`);
            } else {
                console.log(`✅ NORMAL SPEED: Likely real LLM response`);
            }
            
            analysisResults.push(result);
            
            // Use LLM-generated risk score
            const fileRiskScore = result.risk_assessment?.risk_score || 0;
            totalRiskScore += fileRiskScore;
            
            for (const vuln of result.vulnerabilities || []) {
                vuln.file = file.originalname;
                vuln.file_path = file.originalname;
                allVulnerabilities.push(vuln);
            }
        }

        // Calculate average LLM risk score across all files
        const avgLLMRiskScore = Math.round(totalRiskScore / files.length);
        
        // Count vulnerabilities for summary
        const criticalCount = allVulnerabilities.filter(v => v.severity === 'Critical').length;
        const highCount = allVulnerabilities.filter(v => v.severity === 'High').length;
        const mediumCount = allVulnerabilities.filter(v => v.severity === 'Medium').length;
        const lowCount = allVulnerabilities.filter(v => v.severity === 'Low').length;
        
        // Use LLM risk score instead of calculated score
        const riskScore = avgLLMRiskScore;
        const securityScore = Math.max(0, 100 - riskScore);
        
        console.log(`\n📊 ========== FINAL RESULTS ==========`);
        console.log(`🎯 Average LLM Risk Score: ${riskScore}/100`);
        console.log(`🛡️ Security Score: ${securityScore}/100`);
        console.log(`🤖 Real LLM used: ${!analysisResults[0]?._fallback_used}`);
        console.log(`⚡ Total analysis time: ${Date.now() - req.startTime}ms`);
        console.log(`🐛 Total vulnerabilities: ${allVulnerabilities.length}`);
        console.log(`📈 Breakdown: ${criticalCount} Critical, ${highCount} High, ${mediumCount} Medium, ${lowCount} Low`);
        
        // Store scan in history
        const scanResult = {
            id: scanHistory.length + 1,
            timestamp: new Date().toISOString(),
            files: files.map(f => f.originalname),
            vulnerabilities: allVulnerabilities,
            analysis_results: analysisResults, // Store full LLM analysis
            summary: {
                total_files: files.length,
                total_vulnerabilities: allVulnerabilities.length,
                critical: criticalCount,
                high: highCount,
                medium: mediumCount,
                low: lowCount,
                security_score: securityScore,
                risk_score: riskScore, // This is now from LLM
                llm_generated: !analysisResults[0]?._fallback_used,
                is_real_llm_data: analysisResults[0]?._is_real_llm_data || false,
                risk_level: riskScore >= 81 ? 'Critical Risk' : 
                           riskScore >= 61 ? 'High Risk' :
                           riskScore >= 41 ? 'Medium Risk' :
                           riskScore >= 21 ? 'Low Risk' : 'Very Low Risk'
            }
        };
        
        scanHistory.push(scanResult);

        console.log(`\n✅ ========== ANALYSIS COMPLETE ==========`);
        console.log(`📤 Sending results to frontend`);
        console.log(`🎯 Final risk score: ${riskScore}/100`);
        console.log(`🤖 LLM was used: ${scanResult.summary.is_real_llm_data}`);

        res.json({
            vulnerabilities: allVulnerabilities,
            summary: scanResult.summary,
            results: {
                vulnerabilities: allVulnerabilities
            },
            llm_analysis: analysisResults, // Include full LLM analysis
            _debug_info: {
                total_analysis_time_ms: Date.now() - req.startTime,
                files_analyzed: files.length,
                llm_used: scanResult.summary.is_real_llm_data,
                fallback_reasons: analysisResults.map(r => r._fallback_reason).filter(Boolean)
            }
        });
    } catch (error) {
        console.error('\n💥 ========== FILE ANALYSIS ERROR ==========');
        console.error(`Error: ${error.message}`);
        console.error(`Stack: ${error.stack}`);
        res.status(500).json({ error: 'Analysis failed' });
    }
});

// Get scans with limit
app.get('/api/scans', (req, res) => {
    const limit = parseInt(req.query.limit) || 5;
    const recentScans = scanHistory.slice(-limit);
    res.json({ scans: recentScans });
});

// Get specific scan
app.get('/api/scans/:scanId', (req, res) => {
    const scanId = parseInt(req.params.scanId);
    const scan = scanHistory.find(s => s.id === scanId);
    
    if (!scan) {
        return res.status(404).json({ error: 'Scan not found' });
    }
    
    res.json(scan);
});

// Analyze GitHub repository
app.post('/api/analyze/repo', async (req, res) => {
    try {
        const { url } = req.body;
        console.log(`\n🔍 ========== ANALYZING GITHUB REPO ==========`);
        console.log(`📁 Repository URL: ${url}`);
        
        // Extract owner and repo from URL
        const { owner, repo } = extractRepoInfo(url);
        if (!owner || !repo) {
            return res.status(400).json({ error: 'Invalid GitHub URL format' });
        }
        
        console.log(`📊 Repository: ${owner}/${repo}`);
        
        // Use GitHubService to fetch repository files
        if (!githubService) {
            return res.status(500).json({ error: 'GitHub service not available' });
        }
            
        const files = await githubService.getRepositoryFiles(owner, repo);
        if (!files || files.length === 0) {
            return res.status(404).json({ error: 'No supported files found or repository access denied' });
        }
        
        console.log(`📚 Found ${files.length} files to analyze`);
        
        const allVulnerabilities = [];
        const analyzedFiles = [];
        let totalLLMRiskScore = 0;
        let llmAnalysisCount = 0;
        
        // Analyze each file (limit to 10 files for demo to avoid long waits)
        const filesToAnalyze = files.slice(0, 10);
        
        for (let i = 0; i < filesToAnalyze.length; i++) {
            const fileInfo = filesToAnalyze[i];
            try {
                console.log(`\n🔍 ========== REPO FILE ${i+1}/${filesToAnalyze.length} ==========`);
                console.log(`📄 File: ${fileInfo.path}`);
                
                const content = fileInfo.content;
                if (!content) {
                    console.log(`⚠️ Skipping empty file: ${fileInfo.path}`);
                    continue;
                }
                
                // Skip very large files (>50KB for better performance)
                if (content.length > 50000) {
                    console.log(`⚠️ Skipping large file: ${fileInfo.path} (${content.length} chars)`);
                    continue;
                }
                
                // Analyze with LLM
                const filename = fileInfo.path.split('/').pop();
                const analysisStart = Date.now();
                const result = await analyzeWithGPT5(content, filename, fileInfo.path);
                const analysisTime = Date.now() - analysisStart;
                
                console.log(`📊 File analysis complete in ${analysisTime}ms`);
                console.log(`🤖 LLM used: ${result._is_real_llm_data || false}`);
                
                analyzedFiles.push(fileInfo.path);
                
                // Track LLM-generated risk scores
                if (result.risk_assessment?.risk_score && result._is_real_llm_data) {
                    totalLLMRiskScore += result.risk_assessment.risk_score;
                    llmAnalysisCount++;
                }
                
                // Add vulnerabilities with file path info
                for (const vuln of result.vulnerabilities || []) {
                    vuln.file = filename;
                    vuln.file_path = fileInfo.path;
                    allVulnerabilities.push(vuln);
                }
                
            } catch (error) {
                console.log(`❌ Error analyzing ${fileInfo.path}: ${error.message}`);
                continue;
            }
        }
        
        // Calculate summary statistics
        const criticalCount = allVulnerabilities.filter(v => v.severity === 'Critical').length;
        const highCount = allVulnerabilities.filter(v => v.severity === 'High').length;
        const mediumCount = allVulnerabilities.filter(v => v.severity === 'Medium').length;
        const lowCount = allVulnerabilities.filter(v => v.severity === 'Low').length;
        
        // Use LLM average if available, otherwise calculate from vulnerability counts
        let riskScore;
        if (llmAnalysisCount > 0) {
            riskScore = Math.round(totalLLMRiskScore / llmAnalysisCount);
            console.log(`📊 Using LLM average risk score: ${riskScore}/100 (from ${llmAnalysisCount} LLM analyses)`);
        } else {
            riskScore = Math.min(100, (criticalCount * 25) + (highCount * 15) + (mediumCount * 8) + (lowCount * 3));
            console.log(`📊 Using calculated risk score: ${riskScore}/100 (no LLM data available)`);
        }
        
        const securityScore = Math.max(0, 100 - riskScore);
        
        const summary = {
            total_files: analyzedFiles.length,
            total_vulnerabilities: allVulnerabilities.length,
            critical: criticalCount,
            high: highCount,
            medium: mediumCount,
            low: lowCount,
            security_score: securityScore,
            risk_score: riskScore,
            llm_analyses_used: llmAnalysisCount
        };
        
        // Store scan in history
        const scanResult = {
            id: scanHistory.length + 1,
            timestamp: new Date().toISOString(),
            repository: `${owner}/${repo}`,
            url: url,
            files: analyzedFiles,
            vulnerabilities: allVulnerabilities,
            summary: summary
        };
        scanHistory.push(scanResult);
        
        console.log(`\n✅ ========== REPO ANALYSIS COMPLETE ==========`);
        console.log(`📊 Files analyzed: ${analyzedFiles.length}`);
        console.log(`🐛 Vulnerabilities found: ${allVulnerabilities.length}`);
        console.log(`🎯 Risk score: ${riskScore}/100`);
        console.log(`🤖 LLM analyses: ${llmAnalysisCount}/${analyzedFiles.length}`);
        
        res.json({
            repository: `${owner}/${repo}`,
            files_analyzed: analyzedFiles.length,
            vulnerabilities: allVulnerabilities,
            summary: summary,
            results: {
                vulnerabilities: allVulnerabilities
            },
            _debug_info: {
                llm_analyses_used: llmAnalysisCount,
                total_files_found: files.length,
                files_skipped: files.length - analyzedFiles.length
            }
        });
        
    } catch (error) {
        console.error(`\n💥 ========== REPO ANALYSIS ERROR ==========`);
        console.error(`Error: ${error.message}`);
        console.error(`Stack: ${error.stack}`);
        res.status(500).json({ error: `Repository analysis failed: ${error.message}` });
    }
});

// Get dashboard stats
app.get('/api/dashboard/stats', (req, res) => {
    const totalScans = scanHistory.length;
    const totalVulnerabilities = scanHistory.reduce((sum, scan) => sum + (scan.vulnerabilities?.length || 0), 0);
    
    let avgRiskScore = 0;
    if (totalScans > 0) {
        avgRiskScore = scanHistory.reduce((sum, scan) => sum + (scan.summary?.risk_score || 0), 0) / totalScans;
    }
    
    console.log(`\n📊 ========== DASHBOARD STATS ==========`);
    console.log(`📈 Total scans: ${totalScans}`);
    console.log(`🐛 Total vulnerabilities: ${totalVulnerabilities}`);
    console.log(`🎯 Average risk score: ${avgRiskScore.toFixed(1)}/100`);
    
    res.json({
        overview: {
            total_scans: totalScans,
            total_vulnerabilities: totalVulnerabilities,
            avg_risk_score: avgRiskScore
        },
        scans: scanHistory.slice(-10) // Last 10 scans
    });
});

// Start server
app.listen(port, '0.0.0.0', () => {
    console.log(`\n🚀 ========== SERVER STARTED ==========`);
    console.log(`🌐 Server running on http://0.0.0.0:${port}`);
    console.log(`📊 Health check: http://localhost:${port}/health`);
    console.log(`🧪 Test LLM: http://localhost:${port}/api/test-llm`);
    console.log(`🔧 Check setup: http://localhost:${port}/api/check-setup`);
    console.log(`==========================================\n`);
});