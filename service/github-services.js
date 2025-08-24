const axios = require('axios');

class GitHubService {
    constructor() {
        this.baseURL = 'https://api.github.com';
        this.token = process.env.GITHUB_TOKEN; // Optional: for higher rate limits
    }

    /**
     * Get repository files recursively
     * @param {string} owner - Repository owner
     * @param {string} repo - Repository name
     * @returns {Array} Array of file objects with content
     */
    async getRepositoryFiles(owner, repo) {
        try {
            console.log(`Fetching repository tree for ${owner}/${repo}...`);
            
            // Get repository tree recursively
            const treeResponse = await this.makeRequest(`/repos/${owner}/${repo}/git/trees/main?recursive=1`);
            const tree = treeResponse.tree;
            
            // Filter for supported file types
            const supportedExtensions = ['.py', '.js', '.java', '.php', '.rb', '.go', '.cpp', '.c', '.cs', '.ts', '.jsx', '.tsx'];
            const codeFiles = tree.filter(item => {
                return item.type === 'blob' && 
                       supportedExtensions.some(ext => item.path.toLowerCase().endsWith(ext)) &&
                       item.size < 100000; // Skip files larger than 100KB
            });

            console.log(`Found ${codeFiles.length} code files to analyze`);

            // Fetch content for each file
            const files = [];
            for (const file of codeFiles.slice(0, 20)) { // Limit to 20 files
                try {
                    const contentResponse = await this.makeRequest(`/repos/${owner}/${repo}/contents/${file.path}`);
                    
                    // Decode base64 content
                    const content = Buffer.from(contentResponse.content, 'base64').toString('utf-8');
                    
                    files.push({
                        path: file.path,
                        size: file.size,
                        content: content
                    });
                    
                    console.log(`✓ Fetched ${file.path} (${file.size} bytes)`);
                } catch (error) {
                    console.log(`✗ Failed to fetch ${file.path}: ${error.message}`);
                    continue;
                }
            }

            return files;
        } catch (error) {
            console.error(`GitHub API error: ${error.message}`);
            if (error.response?.status === 404) {
                throw new Error('Repository not found or not accessible');
            } else if (error.response?.status === 403) {
                throw new Error('GitHub API rate limit exceeded or repository is private');
            } else {
                throw new Error(`GitHub API error: ${error.message}`);
            }
        }
    }

    /**
     * Make authenticated request to GitHub API
     * @param {string} endpoint - API endpoint
     * @returns {Object} Response data
     */
    async makeRequest(endpoint) {
        const headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Security-Scanner-App'
        };

        // Add authorization header if token is available
        if (this.token) {
            headers['Authorization'] = `token ${this.token}`;
        }

        const response = await axios.get(`${this.baseURL}${endpoint}`, {
            headers: headers,
            timeout: 30000
        });

        return response.data;
    }

    /**
     * Get repository information
     * @param {string} owner - Repository owner
     * @param {string} repo - Repository name
     * @returns {Object} Repository info
     */
    async getRepositoryInfo(owner, repo) {
        try {
            const repoInfo = await this.makeRequest(`/repos/${owner}/${repo}`);
            return {
                name: repoInfo.name,
                full_name: repoInfo.full_name,
                description: repoInfo.description,
                language: repoInfo.language,
                stars: repoInfo.stargazers_count,
                forks: repoInfo.forks_count,
                created_at: repoInfo.created_at,
                updated_at: repoInfo.updated_at,
                default_branch: repoInfo.default_branch
            };
        } catch (error) {
            console.error(`Failed to get repository info: ${error.message}`);
            throw error;
        }
    }
}

module.exports = GitHubService;