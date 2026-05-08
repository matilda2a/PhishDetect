# PhishDetect: Phishing Analysis & Security Lab

PhishDetect is a specialized tool developed for academic and laboratory environments to analyze potential phishing threats through multi-layered heuristic evaluation. It provides a real-time assessment of URLs and Email content based on common attack vectors used in modern cyberattacks.

## 🛡️ Core Capabilities

### 1. URL Heuristic Engine
The engine performs a 10-point inspection on provided URLs, calculating a risk score based on:
- **Typosquatting Detection**: Uses Levenshtein distance algorithms to identify brand impersonation (e.g., `g00gle.com` vs `google.com`).
- **Homograph Analysis**: Identifies character substitution using look-alike characters from different alphabets.
- **Infrastructure Assessment**: Checks for insecure protocols (HTTP), non-standard ports, and IP-based hosting.
- **Structural Evaluation**: Analyzes subdomain depth, URL length, and suspicious Top-Level Domains (TLDs).

### 2. Email Pattern Analysis
Analyzes text content for social engineering signatures:
- **Urgency & Threat Detection**: Identifies psychological triggers like "immediate action required" or legal threats.
- **Credential Harvesting**: Scans for requests involving passwords, SSNs, or billing information.
- **Brand Mimicry**: Flags mentions of major brands combined with high-pressure tactics.
- **Formatting Heuristics**: Detects poor grammar, suspicious link patterns, and generic greetings.

## 💻 Technical Stack

- **Frontend**: React 19 + TypeScript
- **Styling**: Tailwind CSS 4 (Custom Design System)
- **Animations**: Framer Motion
- **Icons**: Lucide React
- **Build Tool**: Vite

## 🚀 Getting Started

### Prerequisites
- Node.js (Latest LTS recommended)
- npm or yarn

### Installation
1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the development server:
   ```bash
   npm run dev
   ```

## 📊 Heuristic Scoring Model
The analysis results in a weighted score (0-100):
- **90 - 100**: Low Risk (Safe)
- **70 - 89**: Medium Risk (Suspicious)
- **< 70**: High Risk (Dangerous)

*Note: This tool is intended for educational purposes and should be used as a supplementary aid for security awareness training.*
