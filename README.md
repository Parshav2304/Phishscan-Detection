# 🛡️ PhishScan - Advanced Phishing URL Detection Chrome Extension

A powerful Chrome extension that detects and highlights phishing or malicious URLs on any webpage using multiple detection methods including real-time API scanning, shortened URL resolution, and comprehensive threat intelligence.

## ✨ Features

### 🔍 **Multi-Layer Detection System**
- **VirusTotal API Integration** - Real-time scanning with 70+ antivirus engines
- **Google Safe Browsing API** - Google's threat intelligence database
- **OpenPhish Database Fallback** - Local database for offline detection
- **Safe Domain Whitelist** - Prevents false positives on trusted sites

### 🔗 **Shortened URL Resolution**
- Automatically detects and resolves shortened URLs (bit.ly, tinyurl, t.co, etc.)
- Checks the final destination URL for malicious content
- Visual indicators for resolved malicious shortened URLs

### 🎯 **Smart Detection Logic**
- **Hierarchical Checking**: Exact URL → Hostname → Domain matching
- **URL Normalization**: Removes tracking parameters, normalizes schemes
- **Conservative Matching**: Reduces false positives while maintaining accuracy
- **Batch Processing**: Efficient API usage with rate limiting

### 🎨 **Enhanced User Interface**
- **Real-time Status Updates**: Live scanning progress and results
- **Detailed Threat Information**: Shows detection method, engine counts, and reasons
- **Visual Indicators**: Red borders, warning icons, and tooltips
- **Responsive Design**: Works on all screen sizes

### 🔧 **Developer-Friendly**
- **Manifest V3 Compatible**: Latest Chrome extension standards
- **Modular Architecture**: Clean separation of concerns
- **Comprehensive Logging**: Detailed console output for debugging
- **Easy Configuration**: Simple API key setup

##🤝 **The Team** 

- **Parshav Shah**
- **Smeet Sadhu**
- **Mahi Panchal**



