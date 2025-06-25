# Outdated Software Checker GitHub App

This GitHub App automatically checks for outdated dependencies in your repositories and creates/updates issues with detailed reports about outdated packages.

## Features

- Checks NPM dependencies from `package.json`
- Checks Python dependencies from `requirements.txt`
- Creates or updates an issue with a formatted report
- Runs automatically on repository installation and daily schedule
- Shows current and latest versions of packages
- Visual indicators for outdated (⚠️) and up-to-date (✅) packages

## Setup

1. Create a new GitHub App in your GitHub account:
   - Go to Settings > Developer settings > GitHub Apps > New GitHub App
   - Set the following permissions:
     - Repository permissions:
       - Contents: Read
       - Issues: Write
       - Metadata: Read
   - Subscribe to events:
     - Installation
     - Installation repositories
     - Schedule

2. After creating the app, you'll need:
   - App ID
   - Private key (generate and download)
   - Client ID
   - Client Secret
   - Webhook Secret (optional)

3. Clone this repository

4. Install dependencies:
   ```bash
   npm install
   ```

5. Copy `.env.example` to `.env` and fill in your GitHub App credentials:
   ```
   APP_ID=your_app_id
   PRIVATE_KEY=your_private_key
   WEBHOOK_SECRET=your_webhook_secret
   GITHUB_CLIENT_ID=your_client_id
   GITHUB_CLIENT_SECRET=your_client_secret
   ```

6. Start the app:
   ```bash
   npm start
   ```

## How it Works

1. When the app is installed on a repository, it immediately performs a dependency check
2. The app runs daily checks based on the configured schedule (default: midnight)
3. For each check:
   - Reads `package.json` and `requirements.txt` if they exist
   - Fetches latest versions from npm and PyPI registries
   - Compares current versions with latest versions
   - Creates or updates an issue with the findings

## Example Output

The app creates an issue that looks like this:

```markdown
# 📦 Dependency Version Check Report

## NPM Dependencies

| Package | Current Version | Latest Version | Status |
|---------|----------------|----------------|--------|
| react | 17.0.2 | 19.1.0 | ⚠️ Outdated |
| express | 4.17.1 | 5.1.0 | ⚠️ Outdated |

## PIP Dependencies

| Package | Current Version | Latest Version | Status |
|---------|----------------|----------------|--------|
| django | 3.2.0 | 5.2.3 | ⚠️ Outdated |
| Flask | 3.1.1 | 3.1.1 | ✅ Up to date |
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. "# project_pro" 
