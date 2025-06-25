import os
import json
import hmac
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, abort, jsonify
from github import Github, GithubIntegration
import requests
from dotenv import load_dotenv
from packaging import version
import jwt
import time
from apscheduler.schedulers.background import BackgroundScheduler
import pytz
from scheduler import schedule_dependency_scans
from github_utils import (
    get_github_client,
    verify_webhook_signature,
    check_repository_dependencies,
    process_webhook_event,
    scan_repository_dependencies,
    create_dependency_report_issue,
    create_dependency_update_pr
)

load_dotenv()

def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Initialize scheduler
    with app.app_context():
        schedule_dependency_scans()
        print("✨ Dependency scanner initialized and scheduled")
    
    @app.route('/configure-repo', methods=['POST'])
    def configure_repository():
        """Configure repository for automatic dependency updates"""
        try:
            data = request.json
            if not data or 'repo_name' not in data:
                return jsonify({"error": "Repository name is required"}), 400
            
            repo_name = data['repo_name']
            print(f"⚙️ Configuring repository: {repo_name}")
            
            # Get GitHub client
            g = Github(os.getenv('GITHUB_TOKEN'))
            repo = g.get_repo(repo_name)
            
            # Initial scan and update
            print(f"🔍 Performing initial dependency scan for {repo_name}")
            scan_results = scan_repository_dependencies(repo_name)
            if not scan_results['success']:
                return jsonify({"error": scan_results['error']}), 500
            
            # Create initial report
            report_result = create_dependency_report_issue(repo_name, scan_results['dependencies'])
            if not report_result['success']:
                return jsonify({"error": report_result['error']}), 500
            
            print(f"📝 Created initial dependency report: {report_result['issue_url']}")
            
            # Check for outdated dependencies
            has_outdated = False
            outdated_deps = []
            for ecosystem, deps in scan_results['dependencies'].items():
                for dep in deps:
                    if dep.get('is_outdated'):
                        has_outdated = True
                        outdated_deps.append({
                            'name': dep['name'],
                            'current': dep['current_version'],
                            'latest': dep['latest_version']
                        })
            
            # Create pull request if there are outdated dependencies
            if has_outdated:
                branch_name = f"deps/auto-update-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                pr_result = create_dependency_update_pr(repo, scan_results['dependencies'], branch_name)
                if not pr_result['success']:
                    return jsonify({"error": pr_result['error']}), 500
                
                print(f"🔀 Created initial pull request: {pr_result['pr_url']}")
                
                return jsonify({
                    "status": "success",
                    "message": "Repository configured successfully",
                    "initial_scan": {
                        "issue_url": report_result['issue_url'],
                        "pr_url": pr_result['pr_url'],
                        "outdated_dependencies": outdated_deps
                    }
                }), 200
            else:
                return jsonify({
                    "status": "success",
                    "message": "Repository configured successfully - No outdated dependencies found",
                    "initial_scan": {
                        "issue_url": report_result['issue_url'],
                        "outdated_dependencies": []
                    }
                }), 200
            
        except Exception as e:
            print(f"❌ Error configuring repository: {str(e)}")
            return jsonify({"error": str(e)}), 500

    @app.route('/webhook', methods=['POST'])
    def webhook():
        # Verify webhook signature
        if not verify_webhook_signature(request):
            return jsonify({"error": "Invalid signature"}), 401

        event = request.headers.get('X-GitHub-Event')
        delivery_id = request.headers.get('X-GitHub-Delivery')
        
        print(f"🎣 Received webhook event")
        print(f"📥 Event type: {event}")
        print(f"🆔 Delivery ID: {delivery_id}")
        
        try:
            # Handle installation events
            if event == 'installation':
                action = request.json.get('action')
                if action == 'created':
                    installation_id = request.json['installation']['id']
                    repositories = request.json['repositories']
                    
                    print(f"📦 Processing installation for {len(repositories)} repositories")
                    
                    # Get GitHub client
                    g = get_github_client(installation_id)
                    if g:
                        for repo_info in repositories:
                            try:
                                repo_name = repo_info['full_name']
                                print(f"🔍 Scanning repository: {repo_name}")
                                
                                # Scan dependencies
                                scan_results = scan_repository_dependencies(repo_name)
                                if not scan_results['success']:
                                    print(f"❌ Error scanning {repo_name}: {scan_results['error']}")
                                    continue
                                
                                # Create report
                                report_result = create_dependency_report_issue(repo_name, scan_results['dependencies'])
                                if not report_result['success']:
                                    print(f"❌ Error creating report for {repo_name}: {report_result['error']}")
                                    continue
                                
                                print(f"📝 Created dependency report: {report_result['issue_url']}")
                                
                                # Check for outdated dependencies
                                has_outdated = False
                                outdated_deps = []
                                for ecosystem, deps in scan_results['dependencies'].items():
                                    for dep in deps:
                                        if dep.get('is_outdated'):
                                            has_outdated = True
                                            outdated_deps.append({
                                                'name': dep['name'],
                                                'current': dep['current_version'],
                                                'latest': dep['latest_version']
                                            })
                                
                                # Create pull request if there are outdated dependencies
                                if has_outdated:
                                    repo = g.get_repo(repo_name)
                                    branch_name = f"deps/auto-update-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                                    pr_result = create_dependency_update_pr(repo, scan_results['dependencies'], branch_name)
                                    if not pr_result['success']:
                                        print(f"❌ Error creating PR for {repo_name}: {pr_result['error']}")
                                        continue
                                    
                                    print(f"🔀 Created pull request: {pr_result['pr_url']}")
                                    print(f"📊 Found {len(outdated_deps)} outdated dependencies in {repo_name}")
                                
                            except Exception as e:
                                print(f"❌ Error processing repository {repo_info['full_name']}: {str(e)}")
                    
                    return jsonify({
                        "status": "success",
                        "message": f"Processed {len(repositories)} repositories"
                    }), 200
            
            # Process other webhook events
            result = process_webhook_event(event, request.json)
            if not result['success']:
                return jsonify({"error": result['error']}), 500

            return jsonify({"status": "success"}), 200
            
        except Exception as e:
            print(f"❌ Error processing webhook: {str(e)}")
            return jsonify({"error": str(e)}), 500

    return app

if __name__ == '__main__':
    load_dotenv()
    app = create_app()
    # Use the specific ngrok URL
    public_url = "https://a1cb-103-186-233-167.ngrok-free.app"
    print(f' * Tunnel URL: {public_url}')
    print(f' * Webhook URL: {public_url}/webhook')
    app.run(host='0.0.0.0', port=5000, debug=True) 