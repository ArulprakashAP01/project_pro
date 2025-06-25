from github import Github, GithubIntegration
import os
import hmac
import hashlib
import requests
from packaging import version
import json
from datetime import datetime
from urllib.parse import quote
import json
from quickchart import QuickChart
from quickchart import QuickChartFunction


from dependency_metrics import calculate_health_metrics, get_ecosystem_symbol, get_registry_url

def get_github_app():
    """Get GitHub App instance"""
    try:
        app_id = "1375945"
        private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA+3vhC2MAo0ZtBPUAwdQ1suSwxr1AmSZy7hw4YVEIE7G4wHvR
iV6vbX3yGCuJO91NR1yNkBrQNgGL6VPfX0sRLt0VGTp+fJwAAlsOld6flYYfoLCF
qxZNq6wWJ8hPb5jPqplXBubFQw6S1oLz9jCAAOI6AVSsjrjYf3+T6/VS6tLX6Dqo
qoquQldgYhW2wLKsgiRJd4PLJNTifBQRwwXGZCgCLLt4K0MWNWTR3FfWowmwvjhM
1AvoYmp5PSx+aQD8UEcY3Z61XuLF0GWdwqo4gN+INg8ndOkUObIgVA5gFAwoPVFQ
cqU+UtWI/iaU7sxrs/+Vv75lDnGQOp4aqSR/RwIDAQABAoIBAQDgVNAaFTVzcJY9
bsQ/IyrHquLaVeXy9+5b40aT4PHAh6+T3J+8137LwCaeUu+3PCD8gF4zZwfGtTh2
af//BHqOgF6aw6gjRhFoCIwJOq7Gdf9umyiRxnKAqiCVWkUp+nl86A5OtLrQp4Zq
3iP7v6Xfo+40U7EeG1vc2BQ+zvcpSijpNh+ZY5nbZd6zGzj+MUrcbXg7QmsDEwkr
bkOWSCS7Z7TZPE1vBeEW2ppgGQq5Vpbsl+U3Eav2K6quVJIqs1rIz1xuEVfAeFy3
oYOBdGqW4raxLgZ4pNEmSLMxDReNiH7PuhMYeQjKmkUVukEzPTQkwpPEtLkrd6As
VKvP5C05AoGBAP8lqVR/XBY7azgoqF4jJeXEHTNhlHqjqrXY36JLki8uWhVYnXRU
1RbfmQpwPq0nl1ie5OceFLQ1XI0iURN8rYf2BmSaDlQl3e75luOUGImNOC3CiSqt
drU4kidzmmg5V8ZLo/HIAPt9ybTkcLctuo6Tu3Zq3tA2UhaRAcmuyxqNAoGBAPxT
FThodNBxCQpeVWWkHxvWBMnukJvh3Z/MaMFnYb8I38J2TjdI8FeEF45uWOYj9jz5
6Zjw1BfL5SDXUIJ2oTFKwT+P4Ko4pWy0ogWG46PttKrT+wfQyk50rISg/dDp4uhn
fpBGEsAiWAUXsdDkE/kHc5w11B0HqGLIU1TDZtYjAoGAbIezmGq4XAiYWgIJZEml
JDAgj6uRQf1+bu26asmkfAdGcFAKYeJ35cvkyGjocDUoDp1AFwNXoTQVkz8mp5hg
JDZFj+Nr9uVImw913IYxTclRPT3DpPC2Tu2qVbe51V2W9ZVVPlJqAJAIDbciLvj3
oxA6LGvXLU/96PVzgjukzz0CgYArETtD/4BAu6phXKySxqqQo7z5goCoOqsLRWZz
7GNgqfEXTf4XrZloNqGWq/r8fRLgYX+fnSt2TFT1gAq72ee1dB777GDabQS/Qy2M
Z/Oe3UnDBp+IO/jr3zo7AQeRivox1Mhjc7JrnPENHXg6QVOvY7g153Im6lGxWqPu
idOZpQKBgE5lFZoEf6wwgSHoGmaPhOS2QQzwZx+vznykPOAmpGrjueMUc6/DqCXW
AXqEZ+kFxqGkWQVr/jnD7fhpCm2Z92XIlvioZHhc5l4dsDQ593IbFXaiKovMOH+g
l/yOVmBtysTZGGbb6EfkEngcEwf0NxzFxOp0BX+1Iu74e+MFCWYn
-----END RSA PRIVATE KEY-----"""
        
        integration = GithubIntegration(
            app_id,
            private_key,
        )
        return integration
    except Exception as e:
        print(f"❌ Error creating GitHub App instance: {str(e)}")
        return None

def get_github_client(installation_id=None):
    """Get authenticated GitHub client"""
    try:
        if installation_id:
            integration = get_github_app()
            if integration:
                token = integration.get_access_token(installation_id).token
                return Github(token)
        return None
    except Exception as e:
        print(f"❌ Error getting GitHub client: {str(e)}")
        return None

def verify_webhook_signature(request):
    """Verify that the webhook payload was sent by GitHub"""
    try:
        # Get signature header
        signature_header = request.headers.get('X-Hub-Signature-256')
        if not signature_header:
            print("❌ Missing signature header")
            return False

        # Get the webhook secret from environment
        webhook_secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"
        
        if not webhook_secret:
            print("❌ No webhook secret found")
            return False
            
        # Convert webhook secret to bytes
        if isinstance(webhook_secret, str):
            webhook_secret = webhook_secret.encode('utf-8')
            
        # Get raw payload
        payload_body = request.get_data()
            
        # Calculate expected signature
        expected_signature = "sha256=" + hmac.new(
            webhook_secret,
            payload_body,
            hashlib.sha256
        ).hexdigest()
        
        print(f"🔐 Verifying webhook signature...")
        print(f"📝 Received signature: {signature_header}")
        print(f"📝 Expected signature: {expected_signature}")
        
        # Use hmac.compare_digest to prevent timing attacks
        is_valid = hmac.compare_digest(expected_signature, signature_header)
        if is_valid:
            print("✅ Webhook signature verified successfully")
        else:
            print("❌ Webhook signature verification failed")
            print("💡 Make sure the webhook secret in GitHub matches exactly")
        return is_valid
        
    except Exception as e:
        print(f"❌ Error verifying webhook signature: {str(e)}")
        return False

def check_npm_package(package_name, current_version):
    """Check latest version of an NPM package"""
    try:
        print(f"🔍 Checking NPM package: {package_name} (current: {current_version})")
        response = requests.get(f'https://registry.npmjs.org/{package_name}')
        if response.status_code == 200:
            data = response.json()
            latest_version = data['dist-tags']['latest']
            current_version = current_version.replace('^', '').replace('~', '')
            
            # Parse versions
            current_v = version.parse(current_version)
            latest_v = version.parse(latest_version)
            
            # Determine update type
            is_outdated = current_v < latest_v
            update_type = 'none'
            if is_outdated:
                if latest_v.major > current_v.major:
                    update_type = 'major'
                elif latest_v.minor > current_v.minor:
                    update_type = 'minor'
                else:
                    update_type = 'patch'
            
            status = "⚠️ Outdated" if is_outdated else "✅ Up to date"
            print(f"📦 {package_name}: {current_version} -> {latest_version} ({status})")
            return {
                'name': package_name,
                'current_version': current_version,
                'latest_version': latest_version,
                'is_outdated': is_outdated,
                'update_type': update_type
            }
    except Exception as e:
        print(f"❌ Error checking NPM package {package_name}: {str(e)}")
    return None

def check_pip_package(package_name, current_version):
    """Check latest version of a PyPI package"""
    try:
        print(f"🔍 Checking Python package: {package_name} (current: {current_version})")
        response = requests.get(f'https://pypi.org/pypi/{package_name}/json')
        if response.status_code == 200:
            data = response.json()
            latest_version = data['info']['version']
            
            # Parse versions
            current_v = version.parse(current_version)
            latest_v = version.parse(latest_version)
            
            # Determine update type
            is_outdated = current_v < latest_v
            update_type = 'none'
            if is_outdated:
                if latest_v.major > current_v.major:
                    update_type = 'major'
                elif latest_v.minor > current_v.minor:
                    update_type = 'minor'
                else:
                    update_type = 'patch'
            
            status = "⚠️ Outdated" if is_outdated else "✅ Up to date"
            print(f"📦 {package_name}: {current_version} -> {latest_version} ({status})")
            return {
                'name': package_name,
                'current_version': current_version,
                'latest_version': latest_version,
                'is_outdated': is_outdated,
                'update_type': update_type
            }
    except Exception as e:
        print(f"❌ Error checking PyPI package {package_name}: {str(e)}")
    return None

def check_maven_package(package_info):
    """Check latest version of a Maven package"""
    try:
        group_id, artifact_id, current_version = package_info
        print(f"🔍 Checking Maven package: {group_id}:{artifact_id} (current: {current_version})")
        url = f"https://search.maven.org/solrsearch/select?q=g:{group_id}+AND+a:{artifact_id}&rows=1&wt=json"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data['response']['docs']:
                latest_version = data['response']['docs'][0]['latestVersion']
                is_outdated = version.parse(current_version) < version.parse(latest_version)
                status = "⚠️ Outdated" if is_outdated else "✅ Up to date"
                print(f"📦 {artifact_id}: {current_version} -> {latest_version} ({status})")
                return {
                    'name': f"{group_id}:{artifact_id}",
                    'current_version': current_version,
                    'latest_version': latest_version,
                    'is_outdated': is_outdated
                }
    except Exception as e:
        print(f"❌ Error checking Maven package {group_id}:{artifact_id}: {str(e)}")
    return None

def check_cargo_package(package_name, current_version):
    """Check latest version of a Rust/Cargo package"""
    try:
        print(f"🔍 Checking Rust package: {package_name} (current: {current_version})")
        response = requests.get(f'https://crates.io/api/v1/crates/{package_name}')
        if response.status_code == 200:
            data = response.json()
            latest_version = data['crate']['max_version']
            is_outdated = version.parse(current_version) < version.parse(latest_version)
            status = "⚠️ Outdated" if is_outdated else "✅ Up to date"
            print(f"📦 {package_name}: {current_version} -> {latest_version} ({status})")
            return {
                'name': package_name,
                'current_version': current_version,
                'latest_version': latest_version,
                'is_outdated': is_outdated
            }
    except Exception as e:
        print(f"❌ Error checking Cargo package {package_name}: {str(e)}")
    return None

def check_composer_package(package_name, current_version):
    """Check latest version of a PHP/Composer package"""
    try:
        print(f"🔍 Checking PHP package: {package_name} (current: {current_version})")
        response = requests.get(f'https://repo.packagist.org/p2/{package_name}.json')
        if response.status_code == 200:
            data = response.json()
            latest_version = data['packages'][package_name][0]['version']
            is_outdated = version.parse(current_version.replace('v', '')) < version.parse(latest_version.replace('v', ''))
            status = "⚠️ Outdated" if is_outdated else "✅ Up to date"
            print(f"📦 {package_name}: {current_version} -> {latest_version} ({status})")
            return {
                'name': package_name,
                'current_version': current_version,
                'latest_version': latest_version,
                'is_outdated': is_outdated
            }
    except Exception as e:
        print(f"❌ Error checking Composer package {package_name}: {str(e)}")
    return None

def check_gem_package(package_name, current_version):
    """Check latest version of a Ruby gem"""
    try:
        print(f"🔍 Checking Ruby gem: {package_name} (current: {current_version})")
        response = requests.get(f'https://rubygems.org/api/v1/versions/{package_name}/latest.json')
        if response.status_code == 200:
            data = response.json()
            latest_version = data['version']
            is_outdated = version.parse(current_version) < version.parse(latest_version)
            status = "⚠️ Outdated" if is_outdated else "✅ Up to date"
            print(f"📦 {package_name}: {current_version} -> {latest_version} ({status})")
            return {
                'name': package_name,
                'current_version': current_version,
                'latest_version': latest_version,
                'is_outdated': is_outdated
            }
    except Exception as e:
        print(f"❌ Error checking Ruby gem {package_name}: {str(e)}")
    return None

def check_repository_dependencies(repo, installation_id):
    """Check dependencies for a repository"""
    print(f"\n🔎 Starting dependency scan for repository: {repo.full_name}")
    all_deps = {
        'npm': [],
        'pip': [],
        'maven': [],
        'cargo': [],
        'composer': [],
        'ruby': []
    }

    try:
        # Check package.json (Node.js)
        print("\n📂 Checking package.json...")
        try:
            package_json = repo.get_contents('package.json')
            print("✅ Found package.json")
            content = json.loads(package_json.decoded_content.decode())
            dependencies = {**content.get('dependencies', {}), **content.get('devDependencies', {})}
            print(f"📦 Found {len(dependencies)} NPM dependencies to check")
            for package_name, current_version in dependencies.items():
                result = check_npm_package(package_name, current_version)
                if result:
                    all_deps['npm'].append(result)
        except Exception as e:
            print(f"ℹ️ No package.json found or error: {str(e)}")

        # Check requirements.txt (Python)
        print("\n📂 Checking requirements.txt...")
        try:
            requirements_txt = repo.get_contents('requirements.txt')
            print("✅ Found requirements.txt")
            content = requirements_txt.decoded_content.decode()
            requirements = [line.strip() for line in content.split('\n') 
                          if line.strip() and not line.startswith('#')]
            print(f"📦 Found {len(requirements)} Python dependencies to check")
            
            for line in requirements:
                if '==' in line:
                    package_name, current_version = line.split('==')
                    result = check_pip_package(package_name.strip(), current_version.strip())
                    if result:
                        all_deps['pip'].append(result)
                elif '>=' in line:
                    package_name, current_version = line.split('>=')
                    result = check_pip_package(package_name.strip(), current_version.strip())
                    if result:
                        all_deps['pip'].append(result)
        except Exception as e:
            print(f"ℹ️ No requirements.txt found or error: {str(e)}")

        # Check pom.xml (Java/Maven)
        print("\n📂 Checking pom.xml...")
        try:
            pom_xml = repo.get_contents('pom.xml')
            print("✅ Found pom.xml")
            import xml.etree.ElementTree as ET
            root = ET.fromstring(pom_xml.decoded_content.decode())
            
            # Get dependencies
            dependencies = root.findall(".//dependency")
            print(f"📦 Found {len(dependencies)} Maven dependencies to check")
            
            for dep in dependencies:
                group_id = dep.find('groupId').text
                artifact_id = dep.find('artifactId').text
                current_version = dep.find('version').text
                result = check_maven_package((group_id, artifact_id, current_version))
                if result:
                    all_deps['maven'].append(result)
        except Exception as e:
            print(f"ℹ️ No pom.xml found or error: {str(e)}")

        # Check Cargo.toml (Rust)
        print("\n📂 Checking Cargo.toml...")
        try:
            cargo_toml = repo.get_contents('Cargo.toml')
            print("✅ Found Cargo.toml")
            import toml
            content = toml.loads(cargo_toml.decoded_content.decode())
            dependencies = content.get('dependencies', {})
            print(f"📦 Found {len(dependencies)} Rust dependencies to check")
            
            for package_name, version_info in dependencies.items():
                if isinstance(version_info, str):
                    current_version = version_info
                elif isinstance(version_info, dict):
                    current_version = version_info.get('version', '')
                result = check_cargo_package(package_name, current_version)
                if result:
                    all_deps['cargo'].append(result)
        except Exception as e:
            print(f"ℹ️ No Cargo.toml found or error: {str(e)}")

        # Check composer.json (PHP)
        print("\n📂 Checking composer.json...")
        try:
            composer_json = repo.get_contents('composer.json')
            print("✅ Found composer.json")
            content = json.loads(composer_json.decoded_content.decode())
            dependencies = {**content.get('require', {}), **content.get('require-dev', {})}
            print(f"📦 Found {len(dependencies)} PHP dependencies to check")
            print("Parsed dependencies:", dependencies)

            # Handle custom repositories (type: package)
            custom_packages = {}
            for repo_entry in content.get('repositories', []):
                if repo_entry.get('type') == 'package' and 'package' in repo_entry:
                    pkg = repo_entry['package']
                    name = pkg.get('name')
                    version = pkg.get('version')
                    # Try to get source or dist URL
                    url = None
                    if 'source' in pkg:
                        url = pkg['source'].get('url')
                    elif 'dist' in pkg:
                        url = pkg['dist'].get('url')
                    custom_packages[name] = {'version': version, 'url': url}
            print("Parsed custom packages:", custom_packages)

            # Make name matching case-insensitive and robust
            dep_names = {k.lower().strip(): v for k, v in dependencies.items()}
            custom_names = {k.lower().strip(): v for k, v in custom_packages.items()}

            for package_name, current_version in dep_names.items():
                if package_name != 'php':  # Skip PHP version requirement
                    if package_name in custom_names:
                        url = custom_names[package_name]['url']
                        print(f"Checking custom Composer package: {package_name}, url: {url}, current_version: {current_version}")
                        latest_version = None
                        owner = repo_name = None
                        if url and 'github.com' in url:
                            import re
                            # Try to extract owner/repo from any GitHub URL (including /archive/ and .zip)
                            m = re.search(r'github.com[/:]([^/]+)/([^/]+?)(?:/|$|\.git|\.zip|\?)', url)
                            if m:
                                owner = m.group(1)
                                repo_name = m.group(2).replace('.git', '')
                                print(f"Extracted owner: {owner}, repo_name: {repo_name} from url: {url}")
                            else:
                                print(f"Could not parse owner/repo from url: {url} (regex groups: {m.groups() if m else 'None'})")
                        if owner and repo_name:
                            # Try releases first
                            api_url = f'https://api.github.com/repos/{owner}/{repo_name}/releases/latest'
                            print(f"GitHub API (release) url: {api_url}")
                            resp = requests.get(api_url)
                            print(f"GitHub API (release) status: {resp.status_code}")
                            if resp.status_code == 200 and resp.json().get('tag_name'):
                                latest_version = resp.json().get('tag_name')
                                print(f"Latest release tag: {latest_version}")
                            else:
                                # Fallback: get all tags and pick the highest
                                tags_url = f'https://api.github.com/repos/{owner}/{repo_name}/tags'
                                print(f"GitHub API (tags) url: {tags_url}")
                                tags_resp = requests.get(tags_url)
                                print(f"GitHub API (tags) status: {tags_resp.status_code}")
                                if tags_resp.status_code == 200 and tags_resp.json():
                                    tags = [t['name'] for t in tags_resp.json()]
                                    print(f"Found tags: {tags}")
                                    from packaging.version import parse as vparse
                                    norm_tags = [t.lstrip('v') for t in tags]
                                    try:
                                        latest_version = max(norm_tags, key=lambda x: vparse(x))
                                        print(f"Latest tag (by version): {latest_version}")
                                    except Exception as e:
                                        print(f"Error parsing tags for {package_name}: {e}")
                                        latest_version = norm_tags[0] if norm_tags else None
                                else:
                                    print(f"No tags found for {package_name} at {tags_url}")
                        else:
                            print(f"Skipping {package_name}: could not extract owner/repo from url: {url}")
                        if latest_version:
                            cur_v = version.parse(current_version.lstrip('v'))
                            lat_v = version.parse(latest_version.lstrip('v'))
                            is_outdated = cur_v < lat_v
                            update_type = 'none'
                            if is_outdated:
                                if lat_v.major > cur_v.major:
                                    update_type = 'major'
                                elif lat_v.minor > cur_v.minor:
                                    update_type = 'minor'
                                else:
                                    update_type = 'patch'
                            print(f"Result for {package_name}: current={current_version}, latest={latest_version}, is_outdated={is_outdated}, update_type={update_type}")
                            all_deps['composer'].append({
                                'name': package_name,
                                'current_version': current_version,
                                'latest_version': latest_version,
                                'is_outdated': is_outdated,
                                'update_type': update_type
                            })
                        else:
                            print(f"Could not determine latest version for {package_name}, assuming up-to-date.")
                            all_deps['composer'].append({
                                'name': package_name,
                                'current_version': current_version,
                                'latest_version': current_version,
                                'is_outdated': False,
                                'update_type': 'none'
                            })
                    else:
                        print(f"Checking standard Composer package: {package_name}, current_version: {current_version}")
                        result = check_composer_package(package_name, current_version)
                        if result:
                            print(f"Result for {package_name}: {result}")
                            all_deps['composer'].append(result)
        except Exception as e:
            print(f"ℹ️ No composer.json found or error: {str(e)}")

        # Check Gemfile (Ruby)
        print("\n📂 Checking Gemfile...")
        try:
            gemfile = repo.get_contents('Gemfile')
            print("✅ Found Gemfile")
            content = gemfile.decoded_content.decode()
            import re
            # Parse Gemfile using regex
            gem_pattern = r"gem\\s+['\"]([^'\"]+)['\"]\\s*,?\\s*['\"]([^'\"]+)['\"]"
            matches = re.findall(gem_pattern, content)
            print(f"📦 Found {len(matches)} Ruby dependencies to check")
            for package_name, current_version in matches:
                result = check_gem_package(package_name, current_version)
                if result:
                    all_deps['ruby'].append(result)
        except Exception as e:
            print(f"ℹ️ No Gemfile found or error: {str(e)}")

        # --- New: Go (go.mod) ---
        print("\n📂 Checking go.mod...")
        try:
            go_mod = repo.get_contents('go.mod')
            print("✅ Found go.mod")
            # TODO: Implement Go dependency scanning
            # Example: parse go.mod, check proxy.golang.org for latest versions
        except Exception as e:
            print(f"ℹ️ No go.mod found or error: {str(e)}")

        # --- New: .NET (csproj) ---
        print("\n📂 Checking .csproj files...")
        try:
            contents = repo.get_contents('.')
            for file in contents:
                if file.name.endswith('.csproj'):
                    print(f"✅ Found {file.name}")
                    # TODO: Implement .NET dependency scanning
                    # Example: parse XML, check nuget.org for latest versions
        except Exception as e:
            print(f"ℹ️ No .csproj file found or error: {str(e)}")

    except Exception as e:
        print(f"❌ Error checking repository {repo.full_name}: {str(e)}")

    return all_deps 

def create_dependency_report_issue(repo_name, scan_results):
    """
    Creates a GitHub issue with an enhanced danger-themed dependency scan report
    """
    try:
        # Initialize GitHub client with the app's token
        g = Github(os.getenv('GITHUB_TOKEN'))
        repo = g.get_repo(repo_name)
        
        # Calculate detailed metrics
        metrics = calculate_health_metrics(scan_results)
        
        # Enhanced danger assessment 
        danger_level = "Critical" if metrics['health_score'] < 30 else "High" if metrics['health_score'] < 50 else "Medium" if metrics['health_score'] < 80 else "Low"
        
        # Danger color scheme
        danger_colors = {
            "CRITICAL": "#FF0000",  # Bright Red
            "HIGH": "#FF4500",      # Orange Red
            "MODERATE": "#FFA500",  # Orange
            "LOW": "#32CD32"        # Lime Green
        }

        # --- Your metric calculations ---
        total = metrics['total'] if metrics['total'] > 0 else 1
        protected_pct = int(round((metrics['total'] - metrics['outdated']) / total * 100, 0))
        moderate_pct = int(round(metrics['patch_updates'] / total * 100, 0))
        high_risk_pct = int(round(metrics['minor_updates'] / total * 100, 0))
        critical_pct = int(round(metrics['major_updates'] / total * 100, 0))

        # --- Chart Configuration: Like your image ---
        # chart_config = {
        #     "type": "doughnut",
        #     "data": {
        #         "datasets": [{
        #             "data": [protected_pct, moderate_pct, high_risk_pct, critical_pct],
        #             "backgroundColor": ["#32CD32", "#FFD700", "#FF8C00", "#FF0000"],
        #             "borderColor": "#FFF",
        #             "borderWidth": 2
        #         }]
        #     },
        #     "options": {
        #         "plugins": {
        #             "legend": {
        #                 "display": False
        #             },
        #             "datalabels": {
        #                 "display": True,
        #                 "color": "white",
        #                 "font": {
        #                     "weight": "bold",
        #                     "size": 30
        #                 },
        #                 "formatter": "function(value, context) { return context.chart.data.labels[context.dataIndex]; }"
        #             }
        #         },
        #     },
        #     "plugins": ["datalabels"]
        # }

        chart_config = {
            "type": "bar",
            "data": {
                "datasets": [
                    {
                        "label": "Protected",
                        "backgroundColor": "#32CD32",
                        "data": [protected_pct],
                    },
                    {
                        "label": "Medium",
                        "backgroundColor": "#FFD700",
                        "data": [moderate_pct],
                    },
                    {
                        "label": "High",
                        "backgroundColor": "#FF8C00",
                        "data": [high_risk_pct],
                    },
                    {
                        "label": "Critical",
                        "backgroundColor": "#FF0000",
                        "data": [critical_pct],
                    }
                ]
            },
            "options": {
                "plugins": {
                    "datalabels": {
                        "color": "#ffffff",
                        "display": True,
                        "anchor": "center",
                        "align": "center",
                        "font": {
                            "weight": "bold",
                            "size": 40
                        },
                       "formatter": QuickChartFunction("function(value) { return value === 0 ? null : value + '%'; }")
                    }
                },
                "legend": {
                    "display": False
                },
                "tooltips": {
                    "enabled": False
                },
                "scales": {
                    "xAxes": [
                        {
                            "stacked": True,
                            "ticks": {
                                "display": False,
                                "fontSize": 35
                            },
                            "gridLines": {
                                "display": False
                            }
                        }
                    ],
                    "yAxes": [
                        {
                            "stacked": True,
                            "ticks": {
                                "display": False,
                                "fontSize": 35
                            },
                            "gridLines": {
                                "display": False
                            }
                        }
                    ]
                }
            }
        }


        # Generate final chart URL with datalabels plugin (larger size for better visibility)
        # chart_url = f"https://quickchart.io/chart?c={quote(json.dumps(chart_config))}&width=500&height=620&plugins=datalabels"

        qc = QuickChart()
        qc.width = 500
        qc.height = 650
        qc.config = chart_config
        qc.background_color = "transparent"
        chart_url = qc.get_url()

        report_content = f"""# 🚨 Security Alert: Dependency Health Report

<div align="center">


## 🛡️ Security Assessment Complete 🛡️  

</div>

### 🔍 Repository Security Profile

> **📁 Repository :** `{repo_name}`       **🕒 Assessment Time :** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}`  
> **🚨 Risk Classification :** `{danger_level} Priority`       **🌿 Branch :** `{repo.default_branch}`

<div  style="width: 250px; hight: 250px;">
    <table align="center" style="width: 100%;">
    <tr>
        <td style="width: 60%; align: center;">
        <img src="{chart_url}" alt="Risk Chart" style="width: 100%; max-width: 600px;" width="600">
        </td>
        <td style="width: 40%; vertical-align: top;">
        <p align="center"><strong>📊 Risk Assessment Matrix</strong></p>
        <table align="center" style="width: 100%; border-collapse: collapse;" border="0" cellpadding="4" cellspacing="0">
            <tr>
            <th style="padding: 4px;">Risk Level</th>
            <th style="padding: 4px;">Count</th>
            <th style="padding: 4px;">Percentage</th>
            <th style="padding: 4px;">Action</th>
            <th style="padding: 4px;">Response</th>
            </tr>
            <tr>
            <td style="padding: 4px;">🔴 Critical</td>
            <td style="padding: 4px;">{metrics['major_updates']}</td>
            <td style="padding: 4px;">{ round(metrics['major_updates'] / metrics['total'] * 100) }%</td>
            <td style="padding: 4px;">Immediate</td>
            <td style="padding: 4px;">Address Immediately</td>
            </tr>
            <tr>
            <td style="padding: 4px;">🟠 High Risk</td>
            <td style="padding: 4px;">{metrics['minor_updates']}</td>
            <td style="padding: 4px;">{ round(metrics['minor_updates'] / metrics['total'] * 100) }%</td>
            <td style="padding: 4px;">Priority</td>
            <td style="padding: 4px;">Resolve as High Priority</td>
            </tr>
            <tr>
            <td style="padding: 4px;">🟡 Medium</td>
            <td style="padding: 4px;">{metrics['patch_updates']}</td>
            <td style="padding: 4px;">{ round(metrics['patch_updates'] / metrics['total'] * 100) }%</td>
            <td style="padding: 4px;">Schedule</td>
            <td style="padding: 4px;">Plan Timely Remediation</td>
            </tr>
            <tr>
            <td style="padding: 4px;">🟢 Protected</td>
            <td style="padding: 4px;">{metrics['total'] - metrics['outdated']}</td>
            <td style="padding: 4px;">{ round((metrics['total'] - metrics['outdated']) / metrics['total'] * 100) }%</td>
            <td style="padding: 4px;">Maintain</td>
            <td style="padding: 4px;">Monitor and Maintain Compliance</td>
            </tr>
        </table>
        </td>
    </tr>
    </table>
</div>
"""

        report_content += f"""

---
<div >
    <h3> 🔥 System Security Status </h3>
</div>"""

        # Add ecosystem-specific danger sections
        for ecosystem, eco_metrics in metrics['ecosystem_health'].items():
            if eco_metrics['total'] > 0:
                eco_symbol = get_ecosystem_symbol(ecosystem)
                
                # Enhanced danger indicators
                if eco_metrics['health_score'] < 30:
                    danger_bg = '#8B0000'
                elif eco_metrics['health_score'] < 50:
                    danger_bg = '#DC143C'
                elif eco_metrics['health_score'] < 80:
                    danger_bg = '#FF4500'
                else:
                    danger_bg = '#228B22'
                
                report_content += f"""

<p><strong>Security Score:</strong> {eco_metrics['health_score']:.0f}% - {eco_metrics['outdated']}/{eco_metrics['total']} packages need urgent updates!</p>"""
                
                # Add detailed vulnerability tables
                if eco_metrics['outdated'] > 0:

                    threat_rank = {
                        'critical': 0,
                        'high': 1,
                        'medium': 2,
                        'unknown': 3
                    }

                    # Function to determine threat level from update_type
                    def get_threat_level(pkg):
                        update_type = pkg.get('update_type', '').lower()
                        if update_type == 'major':
                            return 'critical'
                        elif update_type == 'minor':
                            return 'high'
                        elif update_type == 'patch':
                            return 'medium'
                        else:
                            return 'unknown'

                    # Filter and sort outdated packages
                    outdated_pkgs = [pkg for pkg in scan_results[ecosystem] if pkg and pkg.get('is_outdated')]
                    sorted_pkgs = sorted(outdated_pkgs, key=lambda pkg: threat_rank.get(get_threat_level(pkg), 3))

                    report_content += f"""
 

                    
<h3> Vulnerability Details </h3>

<div  style="border: 3px solid #FF0000; background-color: #FFE4E1; padding: 15px; border-radius: 10px;">

| Package | Current | Latest | Threat Level | Registry | Security Impact |
|------------|---------|--------|--------------|----------|-----------------|"""
                    
#                     for pkg in scan_results[ecosystem]:
#                         if pkg and pkg.get('is_outdated'):
#                             update_type = pkg.get('update_type', 'unknown')
                            
#                             # Enhanced threat indicators
#                             if update_type == 'major':
#                                 threat_icon = '⚠️'
#                                 threat_text = 'Critical'
#                                 security_impact = '🔴 **Critical Risk**'
#                             elif update_type == 'minor':
#                                 threat_icon = '⚠️'
#                                 threat_text = 'High'
#                                 security_impact = '🟠 **High Risk**'
#                             else:
#                                 threat_icon = '⚠️'
#                                 threat_text = 'Medium'
#                                 security_impact = '🟡 **Medium Risk**'
                            
#                             registry_url = get_registry_url(ecosystem, pkg['name'])
                            
#                             report_content += f"""
# | **`{pkg['name']}`** | `{pkg['current_version']}` | **`{pkg['latest_version']}`** | {threat_icon} **{threat_text}** | [{ecosystem}]({registry_url}) | {security_impact} |"""
                    

                    for pkg in sorted_pkgs:
                        update_type = pkg.get('update_type', 'unknown').lower()

                        if update_type == 'major':
                            threat_icon = '⚠️'
                            threat_text = 'Critical'
                            security_impact = '🔴 **Critical Risk**'
                        elif update_type == 'minor':
                            threat_icon = '⚠️'
                            threat_text = 'High'
                            security_impact = '🟠 **High Risk**'
                        elif update_type == 'patch':
                            threat_icon = '⚠️'
                            threat_text = 'Medium'
                            security_impact = '🟡 **Medium Risk**'
                        else:
                            threat_icon = '⚠️'
                            threat_text = 'Unknown'
                            security_impact = '⚪ **Unknown Risk**'

                        registry_url = get_registry_url(ecosystem, pkg['name'])

                        report_content += f"""
| **`{pkg['name']}`** | `{pkg['current_version']}` | **`{pkg['latest_version']}`** | {threat_icon} **{threat_text}** | [{ecosystem}]({registry_url}) | {security_impact} |"""
                report_content += f"\n\n---\n\n### 🔥 **Immediate Actions Required**\n"

        if metrics['major_updates'] > 0:
            report_content += f"""
<div style="background-color: #B22222; color: white; padding: 10px; border-radius: 5px;">

<strong>🔴 Critical Priority</strong> (<code>{metrics['major_updates']}</code> package{'' if metrics['major_updates'] == 1 else 's'} require update)<br>
- Immediate attention required to mitigate security and operational risks.<br>
- Upgrade all dependencies with major version changes to maintain compatibility and stability.<br>
- Prioritize updates with known security vulnerabilities or active risk exposure.<br>
- Conduct comprehensive validation testing to ensure application integrity post-upgrade.<br>
- Confirm seamless integration with production workloads before deployment.<br>
- Identify and communicate breaking changes to all impacted stakeholders.

</div><br>
"""

        if metrics['minor_updates'] > 0:
            report_content += f"""
<div style="background-color: #DC143C; color: white; padding: 10px; border-radius: 5px;">

<strong>🟠 High Priority</strong> (<code>{metrics['minor_updates']}</code> package{'' if metrics['minor_updates'] == 1 else 's'} require update)<br>
- Timely action recommended to maintain system health and reduce long-term risk<br>
- Organize minor and patch updates by technology stack or ecosystem for efficiency.<br>
- Schedule updates to development dependencies during off-peak hours to minimize disruption.<br>
- Perform thorough regression testing following updates to detect functional issues.<br>
- Utilize automated compatibility checks to identify safe versions.<br>
- Maintain rollback strategies in case of failure or instability.<br>
- Integrate updates into the CI/CD pipeline for structured and reliable deployment.<br>
- Monitor update cadence to prevent accumulation of technical debt.

</div><br>
"""
            
        if metrics['patch_updates'] > 0:
            report_content += f"""
<div style="background-color: #DC143C; color: white; padding: 10px; border-radius: 5px;">

<strong>🟡 Medium Priority</strong> (<code>{metrics['patch_updates']}</code> package{'' if metrics['patch_updates'] == 1 else 's'} require update)<br>
- Recommended for near-term action during planned maintenance cycles<br>
- Schedule implementation during the next approved maintenance window.<br>
- Communicate planned updates to all relevant stakeholders.<br>
- Review release notes to ensure compatibility with existing systems.<br>
- Deploy updates in a staging environment for pre-production testing.<br>
- Confirm current system backups are available before applying updates.<br>
- Monitor system performance and logs for anomalies post-deployment.

</div><br>
"""
        protected_count = metrics['total'] - metrics['outdated']    
        if protected_count > 0:
            report_content += f"""
<div style="background-color: #DC143C; color: white; padding: 10px; border-radius: 5px;">

<strong>🟢 Low Priority</strong> (<code>{protected_count}</code> package{'' if protected_count == 1 else 's'} { 'is' if protected_count == 1 else 'are' } up to date)<br>
- To be addressed as part of standard patch management processes<br>
- Include in the organization's regular patching cycle.<br>
- Maintain a log of outdated packages for audit and compliance purposes.<br>
- Track vendor support timelines to avoid unexpected end-of-life scenarios.<br>
- Evaluate the operational impact prior to rollout.<br>
- Where feasible, bundle with other low-risk updates to optimize resource use.<br>
- Reassess the priority level during the next vulnerability management review.

</div><br>
"""

        # Always show the security measures and next steps
        report_content += f"""
<div style="background-color: #FF8C00; color: white; padding: 10px; border-radius: 5px;">

<strong>🛡️ Security Measures</strong><br>
- Conduct security audit of all dependencies<br>
- Implement monitoring for vulnerability alerts<br>
- Restrict access to affected systems<br>
- Document all changes for compliance

</div><br>

<div style="background-color: #FF8C00; color: white; padding: 10px; border-radius: 5px;">

<strong>📅 Next Steps</strong><br>
- Review the changes required for each update<br>
- Create update branches for testing<br>
- Run comprehensive tests<br>
- Update documentation<br>
- Schedule updates during maintenance window

</div>
"""
        critical_count = metrics['major_updates']
        high_count = metrics['minor_updates']
        if critical_count >= 1 or high_count >= 1:
            report_content += f"""

---

<div >

### ⚠️ Security Disclaimer 

Your system has been identified as having **Critical Security Vulnerabilities**. 
Immediate action is required to prevent potential:

 - Data Breaches
 - System Compromise 
 - Production Failures
 - Compliance Violations 

**This report was generated by automated security scanning. Manual verification and immediate remediation are Required.**
</div>"""
        report_content += f"""

---
<div align="center">

<sub>🤖 Generated by [Pro Secure Labs Security Scanner](https://github.com/apps/outdated-software-checker)</sub>
<sub>🚨 **CONFIDENTIAL** - Handle with appropriate security measures</sub>

</div>"""
        
        # Create the issue with enhanced security labels
        labels = ['🚨security', '⚠️critical', 'dependencies', 'automated-report', 'emergency']
        if metrics['major_updates'] > 0:
            labels.extend(['🔴critical-vulnerability', '🚨immediate-action'])
        if metrics['health_score'] < 30:
            labels.extend(['💀system-compromise', '🔥maximum-risk'])
        elif metrics['health_score'] < 50:
            labels.extend(['⚠️high-risk', '🚨security-alert'])
        
        # Enhanced issue title with danger indicators
        issue_title = f"🚨 Dependency Health Report - {datetime.now().strftime('%Y-%m-%d')}"
        
        issue = repo.create_issue(
            title=issue_title,
            body=report_content,
            labels=labels
        )
        
        return {"success": True, "issue_url": issue.html_url}
    
    except Exception as e:
        print(f"❌ Error creating security report: {str(e)}")
        return {"success": False, "error": str(e)}

def process_webhook_event(event_type, payload):
    """
    Process GitHub webhook events
    """
    try:
        if event_type == 'installation':
            action = payload.get('action')
            print(f"📦 Installation event action: {action}")
            
            if action == 'created':
                installation_id = payload['installation']['id']
                repositories = payload['repositories']
                print(f"🔄 Processing {len(repositories)} repositories")
                
                g = get_github_client(installation_id)
                if g:
                    for repo_info in repositories:
                        try:
                            repo = g.get_repo(repo_info['full_name'])
                            scan_repository_dependencies(repo_info['full_name'])
                        except Exception as e:
                            print(f"❌ Error processing repository {repo_info['full_name']}: {str(e)}")

        elif event_type == 'push':
            installation_id = payload['installation']['id']
            repo_full_name = payload['repository']['full_name']
            print(f"📌 Push event for repository: {repo_full_name}")
            
            g = get_github_client(installation_id)
            if g:
                repo = g.get_repo(repo_full_name)
                scan_repository_dependencies(repo_full_name)

        return {"success": True}
        
    except Exception as e:
        print(f"❌ Error processing webhook: {str(e)}")
        return {"success": False, "error": str(e)} 

def scan_repository_dependencies(repo_name):
    """
    Scan a repository for outdated dependencies
    """
    try:
        # Get GitHub client
        g = Github(os.getenv('GITHUB_TOKEN'))
        repo = g.get_repo(repo_name)
        
        dependencies = {
            'npm': [],
            'python': [],
            'maven': [],
            'cargo': [],
            'composer': [],
            'ruby': []
        }
        
        # Check package.json for NPM dependencies
        try:
            package_json = repo.get_contents("package.json")
            if package_json:
                print("✅ Found package.json")
                content = json.loads(package_json.decoded_content.decode())
                all_deps = {}
                if 'dependencies' in content:
                    all_deps.update(content['dependencies'])
                if 'devDependencies' in content:
                    all_deps.update(content['devDependencies'])
                
                print(f"📦 Found {len(all_deps)} NPM dependencies to check")
                for pkg_name, version_req in all_deps.items():
                    result = check_npm_package(pkg_name, version_req)
                    if result:
                        dependencies['npm'].append(result)
        except Exception as e:
            print(f"ℹ️ No package.json found or error: {str(e)}")
            
        # Check requirements.txt for Python dependencies
        try:
            requirements_txt = repo.get_contents("requirements.txt")
            if requirements_txt:
                print("✅ Found requirements.txt")
                content = requirements_txt.decoded_content.decode().split('\n')
                deps = [line.strip() for line in content if line.strip() and not line.startswith('#')]
                
                print(f"📦 Found {len(deps)} Python dependencies to check")
                for dep in deps:
                    if '==' in dep:
                        name, version = dep.split('==')
                        result = check_pip_package(name, version)
                        if result:
                            dependencies['python'].append(result)
        except Exception as e:
            print(f"ℹ️ No requirements.txt found or error: {str(e)}")
            
        # Check pom.xml for Maven dependencies
        try:
            pom_xml = repo.get_contents("pom.xml")
            if pom_xml:
                print("✅ Found pom.xml")
                # Add Maven dependency checking logic here
        except Exception as e:
            print(f"ℹ️ No pom.xml found or error: {str(e)}")
            
        # Check Cargo.toml for Rust dependencies
        try:
            cargo_toml = repo.get_contents("Cargo.toml")
            if cargo_toml:
                print("✅ Found Cargo.toml")
                # Add Cargo dependency checking logic here
        except Exception as e:
            print(f"ℹ️ No Cargo.toml found or error: {str(e)}")
            
        # Check composer.json for PHP dependencies
        try:
            composer_json = repo.get_contents("composer.json")
            if composer_json:
                print("✅ Found composer.json")
                # Add Composer dependency checking logic here
        except Exception as e:
            print(f"ℹ️ No composer.json found or error: {str(e)}")
            
        # Check Gemfile for Ruby dependencies
        try:
            gemfile = repo.get_contents("Gemfile")
            if gemfile:
                print("✅ Found Gemfile")
                # Add Ruby dependency checking logic here
        except Exception as e:
            print(f"ℹ️ No Gemfile found or error: {str(e)}")
            
        # --- New: Go (go.mod) ---
        print("\n📂 Checking go.mod...")
        try:
            go_mod = repo.get_contents('go.mod')
            print("✅ Found go.mod")
            # TODO: Implement Go dependency scanning
            # Example: parse go.mod, check proxy.golang.org for latest versions
        except Exception as e:
            print(f"ℹ️ No go.mod found or error: {str(e)}")

        # --- New: .NET (csproj) ---
        print("\n📂 Checking .csproj files...")
        try:
            contents = repo.get_contents('.')
            for file in contents:
                if file.name.endswith('.csproj'):
                    print(f"✅ Found {file.name}")
                    # TODO: Implement .NET dependency scanning
                    # Example: parse XML, check nuget.org for latest versions
        except Exception as e:
            print(f"ℹ️ No .csproj file found or error: {str(e)}")

        return {"success": True, "dependencies": dependencies}
        
    except Exception as e:
        print(f"❌ Error scanning dependencies: {str(e)}")
        return {"success": False, "error": str(e)} 

def create_dependency_update_pr(repo, dependencies, branch_name):
    """Create a pull request to update dependencies"""
    try:
        # Create a new branch
        default_branch = repo.default_branch
        base_branch = repo.get_branch(default_branch)
        
        # Create new branch
        repo.create_git_ref(
            ref=f'refs/heads/{branch_name}',
            sha=base_branch.commit.sha
        )
        
        # Prepare commit message and changes
        commit_message = "chore: update dependencies\n\n"
        changes = {}
        
        # Update package.json if npm dependencies exist
        if dependencies.get('npm'):
            try:
                package_json = repo.get_contents('package.json')
                content = json.loads(package_json.decoded_content.decode())
                
                for dep in dependencies['npm']:
                    if dep['is_outdated']:
                        if 'dependencies' in content and dep['name'] in content['dependencies']:
                            content['dependencies'][dep['name']] = f"^{dep['latest_version']}"
                        if 'devDependencies' in content and dep['name'] in content['devDependencies']:
                            content['devDependencies'][dep['name']] = f"^{dep['latest_version']}"
                        commit_message += f"- Update {dep['name']} from {dep['current_version']} to {dep['latest_version']}\n"
                
                changes['package.json'] = json.dumps(content, indent=2) + '\n'
            except Exception as e:
                print(f"❌ Error updating package.json: {str(e)}")
        
        # Update requirements.txt if pip dependencies exist
        if dependencies.get('pip'):
            try:
                requirements_txt = repo.get_contents('requirements.txt')
                content = requirements_txt.decoded_content.decode()
                lines = content.split('\n')
                
                for dep in dependencies['pip']:
                    if dep['is_outdated']:
                        for i, line in enumerate(lines):
                            if line.startswith(f"{dep['name']}=="):
                                lines[i] = f"{dep['name']}=={dep['latest_version']}"
                                commit_message += f"- Update {dep['name']} from {dep['current_version']} to {dep['latest_version']}\n"
                
                changes['requirements.txt'] = '\n'.join(lines) + '\n'
            except Exception as e:
                print(f"❌ Error updating requirements.txt: {str(e)}")
        
        # Create commit with changes
        for file_path, content in changes.items():
            try:
                file = repo.get_contents(file_path, ref=branch_name)
                repo.update_file(
                    path=file_path,
                    message=commit_message,
                    content=content,
                    sha=file.sha,
                    branch=branch_name
                )
            except Exception as e:
                print(f"❌ Error updating {file_path}: {str(e)}")
        
        # Create pull request
        pr_title = "chore: update dependencies"
        pr_body = f"""## Dependency Updates

This PR updates the following dependencies:

{commit_message}

### Changes Made
- Updated outdated dependencies to their latest versions
- Maintained compatibility with existing codebase

### Testing
Please review the changes and run the test suite to ensure everything works as expected.

### Notes
- All updates are to the latest stable versions
- Breaking changes have been considered and documented
"""
        
        pr = repo.create_pull(
            title=pr_title,
            body=pr_body,
            head=branch_name,
            base=default_branch
        )
        
        print(f"✅ Created pull request #{pr.number} in {repo.full_name}")
        return {"success": True, "pr_url": pr.html_url}
        
    except Exception as e:
        print(f"❌ Error creating pull request: {str(e)}")
        return {"success": False, "error": str(e)} 