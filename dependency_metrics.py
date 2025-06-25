def calculate_health_metrics(dependencies):
    """
    Calculate accurate health metrics for dependencies
    """
    metrics = {
        'total': 0,
        'outdated': 0,
        'up_to_date': 0,
        'major_updates': 0,
        'minor_updates': 0,
        'patch_updates': 0,
        'high_risk': 0,
        'medium_risk': 0,
        'low_risk': 0,
        'ecosystem_health': {}
    }
    
    # Calculate per ecosystem metrics
    for ecosystem, deps in dependencies.items():
        if deps:  # Only count ecosystems with dependencies
            eco_total = len(deps)
            eco_outdated = sum(1 for d in deps if d and d.get('is_outdated', False))
            eco_up_to_date = eco_total - eco_outdated
            
            # Calculate ecosystem health percentage
            eco_health = (eco_up_to_date / eco_total * 100) if eco_total > 0 else 100
            
            metrics['ecosystem_health'][ecosystem] = {
                'total': eco_total,
                'outdated': eco_outdated,
                'up_to_date': eco_up_to_date,
                'health_score': eco_health,
                'major_updates': sum(1 for d in deps if d and d.get('update_type') == 'major'),
                'minor_updates': sum(1 for d in deps if d and d.get('update_type') == 'minor'),
                'patch_updates': sum(1 for d in deps if d and d.get('update_type') == 'patch')
            }
            
            # Add to total metrics
            metrics['total'] += eco_total
            metrics['outdated'] += eco_outdated
            metrics['up_to_date'] += eco_up_to_date
            metrics['major_updates'] += metrics['ecosystem_health'][ecosystem]['major_updates']
            metrics['minor_updates'] += metrics['ecosystem_health'][ecosystem]['minor_updates']
            metrics['patch_updates'] += metrics['ecosystem_health'][ecosystem]['patch_updates']
    
    # Calculate overall health score
    # Weight factors: major updates impact more than minor ones
    if metrics['total'] > 0:
        major_impact = 0.6  # Major updates have 60% impact
        minor_impact = 0.3  # Minor updates have 30% impact
        patch_impact = 0.1  # Patch updates have 10% impact
        
        weighted_outdated = (
            metrics['major_updates'] * major_impact +
            metrics['minor_updates'] * minor_impact +
            metrics['patch_updates'] * patch_impact
        )
        
        metrics['health_score'] = max(0, 100 - (weighted_outdated / metrics['total'] * 100))
        
        # Calculate risk levels
        metrics['high_risk'] = metrics['major_updates']
        metrics['medium_risk'] = metrics['minor_updates']
        metrics['low_risk'] = metrics['patch_updates']
    else:
        metrics['health_score'] = 100
    
    return metrics

def get_ecosystem_symbol(ecosystem):
    """Get the symbol for a dependency ecosystem"""
    return {
        'npm': '⚡',
        'python': '🐍',
        'maven': '☕',
        'cargo': '🦀',
        'composer': '🐘',
        'ruby': '💎'
    }.get(ecosystem, '📦')

def get_registry_url(ecosystem, package_name):
    """Get the registry URL for a package"""
    return {
        'npm': f"https://www.npmjs.com/package/{package_name}",
        'python': f"https://pypi.org/project/{package_name}",
        'maven': f"https://mvnrepository.com/artifact/{package_name}",
        'cargo': f"https://crates.io/crates/{package_name}",
        'composer': f"https://packagist.org/packages/{package_name}",
        'ruby': f"https://rubygems.org/gems/{package_name}"
    }.get(ecosystem, '#') 