#!/usr/bin/env python3
"""
Simplified uBlock Origin Filter Optimizer
Single-file implementation focusing on core functionality.
"""

import asyncio
import aiohttp
import aiofiles
import yaml
import regex as re
import hashlib
import logging
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class FilterRule:
    """Simplified rule representation"""
    raw: str
    rule_type: str  # 'network', 'cosmetic', 'hosts'
    domains: Set[str]
    hash: str
    
    @classmethod
    def from_raw(cls, raw_rule: str) -> 'FilterRule':
        """Create FilterRule from raw string"""
        rule_type = cls._detect_type(raw_rule)
        domains = cls._extract_domains(raw_rule, rule_type)
        rule_hash = hashlib.md5(raw_rule.encode()).hexdigest()[:8]
        return cls(raw_rule, rule_type, domains, rule_hash)
    
    @staticmethod
    def _detect_type(rule: str) -> str:
        """Simple type detection"""
        if rule.startswith(('##', '#@#')):
            return 'cosmetic'
        elif any(x in rule for x in ['0.0.0.0', '127.0.0.1']):
            return 'hosts'
        else:
            return 'network'
    
    @staticmethod
    def _extract_domains(rule: str, rule_type: str) -> Set[str]:
        """Extract domains from rule"""
        domains = set()
        if rule_type == 'hosts':
            parts = rule.split()
            if len(parts) >= 2:
                domains.add(parts[1])
        elif '||' in rule:
            match = re.search(r'\|\|([^/\^$]+)', rule)
            if match:
                domains.add(match.group(1))
        return domains

class FilterOptimizer:
    """Core optimizer with essential functionality only"""
    
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        self.session: Optional[aiohttp.ClientSession] = None
        self.logger = logging.getLogger(__name__)
    
    async def run(self):
        """Main execution flow"""
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'uBO-Filter-Optimizer/1.0'}
        ) as session:
            self.session = session
            
            # Step 1: Fetch all filter lists
            raw_content = await self._fetch_all_sources()
            
            # Step 2: Parse into rules
            all_rules = self._parse_all_content(raw_content)
            
            # Step 3: Optimize (dedupe + convert)
            optimized_rules = self._optimize_rules(all_rules)
            
            # Step 4: Output
            await self._write_output(optimized_rules)
            
            self.logger.info(f"Processed {len(all_rules)} → {len(optimized_rules)} rules")
    
    async def _fetch_all_sources(self) -> Dict[str, str]:
        """Fetch all configured sources concurrently"""
        tasks = []
        for name, config in self.config['filter_sources'].items():
            tasks.append(self._fetch_source(name, config['url']))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        content = {}
        for i, result in enumerate(results):
            source_name = list(self.config['filter_sources'].keys())[i]
            if isinstance(result, Exception):
                self.logger.error(f"Failed to fetch {source_name}: {result}")
            else:
                content[source_name] = result
        
        return content
    
    async def _fetch_source(self, name: str, url: str) -> str:
        """Fetch single source with retry"""
        for attempt in range(3):
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        self.logger.info(f"Fetched {name}: {len(content)} chars")
                        return content
                    else:
                        raise aiohttp.ClientError(f"HTTP {response.status}")
            except Exception as e:
                if attempt == 2:
                    raise
                await asyncio.sleep(2 ** attempt)
        
        return ""
    
    def _parse_all_content(self, content_dict: Dict[str, str]) -> List[FilterRule]:
        """Parse all content into FilterRule objects"""
        all_rules = []
        
        for source_name, content in content_dict.items():
            rules = self._parse_content(content, source_name)
            all_rules.extend(rules)
            self.logger.info(f"Parsed {source_name}: {len(rules)} rules")
        
        return all_rules
    
    def _parse_content(self, content: str, source_name: str) -> List[FilterRule]:
        """Parse content based on format detection"""
        rules = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith(('!', '#', '[')) and not line.startswith('##'):
                continue
            
            # Skip invalid rules
            if len(line) > 1000:  # Reasonable limit
                continue
            
            try:
                rule = FilterRule.from_raw(line)
                rules.append(rule)
            except Exception as e:
                self.logger.debug(f"Failed to parse rule in {source_name}: {line[:50]}...")
        
        return rules
    
    def _optimize_rules(self, rules: List[FilterRule]) -> List[FilterRule]:
        """Core optimization: deduplication + conversion"""
        # Step 1: Deduplicate by hash
        seen_hashes = set()
        unique_rules = []
        
        for rule in rules:
            if rule.hash not in seen_hashes:
                seen_hashes.add(rule.hash)
                unique_rules.append(rule)
        
        self.logger.info(f"Deduplication: {len(rules)} → {len(unique_rules)} rules")
        
        # Step 2: Convert to uBO format
        converted_rules = []
        for rule in unique_rules:
            converted = self._convert_to_ubo(rule)
            if converted:
                converted_rules.append(converted)
        
        # Step 3: Sort by type for better organization
        converted_rules.sort(key=lambda x: (x.rule_type, x.raw))
        
        return converted_rules
    
    def _convert_to_ubo(self, rule: FilterRule) -> Optional[FilterRule]:
        """Convert rule to uBO format if needed"""
        raw = rule.raw
        
        # Convert hosts format to uBO
        if rule.rule_type == 'hosts':
            if any(x in raw for x in ['0.0.0.0', '127.0.0.1']):
                domain = list(rule.domains)[0] if rule.domains else None
                if domain and not domain.startswith('#'):
                    raw = f"||{domain}^"
                    return FilterRule.from_raw(raw)
                else:
                    return None
        
        # Convert AdGuard modifiers to uBO equivalent
        if '$removeparam=' in raw:
            raw = raw.replace('$removeparam=', '$removeparam=')
        
        # Basic validation - keep only valid uBO rules
        if self._is_valid_ubo_rule(raw):
            return FilterRule(raw, rule.rule_type, rule.domains, rule.hash)
        
        return None
    
    def _is_valid_ubo_rule(self, rule: str) -> bool:
        """Basic uBO rule validation"""
        # Must not be empty or too long
        if not rule or len(rule) > 1000:
            return False
        
        # Must not contain invalid characters
        if any(char in rule for char in ['\n', '\r', '\t']):
            return False
        
        # Basic format checks
        if rule.startswith('##') or rule.startswith('#@#'):
            return True  # Cosmetic rule
        elif '||' in rule or rule.startswith('@@'):
            return True  # Network rule
        elif '.' in rule and not rule.startswith('#'):
            return True  # Generic pattern
        
        return False
    
    async def _write_output(self, rules: List[FilterRule]):
        """Write optimized rules to output file"""
        output_path = Path("output/optimized-filters.txt")
        output_path.parent.mkdir(exist_ok=True)
        
        # Generate header
        header = f"""! Title: Optimized uBlock Origin Filters
! Description: Automatically optimized filter list
! Version: {datetime.now().strftime('%Y%m%d-%H%M')}
! Rules: {len(rules)}
! Generated: {datetime.now().isoformat()}
!
"""
        
        # Group rules by type
        network_rules = [r for r in rules if r.rule_type == 'network']
        cosmetic_rules = [r for r in rules if r.rule_type == 'cosmetic']
        
        content = header
        
        if network_rules:
            content += "! *** Network Rules ***\n"
            content += '\n'.join(r.raw for r in network_rules) + '\n\n'
        
        if cosmetic_rules:
            content += "! *** Cosmetic Rules ***\n"
            content += '\n'.join(r.raw for r in cosmetic_rules) + '\n'
        
        async with aiofiles.open(output_path, 'w', encoding='utf-8') as f:
            await f.write(content)
        
        self.logger.info(f"Written {len(rules)} rules to {output_path}")
        
        # Optional: Git commit
        if self.config.get('git', {}).get('auto_commit', True):
            await self._git_commit(output_path)
    
    async def _git_commit(self, file_path: Path):
        """Simple git commit"""
        try:
            import git
            repo = git.Repo('.')
            repo.index.add([str(file_path)])
            repo.index.commit(f"Update optimized filters - {datetime.now().strftime('%Y-%m-%d')}")
            self.logger.info("Git commit successful")
        except Exception as e:
            self.logger.error(f"Git commit failed: {e}")

# CLI Interface
import click

@click.command()
@click.option('--config', default='config/sources.yaml', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose logging')
def main(config: str, verbose: bool):
    """Run the uBlock Origin filter optimizer"""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    optimizer = FilterOptimizer(config)
    asyncio.run(optimizer.run())

if __name__ == '__main__':
    main()
