import re
import numpy as np
from urllib.parse import urlparse, parse_qs, unquote
from collections import Counter

class URLFeatureExtractor:
    def __init__(self):
        self.xss_keywords = [
            'script', 'javascript', 'alert', 'eval', 'document',
            'window', 'onload', 'onerror', 'onclick', 'onmouseover',
            'iframe', 'embed', 'object', 'img', 'svg', 'body',
            'form', 'input', 'textarea', 'select', 'meta'
        ]
        
        self.sql_keywords = [
            'union', 'select', 'insert', 'update', 'delete', 'drop',
            'alter', 'create', 'table', 'database', 'where', 'order',
            'group', 'having', 'limit', 'offset', 'count', 'sum',
            'avg', 'min', 'max', 'exists', 'like', 'between',
            'ascii', 'char', 'concat', 'substring', 'length'
        ]
        
        self.special_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '[', ']', '{', '}']
        
    def extract_features(self, url):
        """Extract comprehensive features from URL"""
        features = []
        
        # Basic URL features
        features.extend(self._extract_basic_features(url))
        
        # Content-based features
        features.extend(self._extract_content_features(url))
        
        # Structure-based features
        features.extend(self._extract_structure_features(url))
        
        # Pattern-based features
        features.extend(self._extract_pattern_features(url))
        
        return features
    
    def _extract_basic_features(self, url):
        """Extract basic URL characteristics"""
        parsed = urlparse(url)
        
        features = [
            len(url),  # URL length
            len(parsed.path),  # Path length
            len(parsed.query),  # Query length
            len(parsed.fragment),  # Fragment length
            len(parse_qs(parsed.query)),  # Number of query parameters
        ]
        
        return features
    
    def _extract_content_features(self, url):
        """Extract content-based features"""
        url_lower = url.lower()
        
        # XSS keyword count
        xss_count = sum(1 for keyword in self.xss_keywords if keyword in url_lower)
        
        # SQL keyword count
        sql_count = sum(1 for keyword in self.sql_keywords if keyword in url_lower)
        
        # Special character count
        special_count = sum(1 for char in self.special_chars if char in url)
        
        # Encoded character count
        encoded_count = len(re.findall(r'%[0-9a-fA-F]{2}', url))
        
        # Script tag count
        script_count = len(re.findall(r'<script|</script>', url_lower))
        
        # HTML tag count
        html_count = len(re.findall(r'<[^>]*>', url))
        
        # JavaScript event handler count
        event_count = len(re.findall(r'on\w+\s*=', url_lower))
        
        # Comment syntax count
        comment_count = len(re.findall(r'--|/\*|\*/', url))
        
        features = [
            xss_count,
            sql_count,
            special_count,
            encoded_count,
            script_count,
            html_count,
            event_count,
            comment_count,
        ]
        
        return features
    
    def _extract_structure_features(self, url):
        """Extract URL structure features"""
        parsed = urlparse(url)
        
        # Path depth
        path_depth = len([p for p in parsed.path.split('/') if p])
        
        # Query parameter statistics
        params = parse_qs(parsed.query)
        param_count = len(params)
        
        # Average parameter value length
        avg_param_len = 0
        if params:
            total_len = sum(len(str(values)) for values in params.values())
            avg_param_len = total_len / param_count
        
        # URL entropy (measure of randomness)
        entropy = self._calculate_entropy(url)
        
        features = [
            path_depth,
            param_count,
            avg_param_len,
            entropy,
        ]
        
        return features
    
    def _extract_pattern_features(self, url):
        """Extract pattern-based features"""
        
        # SQL injection patterns
        sql_patterns = [
            r"'\s*(or|and)\s*'",  # ' or ' patterns
            r"'\s*(union|select)",  # union/select patterns
            r"--",  # SQL comments
            r";\s*(drop|delete|insert)",  # Dangerous SQL commands
            r"'\s*=\s*'",  # Equality patterns
        ]
        
        # XSS patterns
        xss_patterns = [
            r"<script[^>]*>",  # Script tags
            r"javascript:",  # JavaScript protocol
            r"on\w+\s*=",  # Event handlers
            r"alert\s*\(",  # Alert function
            r"eval\s*\(",  # Eval function
        ]
        
        # Count pattern matches
        sql_pattern_count = sum(1 for pattern in sql_patterns if re.search(pattern, url, re.IGNORECASE))
        xss_pattern_count = sum(1 for pattern in xss_patterns if re.search(pattern, url, re.IGNORECASE))
        
        # Logic operator count
        logic_count = len(re.findall(r'\b(and|or|not)\b', url, re.IGNORECASE))
        
        # Parentheses balance
        paren_balance = abs(url.count('(') - url.count(')'))
        
        # Quote balance
        quote_balance = abs(url.count("'") - url.count('"'))
        
        features = [
            sql_pattern_count,
            xss_pattern_count,
            logic_count,
            paren_balance,
            quote_balance,
        ]
        
        return features
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        char_counts = Counter(text)
        total_chars = len(text)
        
        entropy = 0
        for count in char_counts.values():
            probability = count / total_chars
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def get_feature_names(self):
        """Get names of all features"""
        return [
            'url_length',
            'path_length',
            'query_length',
            'fragment_length',
            'param_count',
            'xss_keyword_count',
            'sql_keyword_count',
            'special_char_count',
            'encoded_char_count',
            'script_tag_count',
            'html_tag_count',
            'event_handler_count',
            'comment_count',
            'path_depth',
            'param_count_struct',
            'avg_param_length',
            'entropy',
            'sql_pattern_count',
            'xss_pattern_count',
            'logic_operator_count',
            'paren_balance',
            'quote_balance',
        ]
