"""
Log Parser - Backend Team
Translates messy raw logs into clean, structured data

"""

import json
import re
from datetime import datetime
from typing import Dict, Optional, List, Any



# CONFIGURATION - Expected Log Format


# Required fields that MUST be in every log
REQUIRED_FIELDS = [
    'timestamp',
    'requestId',
    'duration',
    'memoryUsed',
    'memorySize'
]

# Optional fields with default values
DEFAULT_VALUES = {
    'functionName': 'unknown',
    'statusCode': 200,
    'apiCalls': [],
    'errorMessage': None
}


# ============================================================================
# MAIN PARSER CLASS
# ============================================================================

class LogParser:
    """
    Parse and validate raw serverless logs
    
    Handles:
    - JSON parsing
    - Field validation
    - Type conversion
    - Error handling
    - Data cleaning
    """
    
    def __init__(self, strict_mode: bool = False):
        """
        Initialize parser
        
        Args:
            strict_mode: If True, raise errors for invalid logs.
                        If False, try to fix/skip bad logs.
        """
        self.strict_mode = strict_mode
        
        # Statistics
        self.stats = {
            'total_parsed': 0,
            'successful': 0,
            'failed': 0,
            'warnings': 0
        }
        
        # Store warnings for debugging
        self.warnings = []
    
    def parse(self, raw_log: Any) -> Optional[Dict]:
        """
        Parse a single raw log entry
        
        Args:
            raw_log: Can be:
                - JSON string (e.g., '{"duration": 500, ...}')
                - Python dictionary (already parsed)
                - Malformed string
        
        Returns:
            Parsed and validated log dictionary, or None if parsing fails
        """
        self.stats['total_parsed'] += 1
        
        try:
            # Step 1: Convert to dictionary if needed
            if isinstance(raw_log, str):
                log_dict = self._parse_json_string(raw_log)
            elif isinstance(raw_log, dict):
                log_dict = raw_log
            else:
                raise ValueError(f"Unsupported log type: {type(raw_log)}")
            
            # Step 2: Validate required fields
            self._validate_required_fields(log_dict)
            
            # Step 3: Clean and normalize data
            cleaned_log = self._clean_and_normalize(log_dict)
            
            # Step 4: Validate data types
            validated_log = self._validate_types(cleaned_log)
            
            self.stats['successful'] += 1
            return validated_log
            
        except Exception as e:
            self.stats['failed'] += 1
            
            if self.strict_mode:
                raise  # Re-raise error in strict mode
            else:
                # Log warning and return None
                warning = f"Failed to parse log: {str(e)}"
                self.warnings.append(warning)
                return None
    
    def parse_batch(self, raw_logs: List[Any]) -> List[Dict]:
        """
        Parse multiple logs at once
        
        Args:
            raw_logs: List of raw logs (strings or dicts)
        
        Returns:
            List of successfully parsed logs (skips failed ones)
        """
        parsed_logs = []
        
        for raw_log in raw_logs:
            parsed = self.parse(raw_log)
            if parsed is not None:
                parsed_logs.append(parsed)
        
        return parsed_logs
    
    # ========================================================================
    # INTERNAL PARSING METHODS
    # ========================================================================
    
    def _parse_json_string(self, json_str: str) -> Dict:
        """
        Parse JSON string into dictionary
        
        Handles:
        - Standard JSON
        - JSON with extra whitespace
        - Common malformations
        """
        try:
            # Try standard JSON parsing
            return json.loads(json_str)
            
        except json.JSONDecodeError as e:
            # Try to fix common issues
            
            # Issue 1: Single quotes instead of double quotes
            if "'" in json_str:
                try:
                    fixed = json_str.replace("'", '"')
                    return json.loads(fixed)
                except:
                    pass
            
            # Issue 2: Trailing commas
            if json_str.rstrip().endswith(',}'):
                try:
                    fixed = json_str.replace(',}', '}')
                    return json.loads(fixed)
                except:
                    pass
            
            # Issue 3: Extract JSON from log message
            # Example: "[INFO] 2024-02-06 {...json...}"
            json_match = re.search(r'\{.*\}', json_str, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except:
                    pass
            
            # If all fixes fail, raise original error
            raise ValueError(f"Invalid JSON: {str(e)}")
    
    def _validate_required_fields(self, log_dict: Dict) -> None:
        """
        Check that all required fields are present
        
        Raises:
            ValueError: If required field is missing
        """
        missing_fields = []
        
        for field in REQUIRED_FIELDS:
            if field not in log_dict:
                missing_fields.append(field)
        
        if missing_fields:
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
    
    def _clean_and_normalize(self, log_dict: Dict) -> Dict:
        """
        Clean and normalize log data
        
        - Adds default values for missing optional fields
        - Cleans up field names
        - Removes extra/unknown fields
        """
        cleaned = {}
        
        # Copy required fields
        for field in REQUIRED_FIELDS:
            cleaned[field] = log_dict[field]
        
        # Add optional fields with defaults
        for field, default_value in DEFAULT_VALUES.items():
            cleaned[field] = log_dict.get(field, default_value)
        
        # Handle special cases
        
        # Ensure apiCalls is a list
        if not isinstance(cleaned['apiCalls'], list):
            if isinstance(cleaned['apiCalls'], str):
                # Single call as string
                cleaned['apiCalls'] = [cleaned['apiCalls']]
            else:
                cleaned['apiCalls'] = []
        
        return cleaned
    
    def _validate_types(self, log_dict: Dict) -> Dict:
        """
        Validate and convert data types
        
        Ensures:
        - duration is int/float (milliseconds)
        - memoryUsed is int (MB)
        - memorySize is int (MB)
        - statusCode is int
        - timestamp is valid
        """
        validated = log_dict.copy()
        
        # 1. Duration (convert to int, handle different formats)
        validated['duration'] = self._parse_duration(log_dict['duration'])
        
        # 2. Memory Used (convert to int)
        validated['memoryUsed'] = self._parse_memory(log_dict['memoryUsed'])
        
        # 3. Memory Size (convert to int)
        validated['memorySize'] = self._parse_memory(log_dict['memorySize'])
        
        # 4. Status Code (convert to int)
        validated['statusCode'] = self._parse_status_code(log_dict['statusCode'])
        
        # 5. Timestamp (validate format)
        validated['timestamp'] = self._parse_timestamp(log_dict['timestamp'])
        
        return validated
    
    def _parse_duration(self, value: Any) -> int:
        """
        Parse duration value
        
        Handles:
        - Plain numbers: 450
        - Strings with units: "450ms", "0.45s"
        - Floats: 450.5
        """
        try:
            # If already a number
            if isinstance(value, (int, float)):
                return int(value)
            
            # If string
            if isinstance(value, str):
                # Remove whitespace
                value = value.strip()
                
                # Handle "450ms"
                if 'ms' in value.lower():
                    return int(float(value.lower().replace('ms', '').strip()))
                
                # Handle "0.45s" or "0.45 seconds"
                if 's' in value.lower() or 'sec' in value.lower():
                    seconds = float(re.sub(r'[^0-9.]', '', value))
                    return int(seconds * 1000)  # Convert to ms
                
                # Just a number as string
                return int(float(value))
            
            raise ValueError(f"Cannot parse duration: {value}")
            
        except Exception as e:
            if self.strict_mode:
                raise ValueError(f"Invalid duration '{value}': {e}")
            else:
                self.stats['warnings'] += 1
                self.warnings.append(f"Invalid duration '{value}', using 0")
                return 0
    
    def _parse_memory(self, value: Any) -> int:
        """
        Parse memory value
        
        Handles:
        - Plain numbers: 128
        - Strings with units: "128MB", "128 MB"
        """
        try:
            # If already a number
            if isinstance(value, (int, float)):
                return int(value)
            
            # If string
            if isinstance(value, str):
                # Remove whitespace and units
                value = value.strip().upper()
                value = value.replace('MB', '').replace('M', '').strip()
                return int(float(value))
            
            raise ValueError(f"Cannot parse memory: {value}")
            
        except Exception as e:
            if self.strict_mode:
                raise ValueError(f"Invalid memory '{value}': {e}")
            else:
                self.stats['warnings'] += 1
                self.warnings.append(f"Invalid memory '{value}', using 0")
                return 0
    
    def _parse_status_code(self, value: Any) -> int:
        """Parse HTTP status code"""
        try:
            return int(value)
        except:
            if self.strict_mode:
                raise ValueError(f"Invalid status code: {value}")
            else:
                self.stats['warnings'] += 1
                self.warnings.append(f"Invalid status code '{value}', using 200")
                return 200
    
    def _parse_timestamp(self, value: Any) -> str:
        """
        Parse and validate timestamp
        
        Handles:
        - ISO format strings: "2024-02-06T10:00:00Z"
        - Python datetime objects
        - Unix timestamps
        """
        try:
            # If already a string in ISO format, validate it
            if isinstance(value, str):
                # Try to parse to ensure it's valid
                datetime.fromisoformat(value.replace('Z', '+00:00'))
                return value
            
            # If datetime object
            if isinstance(value, datetime):
                return value.isoformat()
            
            # If Unix timestamp (number)
            if isinstance(value, (int, float)):
                dt = datetime.fromtimestamp(value)
                return dt.isoformat()
            
            raise ValueError(f"Cannot parse timestamp: {value}")
            
        except Exception as e:
            if self.strict_mode:
                raise ValueError(f"Invalid timestamp '{value}': {e}")
            else:
                self.stats['warnings'] += 1
                self.warnings.append(f"Invalid timestamp '{value}', using current time")
                return datetime.now().isoformat()
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def get_statistics(self) -> Dict:
        """
        Get parsing statistics
        
        Returns:
            Statistics dictionary
        """
        total = self.stats['total_parsed']
        
        return {
            'total_logs_parsed': total,
            'successful': self.stats['successful'],
            'failed': self.stats['failed'],
            'warnings': self.stats['warnings'],
            'success_rate': f"{(self.stats['successful'] / max(total, 1)) * 100:.1f}%"
        }
    
    def print_statistics(self):
        """Print nice statistics summary"""
        stats = self.get_statistics()
        
        print("=" * 60)
        print("LOG PARSER STATISTICS")
        print("=" * 60)
        print(f"Total Logs Parsed:  {stats['total_logs_parsed']}")
        print(f"✅ Successful:      {stats['successful']}")
        print(f"❌ Failed:          {stats['failed']}")
        print(f"⚠️  Warnings:        {stats['warnings']}")
        print(f"Success Rate:       {stats['success_rate']}")
        print("=" * 60)
    
    def get_warnings(self, last_n: int = 10) -> List[str]:
        """
        Get recent warnings
        
        Args:
            last_n: Number of recent warnings to return
        
        Returns:
            List of warning messages
        """
        return self.warnings[-last_n:]
    
    def reset_statistics(self):
        """Reset all statistics"""
        self.stats = {
            'total_parsed': 0,
            'successful': 0,
            'failed': 0,
            'warnings': 0
        }
        self.warnings = []


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def parse_log(raw_log: Any, strict: bool = False) -> Optional[Dict]:
    """
    Quick function to parse a single log
    
    Args:
        raw_log: Raw log (string or dict)
        strict: If True, raise errors. If False, return None on error.
    
    Returns:
        Parsed log dictionary or None
    """
    parser = LogParser(strict_mode=strict)
    return parser.parse(raw_log)


def parse_logs(raw_logs: List[Any], strict: bool = False) -> List[Dict]:
    """
    Quick function to parse multiple logs
    
    Args:
        raw_logs: List of raw logs
        strict: If True, raise errors. If False, skip bad logs.
    
    Returns:
        List of successfully parsed logs
    """
    parser = LogParser(strict_mode=strict)
    return parser.parse_batch(raw_logs)


# ============================================================================
# TESTING AND EXAMPLES
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("LOG PARSER - COMPREHENSIVE TESTING")
    print("=" * 70)
    
    # ========================================================================
    # TEST 1: Perfect JSON Log
    # ========================================================================
    print("\n📋 TEST 1: Perfect JSON Log")
    print("-" * 70)
    
    perfect_json = '''
    {
        "timestamp": "2024-02-06T10:00:00Z",
        "requestId": "req-123456",
        "functionName": "process_payment",
        "duration": 450,
        "memoryUsed": 128,
        "memorySize": 512,
        "statusCode": 200,
        "apiCalls": ["dynamodb:GetItem", "s3:GetObject"],
        "errorMessage": null
    }
    '''
    
    parser = LogParser()
    result = parser.parse(perfect_json)
    
    print("✅ Parsed successfully!")
    print(f"Duration: {result['duration']}ms")
    print(f"Memory: {result['memoryUsed']}MB")
    print(f"API Calls: {len(result['apiCalls'])}")
    
    # ========================================================================
    # TEST 2: JSON with Units (e.g., "450ms", "128MB")
    # ========================================================================
    print("\n📋 TEST 2: JSON with Units")
    print("-" * 70)
    
    json_with_units = {
        "timestamp": "2024-02-06T10:00:00Z",
        "requestId": "req-789012",
        "duration": "450ms",      # Has "ms" suffix
        "memoryUsed": "128 MB",   # Has "MB" suffix with space
        "memorySize": 512,
        "statusCode": 200
    }
    
    result = parser.parse(json_with_units)
    
    print("✅ Parsed successfully!")
    print(f"Duration: {result['duration']}ms (converted from '450ms')")
    print(f"Memory: {result['memoryUsed']}MB (converted from '128 MB')")
    
    # ========================================================================
    # TEST 3: Duration in Seconds
    # ========================================================================
    print("\n📋 TEST 3: Duration in Seconds")
    print("-" * 70)
    
    json_seconds = {
        "timestamp": "2024-02-06T10:00:00Z",
        "requestId": "req-345678",
        "duration": "1.5s",       # In seconds!
        "memoryUsed": 150,
        "memorySize": 512,
        "statusCode": 200
    }
    
    result = parser.parse(json_seconds)
    
    print("✅ Parsed successfully!")
    print(f"Duration: {result['duration']}ms (converted from '1.5s')")
    
    # ========================================================================
    # TEST 4: Missing Optional Fields
    # ========================================================================
    print("\n📋 TEST 4: Missing Optional Fields")
    print("-" * 70)
    
    minimal_json = {
        "timestamp": "2024-02-06T10:00:00Z",
        "requestId": "req-minimal",
        "duration": 500,
        "memoryUsed": 128,
        "memorySize": 512
        # Missing: functionName, statusCode, apiCalls, errorMessage
    }
    
    result = parser.parse(minimal_json)
    
    print("✅ Parsed successfully with defaults!")
    print(f"Function Name: {result['functionName']} (default)")
    print(f"Status Code: {result['statusCode']} (default)")
    print(f"API Calls: {result['apiCalls']} (default)")
    
    # ========================================================================
    # TEST 5: Messy Log from Real System
    # ========================================================================
    print("\n📋 TEST 5: Messy Real-World Log")
    print("-" * 70)
    
    messy_log = '''
    [INFO] 2024-02-06T10:00:00Z Request ID: req-999888 
    {"timestamp": "2024-02-06T10:00:00Z", "requestId": "req-999888", 
    "duration": 450, "memoryUsed": 128, "memorySize": 512, 
    "statusCode": 200, "apiCalls": ["dynamodb:GetItem"]}
    '''
    
    result = parser.parse(messy_log)
    
    print("✅ Extracted JSON from messy log!")
    print(f"Request ID: {result['requestId']}")
    
    # ========================================================================
    # TEST 6: Invalid Log (Missing Required Field)
    # ========================================================================
    print("\n📋 TEST 6: Invalid Log (Non-Strict Mode)")
    print("-" * 70)
    
    invalid_json = {
        "timestamp": "2024-02-06T10:00:00Z",
        "requestId": "req-invalid"
        # Missing: duration, memoryUsed, memorySize (REQUIRED!)
    }
    
    result = parser.parse(invalid_json)
    
    if result is None:
        print("❌ Failed to parse (as expected in non-strict mode)")
        print(f"Warning: {parser.get_warnings()[-1]}")
    
    # ========================================================================
    # TEST 7: Batch Parsing
    # ========================================================================
    print("\n📋 TEST 7: Batch Parsing (10 logs, 2 invalid)")
    print("-" * 70)
    
    batch_logs = [
        # 8 valid logs
        {"timestamp": "2024-02-06T10:00:00Z", "requestId": f"req-{i}", 
         "duration": 450 + i*10, "memoryUsed": 128, "memorySize": 512}
        for i in range(8)
    ]
    
    # 2 invalid logs
    batch_logs.append({"requestId": "bad-1"})  # Missing required fields
    batch_logs.append({"timestamp": "bad timestamp", "requestId": "bad-2"})
    
    parser2 = LogParser()
    results = parser2.parse_batch(batch_logs)
    
    print(f"✅ Parsed {len(results)} out of 10 logs")
    parser2.print_statistics()
    
    # ========================================================================
    # TEST 8: Strict Mode (Raises Errors)
    # ========================================================================
    print("\n📋 TEST 8: Strict Mode")
    print("-" * 70)
    
    strict_parser = LogParser(strict_mode=True)
    
    try:
        result = strict_parser.parse(invalid_json)
        print("Unexpected success")
    except ValueError as e:
        print(f"✅ Correctly raised error in strict mode:")
        print(f"   Error: {e}")
    
    # ========================================================================
    # TEST 9: Different Timestamp Formats
    # ========================================================================
    print("\n📋 TEST 9: Different Timestamp Formats")
    print("-" * 70)
    
    from datetime import datetime
    
    timestamp_tests = [
        {
            "name": "ISO String",
            "log": {"timestamp": "2024-02-06T10:00:00Z", "requestId": "t1", 
                   "duration": 450, "memoryUsed": 128, "memorySize": 512}
        },
        {
            "name": "Datetime Object",
            "log": {"timestamp": datetime.now(), "requestId": "t2", 
                   "duration": 450, "memoryUsed": 128, "memorySize": 512}
        },
        {
            "name": "Unix Timestamp",
            "log": {"timestamp": 1707217200, "requestId": "t3", 
                   "duration": 450, "memoryUsed": 128, "memorySize": 512}
        }
    ]
    
    parser3 = LogParser()
    for test in timestamp_tests:
        result = parser3.parse(test["log"])
        print(f"✅ {test['name']:20s}: {result['timestamp'][:19]}")
    
    # ========================================================================
    # TEST 10: Real CloudWatch Log Format
    # ========================================================================
    print("\n📋 TEST 10: AWS CloudWatch Format")
    print("-" * 70)
    
    cloudwatch_log = '''
    REPORT RequestId: abc-123-def-456
    Duration: 450.23 ms
    Billed Duration: 451 ms
    Memory Size: 512 MB
    Max Memory Used: 128 MB
    '''
    
    # This would need custom parsing for CloudWatch format
    # For now, showing that JSON extraction works
    
    cloudwatch_json = {
        "timestamp": "2024-02-06T10:00:00Z",
        "requestId": "abc-123-def-456",
        "duration": "450.23 ms",
        "memoryUsed": "128 MB",
        "memorySize": "512 MB",
        "statusCode": 200
    }
    
    result = parser.parse(cloudwatch_json)
    print("✅ Parsed CloudWatch-style log!")
    print(f"Duration: {result['duration']}ms")
    print(f"Memory: {result['memoryUsed']}MB")
    
    # ========================================================================
    # FINAL SUMMARY
    # ========================================================================
    print("\n" + "=" * 70)
    print("✅ ALL TESTS COMPLETE!")
    print("=" * 70)
    
    print("\nQuick Usage Examples:")
    print("-" * 70)
    
    print("""
# Example 1: Parse single log
from backend.log_parser import parse_log

raw = '{"timestamp": "2024-02-06T10:00:00Z", "requestId": "req-1", ...}'
log = parse_log(raw)

# Example 2: Parse multiple logs
from backend.log_parser import parse_logs

logs = parse_logs([raw1, raw2, raw3])

# Example 3: Use parser with statistics
from backend.log_parser import LogParser

parser = LogParser()
for raw_log in raw_logs:
    parsed = parser.parse(raw_log)
    if parsed:
        # Use parsed log
        ...

parser.print_statistics()
    """)
    
    print("=" * 70)