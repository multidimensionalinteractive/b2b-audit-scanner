import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import scan_headers
import flask

def handler(event, context):
    """Vercel serverless function entry point."""
    url = event.get('queryStringParameters', {}).get('url', '')
    if not url:
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'url required'})
        }
    if not url.startswith('http'):
        url = 'https://' + url
    result = scan_headers(url)
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({
            'url': url,
            'score': result['score'],
            'grade': result['grade'],
            'headers': result['headers'],
        })
    }
