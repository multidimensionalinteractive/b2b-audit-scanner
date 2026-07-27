import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import scan_url

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
    r = scan_url(url); result = {'score': r.score, 'grade': r.grade, 'headers': [{'name': h.header, 'status': 'pass' if h.found else ('warn' if not h.required else 'fail') , 'value': h.value} for h in r.checks]}
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